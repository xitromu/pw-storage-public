"""Отдельные пакеты секретов для виртуальных учётных записей служб Windows."""

from __future__ import annotations

import argparse
import getpass
import json
import re
import stat
import sys
import warnings
from dataclasses import asdict, dataclass
from pathlib import Path

from . import winsecurity
from .config import PROFILES
from .tpm import TpmError, TpmKey, seal, unseal
from .vault import Vault, _hash_or_none, _writer

MAX_PACKAGE_BYTES = 4 * 1024 * 1024
NAME = re.compile(r"PW_[A-Za-z0-9_]{1,60}")
ALIAS = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}")
PROJECT = re.compile(r"[A-Za-z0-9_-]{1,100}")
ROW_ID = re.compile(r"[0-9a-f]{8}")


class ServiceError(RuntimeError):
    pass


def _name(value: str) -> str:
    if not isinstance(value, str) or not NAME.fullmatch(value):
        raise ServiceError("Недопустимое имя службы PW_STORAGE")
    return value.upper()


def _text(value) -> bool:
    return isinstance(value, str) and 0 < len(value) <= 200 and not any(ord(c) < 32 for c in value)


@dataclass(frozen=True)
class Binding:
    project: str
    row: str
    service: str
    key: str
    alias: str

    def __post_init__(self):
        if (not isinstance(self.project, str) or not PROJECT.fullmatch(self.project)
                or self.project in ("ALL", "_SYSTEM")
                or not isinstance(self.row, str) or not ROW_ID.fullmatch(self.row)
                or not _text(self.service) or not _text(self.key)
                or not isinstance(self.alias, str) or not ALIAS.fullmatch(self.alias)):
            raise ServiceError("Неверное описание строки служебного пакета")


@dataclass(frozen=True)
class ServiceSpec:
    name: str
    profile: str
    bindings: tuple[Binding, ...]

    def __post_init__(self):
        object.__setattr__(self, "name", _name(self.name))
        if self.profile not in PROFILES:
            raise ServiceError("Неизвестный профиль")
        if (not isinstance(self.bindings, tuple) or not 1 <= len(self.bindings) <= 64
                or any(not isinstance(b, Binding) for b in self.bindings)):
            raise ServiceError("Нужен явный непустой список строк")
        if (len({b.alias for b in self.bindings}) != len(self.bindings)
                or len({b.row for b in self.bindings}) != len(self.bindings)):
            raise ServiceError("Повтор номера строки или имени получателя")

    @classmethod
    def read(cls, path: Path) -> ServiceSpec:
        try:
            with Path(path).open("rb") as stream:
                raw = stream.read(65537)
            if len(raw) > 65536:
                raise ServiceError("Реестр службы слишком большой")
            data = json.loads(raw)
            if not isinstance(data, dict) or set(data) != {"name", "profile", "bindings"}:
                raise ServiceError("Реестр должен содержать только name, profile и bindings")
            return cls(data["name"], data["profile"], tuple(Binding(**b) for b in data["bindings"]))
        except (OSError, ValueError, TypeError, KeyError, RecursionError):
            raise ServiceError("Не удалось прочитать реестр службы без значений") from None


def _location(name: str, profile: str) -> Path:
    name = _name(name)
    if profile not in PROFILES:
        raise ServiceError("Неизвестный профиль")
    return winsecurity.common_app_data() / f"PW_STORAGE_SERVICE_{profile}_{name}"


def _key(name: str, profile: str, sid: str) -> TpmKey:
    return TpmKey(f"PW_STORAGE_SERVICE_{profile}_{name}", machine=True, service_sid=sid)


def _no_links(path: Path) -> None:
    for item in (path, *path.parents):
        try:
            info = item.lstat()
        except FileNotFoundError:
            continue
        if getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT:
            raise ServiceError("Ссылки и перенаправления в пути служебного пакета запрещены")


def _collect(spec: ServiceSpec, vault: Vault) -> dict[str, str]:
    rows = {row.uid: row for row in vault.rows()}
    for binding in spec.bindings:
        row = rows.get(binding.row)
        if (row is None or binding.project not in row.projects or not row.comment.strip()
                or (row.service, row.key) != (binding.service, binding.key)):
            raise ServiceError("Строки не соответствуют реестру или не разрешены указанному проекту")
    values = {}
    for binding in spec.bindings:
        value = vault.value(binding.row)
        if not isinstance(value, str):
            raise ServiceError("В выбранной строке отсутствует значение")
        values[binding.alias] = value
    return values


def _payload(spec: ServiceSpec, sid: str, values: dict[str, str], enabled: bool) -> bytes:
    raw = json.dumps({"format": 1, "name": spec.name, "profile": spec.profile, "sid": sid,
                      "enabled": enabled, "bindings": [asdict(b) for b in spec.bindings],
                      "values": values}, ensure_ascii=False).encode("utf-8")
    if len(raw) > MAX_PACKAGE_BYTES - 1024:
        raise ServiceError("Служебный пакет слишком большой")
    return raw


def _read_payload(path: Path, key, name: str, profile: str, sid: str) -> dict:
    try:
        _no_links(path)
        with path.open("rb") as stream:
            blob = stream.read(MAX_PACKAGE_BYTES + 1)
        if len(blob) > MAX_PACKAGE_BYTES:
            raise ServiceError("Служебный пакет слишком большой")
        data = json.loads(unseal(key, blob))
        if (not isinstance(data, dict)
                or set(data) != {"format", "name", "profile", "sid", "enabled", "bindings", "values"}
                or type(data["format"]) is not int or data["format"] != 1
                or data["name"] != name or data["profile"] != profile or data["sid"] != sid
                or type(data["enabled"]) is not bool):
            raise ServiceError("Пакет не соответствует службе или профилю")
        spec = ServiceSpec(name, profile, tuple(Binding(**b) for b in data["bindings"]))
        values = data["values"]
        if (not isinstance(values, dict) or any(not isinstance(v, str) for v in values.values())
                or set(values) != ({b.alias for b in spec.bindings} if data["enabled"] else set())):
            raise ServiceError("Содержимое пакета не соответствует реестру")
        return data
    except (OSError, TpmError, ValueError, TypeError, KeyError, RecursionError):
        raise ServiceError("Служебный пакет недоступен или повреждён") from None


def provision(spec: ServiceSpec, vault: Vault) -> None:
    winsecurity.require_admin()
    sid = winsecurity.service_sid(spec.name)
    if vault.path.resolve() != PROFILES[spec.profile].vault.resolve():
        raise ServiceError("Хранилище не соответствует профилю служебного пакета")
    values = _collect(spec, vault)
    directory = _location(spec.name, spec.profile)
    _no_links(directory)
    winsecurity.create_service_directory(directory, sid)
    path = directory / "credentials.bin"
    lock = directory / "access.lock"
    _no_links(lock)
    try:
        with lock.open("xb"):
            pass
    except FileExistsError:
        pass
    with winsecurity.package_lock(lock):
        _no_links(path)
        key = _key(spec.name, spec.profile, sid)
        if key.exists():
            key.restrict_service_access()
        else:
            key.create()
        raw = _payload(spec, sid, values, True)
        blob = seal(key, raw)
        if unseal(key, blob) != raw:
            raise ServiceError("Проверка шифрования служебного пакета не пройдена")
        with _writer(vault.path):
            if vault.source_hash is None or _hash_or_none(vault.path) != vault.source_hash:
                raise ServiceError("Хранилище изменилось; пакет не записан")
            winsecurity.publish_file(path, blob, sid)


def revoke(name: str, profile: str) -> None:
    winsecurity.require_admin()
    name = _name(name)
    sid = winsecurity.service_sid(name)
    directory = _location(name, profile)
    _no_links(directory)
    winsecurity.protect_directory(directory, sid)
    path = directory / "credentials.bin"
    with winsecurity.package_lock(directory / "access.lock"):
        key = _key(name, profile, sid)
        data = _read_payload(path, key, name, profile, sid)
        spec = ServiceSpec(name, profile, tuple(Binding(**b) for b in data["bindings"]))
        raw = _payload(spec, sid, {}, False)
        blob = seal(key, raw)
        if unseal(key, blob) != raw:
            raise ServiceError("Проверка шифрования служебного пакета не пройдена")
        winsecurity.publish_file(path, blob, sid)


class ServiceClient:
    def __init__(self, name: str, profile: str = "main"):
        self.name = _name(name)
        if profile not in PROFILES:
            raise ServiceError("Неизвестный профиль")
        self.profile = profile

    def get(self, alias: str) -> str:
        if not isinstance(alias, str) or not ALIAS.fullmatch(alias):
            raise ServiceError("Недопустимое имя секрета службы")
        try:
            sid = winsecurity.service_sid(self.name)
            if winsecurity.current_user_sid() != sid:
                raise ServiceError("Секреты доступны только отдельной учётной записи этой службы")
            key = _key(self.name, self.profile, sid)
            path = _location(self.name, self.profile) / "credentials.bin"
            _no_links(path.parent)
            with winsecurity.package_lock(path.parent / "access.lock"):
                data = _read_payload(path, key, self.name, self.profile, sid)
            if not data["enabled"]:
                raise ServiceError("Разрешение службы отозвано")
            if alias not in data["values"]:
                raise ServiceError("Этот секрет не разрешён службе")
            binding = next(b for b in data["bindings"] if b["alias"] == alias)
            print(f"[PW_STORAGE/{self.profile}] служба {self.name}: взят ключ {binding['service']} / "
                  f"{binding['key']} (строка {binding['row']})", file=sys.stderr)
            return data["values"][alias]
        except (winsecurity.SecurityError, TpmError, OSError):
            raise ServiceError("Служебные секреты недоступны") from None


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Отдельные секреты служб; без --apply только план")
    commands = parser.add_subparsers(dest="command", required=True)
    install = commands.add_parser("provision")
    install.add_argument("manifest", type=Path, help="JSON-реестр без значений: name, profile, bindings")
    install.add_argument("--apply", action="store_true")
    remove = commands.add_parser("revoke")
    remove.add_argument("name")
    remove.add_argument("--profile", choices=tuple(PROFILES), required=True)
    remove.add_argument("--apply", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.command == "revoke":
            name = _name(args.name)
            print(f"Отзыв: {name}, профиль {args.profile}. Уже взятые значения из памяти не исчезнут.")
            if args.apply:
                revoke(name, args.profile)
                print("Новые чтения секретов запрещены; остановка службы выполняется отдельно.")
            return 0
        spec = ServiceSpec.read(args.manifest)
        print(f"Получатель: NT SERVICE\\{spec.name}; источник: PW_STORAGE/{spec.profile}")
        for b in spec.bindings:
            print(f"  {b.project} / {b.row} / {b.service} / {b.key} -> {b.alias}")
        print("Постоянное разрешение только этим строкам; отдельный машинный ключ TPM и защищённый пакет.")
        print("Служба должна быть установлена отдельно; эта команда её не создаёт и не запускает.")
        if not args.apply:
            return 0
        winsecurity.require_admin()
        winsecurity.service_sid(spec.name)
        if not sys.stdin.isatty():
            raise ServiceError("Запусти команду в локальном терминале для скрытого ввода пароля")
        if input(f"Для выдачи введи имя службы {spec.name}: ").strip() != spec.name:
            raise ServiceError("Выдача отменена")
        with warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            password = getpass.getpass("Пароль хранилища: ")
        vault = Vault.open_readonly(PROFILES[spec.profile].vault, password)
        del password
        provision(spec, vault)
        print("Зашифрованный пакет записан. Автозапуск и приложения не изменены.")
        return 0
    except winsecurity.PublicationPending:
        print("Пакет заменён, но пока закрыт для службы. Повтори выдачу после проверки прав; "
              "старый пакет автоматически не возвращается.", file=sys.stderr)
        return 1
    except (Exception, KeyboardInterrupt):
        print("Операция не выполнена. Проверь реестр, учётную запись службы, права, TPM и пароль; "
              "открытого запасного источника нет.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
