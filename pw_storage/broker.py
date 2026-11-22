"""Посредник: держит открытую базу в памяти, выдаёт значения скриптам, ведёт журнал выдачи.

Запуск: python -m pw_storage.broker --profile test. Обычно его запускает клиент при первом запросе доступа.
Окно ввода живёт в этом же процессе: пароль никуда не передаётся, ни по каналу, ни в файлы.
Без доступов посредник завершается: база не лежит в памяти без необходимости.

Т26: сессия просит отдельные строки по номерам из перечня. Видны ей строки своего проекта и строки с ALL;
одобрение строки из ALL добавляет проект в список записи. Владелец снимает лишнее отметками в окне.
"""

from __future__ import annotations

import argparse
import base64
import gc
import json
import queue
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from multiprocessing.connection import Listener
from pathlib import Path

from . import catalog, procinfo
from .audit import Audit
from .config import (
    CONFIRM_SECONDS,
    DEFAULT_GRANT_HOURS,
    IDLE_EXIT_SECONDS,
    MAX_REMOTE_ATTEMPTS,
    MAX_WHY_CHARS,
    PROFILES,
    read_settings,
    TOTP_ENTRY,
    Profile,
    valid_hours,
)
from .remote import QueueLock, RemoteListener, WrongCode, read_password
from .second_factor import BotApi, TelegramConfirm, Totp
from .tpm import TpmError, TpmKey
from .vault import Row, Vault, VaultChanged, VaultCommitted, VaultError, WrongPassword

MAX_REQUEST_BYTES = 64 * 1024
MAX_REQUEST_ROWS = 200
SWEEP_SECONDS = 30
QUEUE_REFRESH_SECONDS = 20
OPEN_WAIT_SECONDS = CONFIRM_SECONDS + 900  # столько клиент ждёт решения: ввод пароля плюс подтверждение
BRIDGE_PROJECT = "COMMON"  # метка записей-мостика: в них лежат токен и chat id Telegram-бота
TELEGRAM_KEYS = ("TG_BOT_TOKEN", "TG_CHAT_ID")


@dataclass
class AccessRequest:
    project: str
    session: str
    hours: int
    listing: catalog.Listing
    rows: tuple[catalog.Item, ...] = ()  # запрошенные строки: сначала свои, затем из ALL
    why: str = ""
    test: bool = False

    @property
    def rebuild(self) -> bool:
        """Перечня нет: окно по паролю только собирает его заново, доступ не выдаётся."""
        return not self.rows

    @property
    def own(self) -> list[catalog.Item]:
        return [item for item in self.rows if self.project in item.projects]

    @property
    def common(self) -> list[catalog.Item]:
        return [item for item in self.rows if self.project not in item.projects]

    @property
    def unnamed(self) -> int:
        return self.listing.unnamed_count(self.project)


@dataclass
class Unlocked:
    """Пароль принят, но доступ ещё не выдан: нужен второй фактор."""
    own: list[str]  # комментарии строк, которые будут выданы: по файлу хранилища, а не по перечню
    common: list[str]
    verify_code: object
    telegram: TelegramConfirm | None
    rebuilt: bool = False


@dataclass(frozen=True)
class Grant:
    expires: float
    allowed: frozenset  # Т23: отпечатки строк, которые владелец видел при подтверждении; выдаются только они


@dataclass
class _Pending:
    project: str
    session: str
    rows: tuple[str, ...] = ()
    why: str = ""
    event: threading.Event = field(default_factory=threading.Event)
    result: dict = field(default_factory=dict)
    verdict: tuple[bool, str, str] | None = None
    vault: Vault | None = None
    chosen: list[Row] = field(default_factory=list)
    hours: int = DEFAULT_GRANT_HOURS
    deadline: float = float("inf")
    cancelled: bool = False
    cancel_reason: str = ""
    finished: bool = False
    presented: bool = False
    unlock_generation: int = 0
    queue_token: str | None = None
    defer_release: bool = False
    cancel_ui: object = None


# Подтверждение уходит в Telegram, как только посредник достал токен из открытого хранилища.
# Канал выключается строкой в settings.json.
def telegram_enabled(profile: Profile) -> bool:
    # В тестовом профиле бот включается отдельно: это запись во внешний сервис.
    return read_settings(profile).get("telegram", profile.name == "main")


def queue_lock_path(profile: Profile):
    """Файл-запрет на время ожидания ответа: нужен, если тем же ботом пользуется ещё один опросчик."""
    path = read_settings(profile).get("telegram_queue_lock")
    return Path(str(path)) if path else None


def default_hours(profile: Profile) -> int:
    """Т27: срок по умолчанию из settings.json; в окне его можно изменить для конкретного запроса."""
    return valid_hours(read_settings(profile).get("grant_hours", DEFAULT_GRANT_HOURS)) or DEFAULT_GRANT_HOURS


def _row_name(row: Row) -> str:
    return f"{row.group} / {row.service} / {row.key}"


class Broker:
    def __init__(self, profile: Profile, tpm_key, ui, bot_api=None, clock=time.time,
                 inspect=None, audit: Audit | None = None,
                 remote_key_factory=None, queue_lock: QueueLock | None = None):
        self.remote_key_factory = remote_key_factory or (lambda code: TpmKey(profile.remote_key, pin=code))
        self.queue_lock = queue_lock
        self._remote_failures = 0
        self._queue_refreshed = 0.0
        self._queue_owner: _Pending | None = None
        self.profile = profile
        self.tpm_key = tpm_key
        self.ui = ui
        self.bot_api = bot_api
        self.clock = clock
        self.inspect = inspect or self._inspect
        self.audit = audit or Audit(profile.audit)
        self.vault: Vault | None = None
        self.grants: dict[str, Grant] = {}
        self.issued: dict[str, list[dict]] = {}
        self._totp: tuple[str, Totp] | None = None
        self._lock = threading.RLock()
        self._pending: queue.Queue[_Pending] = queue.Queue()
        self._waiting: dict[int, _Pending] = {}  # включая проверку перечня до enqueue
        self._active: _Pending | None = None
        self._last_activity = clock()
        self._last_sweep = clock()
        self._listener: Listener | None = None
        self.stop_requested = False

    # Канал

    def start(self) -> None:
        # Первый экземпляр канала: если посредник уже работает, здесь будет ошибка.
        self._listener = Listener(self.profile.pipe, family="AF_PIPE")
        threading.Thread(target=self._accept_loop, daemon=True).start()

    def _accept_loop(self) -> None:
        while not self.stop_requested:
            try:
                conn = self._listener.accept()
            except OSError:
                if self.stop_requested:
                    return
                continue
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _inspect(self, conn) -> tuple[procinfo.ClientInfo, str | None, str]:
        pid = procinfo.pipe_client_pid(conn.fileno())
        info = procinfo.inspect(pid)
        return info, procinfo.resolve_project(info, self.profile.projects_root), procinfo.session_of(pid)

    def _serve(self, conn) -> None:
        with conn:
            try:
                request = json.loads(conn.recv_bytes(MAX_REQUEST_BYTES).decode("utf-8"))
                info, project, session = self.inspect(conn)
                answer = self.dispatch(request, info, project, session)
                conn.send_bytes(json.dumps(answer, ensure_ascii=False).encode("utf-8"))
            except EOFError:
                pass  # клиент только проверил, что посредник работает
            except (OSError, ValueError) as e:
                print(f"Ошибка обмена с клиентом: {type(e).__name__}", flush=True)

    # Запросы

    def dispatch(self, request: dict, info, project: str | None, session: str) -> dict:
        self._last_activity = self.clock()
        if not isinstance(request, dict):
            return {"ok": False, "error": "bad_request", "message": "Запрос — объект JSON"}
        op = request.get("op")
        if op == "shutdown" and self.profile.name == "test":
            self.stop_requested = True
            return {"ok": True}
        if project is None:
            return {"ok": False, "error": "project_unknown",
                    "message": f"Проект не определён: скрипт и рабочая папка вне {self.profile.projects_root}"}
        if op == "status":
            return self._status(project, session)
        if op == "open":
            rows = request.get("rows", [])
            why = request.get("why", "")
            if not isinstance(rows, list) or len(rows) > MAX_REQUEST_ROWS or any(not isinstance(uid, str) for uid in rows):
                return {"ok": False, "error": "bad_request", "message": "Номера строк — списком строк"}
            if not isinstance(why, str):
                return {"ok": False, "error": "bad_request", "message": "Причина запроса — текстом"}
            return self._open(project, session, [uid.strip().lower() for uid in rows], why)
        if op == "list":
            return self._list(project)
        if op == "preview":
            return self._preview(project, session)
        if op == "get":
            return self._get(project, session, info, str(request.get("service", "")), str(request.get("key", "")))
        if op in ("get_attachment", "save_token"):
            service, key = request.get("service"), request.get("key")
            if not isinstance(service, str) or not isinstance(key, str) or not service or not key:
                return {"ok": False, "error": "bad_request", "message": "Нужны сервис и имя ключа текстом"}
            if op == "get_attachment":
                name = request.get("name")
                if not isinstance(name, str) or not name:
                    return {"ok": False, "error": "bad_request", "message": "Нужно имя вложения текстом"}
                return self._get_attachment(project, session, info, service, key, name)
            value, expected = request.get("value"), request.get("expected")
            if not isinstance(value, str) or not value or not isinstance(expected, str):
                return {"ok": False, "error": "bad_request", "message": "Нужны непустой токен и прежнее значение текстом"}
            return self._save_token(project, session, info, service, key, value, expected)
        if op == "report":
            return {"ok": True, "issued": self.issued.get(project, [])}
        if op == "close":
            return self._close(project, session)
        return {"ok": False, "error": "bad_request", "message": "Неизвестная команда"}

    def _has_grant(self, project: str) -> bool:
        with self._lock:
            grant = self.grants.get(project)
            return grant is not None and grant.expires > self.clock() and self.vault is not None

    def _granted_rows(self, project: str) -> list[Row]:
        """Подтверждённые строки, не изменившиеся после подтверждения и всё ещё видимые проекту."""
        with self._lock:
            if not self._has_grant(project):
                return []
            allowed = self.grants[project].allowed
            return [row for row in self.vault.rows() if row.stamp in allowed and row.visible_to(project)]

    def _needs_access(self, project: str) -> dict:
        return {"ok": False, "error": "needs_access",
                "message": f"У проекта {project} нет доступа к этой строке. Номера строк — pw.py list, "
                           "запрос — pw.py open --why \"зачем\" <номера>"}

    def _status(self, project: str, session: str) -> dict:
        with self._lock:
            expires = self.grants[project].expires if self._has_grant(project) else None
        return {"ok": True, "project": project, "session": session, "granted": expires is not None,
                "expires": datetime.fromtimestamp(expires).isoformat(timespec="seconds") if expires else None}

    def _open(self, project: str, session: str, rows: list[str], why: str) -> dict:
        rows = list(dict.fromkeys(uid for uid in rows if uid))
        why = " ".join(why.split())[:MAX_WHY_CHARS]
        pending = _Pending(project, session, tuple(rows), why, deadline=self.clock() + OPEN_WAIT_SECONDS)
        with self._lock:
            self._waiting[id(pending)] = pending
        try:
            answer = self._check_open(project, session, rows)
            with self._lock:
                if pending.finished:
                    return pending.result
                if answer is not None:
                    return answer
                self.audit.write("access_requested", project=project, session=session, rows=rows, why=why)
                self._pending.put(pending)
            if not pending.event.wait(OPEN_WAIT_SECONDS):
                with self._lock:
                    if not pending.finished:
                        pending.cancelled = True
                        pending.vault = None
                        pending.chosen = []
                        return {"ok": False, "error": "timeout", "message": "Владелец не ответил"}
            return pending.result
        finally:
            with self._lock:
                self._waiting.pop(id(pending), None)

    def _check_open(self, project: str, session: str, rows: list[str]) -> dict | None:
        try:
            Vault.resume(self.profile.vault)
        except (VaultError, OSError):
            return {"ok": False, "error": "vault_pending", "message": "Незавершённая запись хранилища требует разбора"}
        if not self.profile.vault.exists():
            return {"ok": False, "error": "no_vault", "message": "Хранилище ещё не создано"}
        listing = self._current_listing()
        if not rows:
            if listing.state != catalog.MISSING:
                return {"ok": False, "error": "no_rows",
                        "message": "Укажите номера строк: pw.py list, затем pw.py open --why \"зачем\" <номера>"}
        elif listing.state == catalog.MISSING:
            return {"ok": False, "error": "no_catalog",
                    "message": "Перечня строк нет на этом ПК. Запросите pw.py open без номеров: "
                               "владелец соберёт перечень паролем, затем запросите строки снова"}
        else:
            visible = listing.visible(project)
            unknown = [uid for uid in rows if uid not in visible]
            if unknown:
                return {"ok": False, "error": "unknown_rows",
                        "message": f"У проекта {project} нет строк: {', '.join(unknown)}. Номера — в pw.py list"}
            if set(rows) <= {row.uid for row in self._granted_rows(project)}:
                return self._status(project, session)
        return None

    def _list(self, project: str) -> dict:
        rows = self._granted_rows(project)
        if not rows:
            return self._needs_access(project)
        return {"ok": True, "rows": [
            {"id": r.uid, "service": r.service, "key": r.key, "comment": r.comment, "all": project not in r.projects}
            for r in rows
        ]}

    def _preview(self, project: str, session: str) -> dict:
        """Что может запросить сессия: номера и комментарии, как в окне до пароля (Т22, Т26)."""
        listing = self._current_listing()
        self.audit.write("catalog_viewed", project=project, session=session, state=listing.state)
        return {"ok": True, "project": project, "state": listing.state,
                "own": [item.to_dict() for item in listing.own(project)],
                "common": [item.to_dict() for item in listing.common(project)],
                "unnamed": listing.unnamed_count(project)}

    def _authorized_row(self, project: str, session: str, info, service: str, key: str, event: str) -> Row | dict:
        fields = dict(project=project, session=session, service=service, key=key,
                      pid=info.pid, script=str(info.script) if info.script else "")
        if not self._has_grant(project):
            self.audit.write(event, **fields, reason="нет доступа")
            return self._needs_access(project)
        allowed = self.grants[project].allowed
        found = [row for row in self.vault.rows()
                 if row.service == service and row.key == key and row.visible_to(project)]
        approved = [row for row in found if row.stamp in allowed]
        if len(approved) > 1:
            approved = [row for row in approved if row.group == project] or approved
        if len(approved) > 1:
            self.audit.write(event, **fields, reason="несколько строк с таким именем")
            return {"ok": False, "error": "ambiguous",
                    "message": f"Строк {service} / {key} несколько: закройте доступ и запросите одну"}
        if not approved and found:
            self.audit.write(event, **fields, reason="нет в подтверждённом списке")
            return {"ok": False, "error": "not_approved",
                    "message": f"Строки {service} / {key} нет в подтверждённом списке или она изменилась. "
                               "Нужен запрос: pw.py list, затем pw.py open --why \"зачем\" <номера>"}
        if approved:
            return approved[0]
        self.audit.write(event, **fields, reason="нет такой записи")
        return {"ok": False, "error": "not_found",
                "message": f"У проекта {project} нет ключа {service} / {key}"}

    def _get(self, project: str, session: str, info, service: str, key: str) -> dict:
        with self._lock:
            row = self._authorized_row(project, session, info, service, key, "value_refused")
            if isinstance(row, dict):
                return row
            value = self.vault.value(row.uid)
            if value is None:
                self.audit.write("value_refused", project=project, session=session, service=service, key=key,
                                 pid=info.pid, script=str(info.script) if info.script else "", reason="нет такой записи")
                return {"ok": False, "error": "not_found", "message": f"У проекта {project} нет ключа {service} / {key}"}
            self.audit.write("value_issued", project=project, session=session, row=row.uid, group=row.group,
                             service=service, key=key, pid=info.pid, script=str(info.script) if info.script else "")
            self.issued.setdefault(project, []).append(
                {"time": datetime.now().isoformat(timespec="seconds"), "id": row.uid,
                 "service": service, "key": key})
            return {"ok": True, "value": value, "id": row.uid}

    def _get_attachment(self, project: str, session: str, info, service: str, key: str, name: str) -> dict:
        with self._lock:
            row = self._authorized_row(project, session, info, service, key, "attachment_refused")
            if isinstance(row, dict):
                return row
            fields = dict(project=project, session=session, row=row.uid, group=row.group, service=service, key=key,
                          pid=info.pid, script=str(info.script) if info.script else "", target=name)
            try:
                data = self.vault.attachment_by_uid(row.uid, name)
            except VaultError:
                self.audit.write("attachment_refused", **fields, reason="несколько одноимённых вложений")
                return {"ok": False, "error": "ambiguous_attachment", "message": "Несколько вложений с таким именем"}
            if data is None:
                self.audit.write("attachment_refused", **fields, reason="нет такого вложения")
                return {"ok": False, "error": "not_found", "message": "Нет такого вложения у разрешённой строки"}
            self.audit.write("attachment_issued", **fields)
            self.issued.setdefault(project, []).append(
                {"time": datetime.now().isoformat(timespec="seconds"), "id": row.uid,
                 "service": service, "key": key, "attachment": name})
            return {"ok": True, "id": row.uid, "data": base64.b64encode(data).decode("ascii")}

    def _save_token(self, project: str, session: str, info, service: str, key: str, value: str, expected: str) -> dict:
        with self._lock:
            row = self._authorized_row(project, session, info, service, key, "token_save_refused")
            if isinstance(row, dict):
                return row
            fields = dict(project=project, session=session, row=row.uid, group=row.group, service=service, key=key,
                          pid=info.pid, script=str(info.script) if info.script else "")
            if self._active is not None:
                self.audit.write("token_save_refused", **fields, reason="ожидается подтверждение доступа")
                return {"ok": False, "error": "vault_busy", "message": "Дождитесь завершения подтверждения доступа"}
            original = self.vault
            if original.value(row.uid) != expected:
                self.audit.write("token_save_refused", **fields, reason="прежнее значение не совпало")
                return {"ok": False, "error": "token_conflict", "message": "Токен уже изменился; перечитайте его"}
            working = None
            warnings = []
            try:
                working = original.clone()
                working.update_entry(row.uid, value=value)
                working.save()
            except (VaultError, OSError, ValueError) as error:
                if (isinstance(error, VaultCommitted) and working is not None
                        and working.source_hash != original.source_hash and working.source_hash == error.source_hash):
                    warnings.append("Токен записан; очистка операции ожидает завершения")
                else:
                    self.audit.write("token_save_failed", **fields, reason=type(error).__name__)
                    return {"ok": False, "error": "vault_changed" if isinstance(error, VaultChanged) else "save_failed",
                            "message": "Токен не сохранён: хранилище изменилось или запись требует разбора"}
            self.vault = working
            updated = next(r for r in working.rows() if r.uid == row.uid)
            grant = self.grants[project]
            allowed = frozenset(stamp for stamp in grant.allowed if stamp[0] != row.uid) | {updated.stamp}
            self.grants[project] = Grant(grant.expires, allowed)
            try:
                catalog.write(self.tpm_key, self.profile.catalog, working.rows(), self.profile.vault,
                              source_hash=working.source_hash)
            except (VaultError, TpmError, OSError) as error:
                warnings.append(f"Токен записан; перечень не обновлён ({type(error).__name__})")
            try:
                self.audit.write("token_saved", **fields)
            except (OSError, ValueError):
                warnings.append("Токен записан; журнал недоступен")
            return {"ok": True, "id": row.uid, "warnings": warnings}

    def _close(self, project: str, session: str) -> dict:
        with self._lock:
            existed = self.grants.pop(project, None) is not None
            self.issued.pop(project, None)
            for pending in tuple(self._waiting.values()):
                if pending.project == project and not pending.finished:
                    existed = True
                    pending.cancelled = True
                    pending.cancel_reason = "доступ закрыт клиентом (close)"
                    self._finish(pending, False, reason=pending.cancel_reason)
            self._drop_vault_if_unused()
        if existed:
            self.audit.write("access_closed", project=project, session=session)
        return {"ok": True, "closed": existed}

    # Окно: вызывается из основного потока, unlock — из рабочего потока окна

    def _current_listing(self) -> catalog.Listing:
        try:
            Vault.resume(self.profile.vault)
            return catalog.read(self.tpm_key, self.profile.catalog, self.profile.vault)
        except (VaultError, TpmError, OSError):
            return catalog.Listing(catalog.MISSING)

    def _enable_telegram(self, rows: list[Row], vault: Vault) -> None:
        """Telegram включается из уже открытого хранилища: на старте посредник сам себе не клиент.

        Нужны ровно по одной строке BRIDGE_PROJECT с именами TG_BOT_TOKEN и TG_CHAT_ID и непустыми значениями;
        иначе канал остаётся выключенным, и подтверждение идёт в окне за ПК.
        """
        if self.bot_api is not None or not telegram_enabled(self.profile):
            return
        found, missing = {}, []
        for name in TELEGRAM_KEYS:
            candidates = [row for row in rows if row.key == name and BRIDGE_PROJECT in row.projects]
            if len(candidates) != 1:
                missing.append(f"{name}: строк {len(candidates)}")
                continue
            found[name] = vault.value(candidates[0].uid) or ""
            if not found[name]:
                missing.append(f"{name}: пустое значение")
        if missing:
            print("Telegram не включён (" + "; ".join(missing) + "). Подтверждение — в окне за ПК.", flush=True)
            return
        with self._lock:
            self.bot_api = BotApi(found["TG_BOT_TOKEN"], found["TG_CHAT_ID"])
        print("Telegram включён: токен взят из хранилища.", flush=True)

    def _make_telegram(self, pending: _Pending, own: list[str], common: list[str]) -> TelegramConfirm | None:
        if self.bot_api is None:
            return None
        confirm = TelegramConfirm(self.bot_api, pending.project, pending.hours, own, common, why=pending.why,
                                  test=self.profile.name == "test")
        return confirm if confirm.fits() else None  # не помещается: подтверждение только в окне, там виден весь список

    def _unlock(self, pending: _Pending, password: str, chosen: list[str] | None, hours: int) -> Unlocked | None:
        """None — неверный пароль. Открытие заново проверяет пароль и подхватывает внешние правки файла.

        chosen — номера строк, оставленные владельцем; None — только собрать перечень (Unlocked.rebuilt).
        Выдаются строки по файлу хранилища: изменённая после сборки перечня строка показывается заново.
        """
        with self._lock:
            if (pending.cancelled or pending.finished or self.clock() >= pending.deadline
                    or pending.presented and self._active is not pending):
                return None
            pending.unlock_generation += 1
            generation = pending.unlock_generation
            pending.vault = None
            pending.chosen = []
        try:
            vault = Vault.open(self.profile.vault, password)
        except WrongPassword:
            self.audit.write("password_failed", project=pending.project, session=pending.session)
            return None
        rows = vault.rows()
        self._enable_telegram(rows, vault)
        try:
            catalog.write(self.tpm_key, self.profile.catalog, rows, self.profile.vault, source_hash=vault.source_hash)
        except (VaultError, TpmError, OSError) as e:
            self.audit.write("catalog_failed", project=pending.project, reason=type(e).__name__)
        current = {row.uid: row for row in rows}
        with self._lock:
            if (pending.cancelled or pending.finished or self.clock() >= pending.deadline
                    or generation != pending.unlock_generation or pending.presented and self._active is not pending):
                return None
            if chosen is None:
                self.audit.write("catalog_rebuilt", project=pending.project, session=pending.session)
                return Unlocked([], [], None, None, rebuilt=True)
            selected = [current[uid] for uid in chosen if uid in current and current[uid].visible_to(pending.project)]
            pending.hours = hours
            own = [row.comment for row in selected if pending.project in row.projects]
            common = [row.comment for row in selected if pending.project not in row.projects]
            result = Unlocked(own, common, self._verifier(vault.system_value(TOTP_ENTRY)),
                              self._make_telegram(pending, own, common))
            pending.chosen = selected
            pending.vault = vault
            return result

    def _verifier(self, secret: str | None):
        """Один проверяющий на всё время работы: принятый код не пройдёт и в запросе другой сессии."""
        if not secret:
            return None
        with self._lock:
            if self._totp is None or self._totp[0] != secret:
                self._totp = (secret, Totp(secret, clock=self.clock))
            return self._totp[1].verify

    def _make_remote(self, request: AccessRequest) -> dict[str, RemoteListener]:
        if (not self.profile.remote.exists() or self._remote_failures >= MAX_REMOTE_ATTEMPTS
                or request.listing.state != catalog.FRESH or request.rebuild):
            return {}
        listeners = {}
        for kind, api, listener_type in (("telegram", self.bot_api, RemoteListener),):
            if api is not None:
                listener = listener_type(api, request.project, request.hours,
                                         [(item.uid, item.comment) for item in request.own],
                                         [(item.uid, item.comment) for item in request.common],
                                         why=request.why, test=request.test, clock=self.clock)
                if listener.fits():
                    listeners[kind] = listener
        return listeners

    def _unlock_by_code(self, pending: _Pending, remote: RemoteListener, code: str, hours: int) -> str | None:
        """"granted"; "refused" при исчерпанных попытках или пустом выборе; None — можно пробовать ещё."""
        with self._lock:
            if (pending.cancelled or pending.finished or self.clock() >= pending.deadline
                    or self._remote_failures >= MAX_REMOTE_ATTEMPTS):
                return "refused"
            generation = pending.unlock_generation
        chosen = remote.chosen()
        if not chosen:
            remote.say("Не отмечено ни одной строки: доступ не выдан.\nОтвет не нужен")
            return "refused"
        try:
            password = read_password(self.remote_key_factory(code), self.profile.remote)
            with self._lock:
                if (pending.cancelled or pending.finished or self.clock() >= pending.deadline
                        or generation != pending.unlock_generation):
                    return "refused"
            unlocked = self._unlock(pending, password, chosen, hours)
            if unlocked is None:
                raise WrongCode("Пароль изменился, код устарел")
            if not unlocked.own and not unlocked.common:
                return "refused"
        except WrongCode:
            with self._lock:
                if pending.cancelled or pending.finished or self.clock() >= pending.deadline:
                    return "refused"
                self._remote_failures += 1
                left = MAX_REMOTE_ATTEMPTS - self._remote_failures
            self.audit.write("code_failed", project=pending.project, session=pending.session)
            status = ("Код не подошёл, попытки исчерпаны. Теперь только пароль за ПК.\nОтвет не нужен"
                      if left <= 0 else
                      f"Код не подошёл, осталось попыток: {left}.\nЖду ответа: pw и ваш код, одним сообщением.")
            try:
                remote.say(status, keep_buttons=left > 0)
            except Exception:
                pass
            return "refused" if left <= 0 else None
        self._remote_failures = 0
        return "granted"

    def _finish(self, pending: _Pending, granted: bool, via: str = "", reason: str = "") -> None:
        extend: list[Row] = []
        with self._lock:
            if pending.finished:
                return pending.verdict
            pending.finished = True
            # close будит клиента сразу; Tk-cancel заберёт только pump, даже если ask ещё строится.
            if not (pending.cancelled and pending.defer_release):
                pending.cancel_ui = None
            if pending.cancelled:
                granted = False
                reason = pending.cancel_reason or reason or "время запроса вышло"
            elif self.clock() >= pending.deadline:
                granted = False
                reason = "время запроса вышло"
            elif granted and (pending.vault is None or not pending.chosen):
                granted = False
                reason = "запрошенных строк нет в хранилище"
            if granted:
                try:
                    self.audit.write("access_granted", project=pending.project, session=pending.session, via=via,
                                     hours=pending.hours, rows=sorted(_row_name(row) for row in pending.chosen))
                except Exception:
                    granted = False
                    reason = "журнал доступа недоступен"
            if granted:
                self.vault = pending.vault
                now = self.clock()
                expires = now + pending.hours * 3600
                previous = self.grants.get(pending.project)
                allowed = frozenset(row.stamp for row in pending.chosen)
                if previous is not None and previous.expires > now:
                    allowed |= previous.allowed
                self.grants[pending.project] = Grant(expires, allowed)
                extend = [row for row in pending.chosen if pending.project not in row.projects]
                pending.result = {"ok": True, "granted": True, "project": pending.project,
                                  "rows": [row.uid for row in pending.chosen],
                                  "expires": datetime.fromtimestamp(expires).isoformat(timespec="seconds")}
            else:
                try:
                    self.audit.write("access_denied", project=pending.project, session=pending.session, reason=reason)
                except Exception:
                    pass
                pending.result = {"ok": False, "error": "denied", "message": f"Доступ не выдан: {reason}"}
            pending.verdict = granted, via if granted else "", reason
            pending.vault = None
            pending.chosen = []
            if self._active is pending:
                self._active = None
            self._last_activity = self.clock()
            if not pending.defer_release:
                self._release_queue(pending)
        try:
            if extend:
                self._extend_lists(pending.project, extend)
        except Exception:
            pending.result.setdefault("warnings", []).append("Доступ выдан; обновление списка проекта не завершилось")
        finally:
            pending.event.set()
        return pending.verdict

    def _extend_lists(self, project: str, rows: list[Row]) -> None:
        """Т26: одобренные строки из ALL получают проект в список записи. Запись в файл с проверкой."""
        with self._lock:
            if self.vault is None:
                return
            try:
                original_hash = self.vault.source_hash
                working = self.vault.clone()
                changed = [row for row in rows if working.add_project(row.uid, project)]
                if not changed:
                    return
                warning = ""
                try:
                    working.save()
                except VaultCommitted as error:
                    if working.source_hash == original_hash or working.source_hash != error.source_hash:
                        raise
                    warning = "очистка записи ожидает завершения"
                self.vault = working
                self.audit.write("list_extended", project=project, rows=sorted(_row_name(row) for row in changed),
                                 reason=warning)
                catalog.write(self.tpm_key, self.profile.catalog, working.rows(), self.profile.vault,
                              source_hash=working.source_hash)
            except (VaultError, TpmError, OSError) as e:
                # Доступ уже выдан и работает; в список проект попадёт при следующем одобрении.
                self.audit.write("list_extend_failed", project=project, reason=type(e).__name__)

    def pump(self) -> None:
        """Вызывается из основного потока: показывает окно следующего запроса и следит за сроками."""
        present = None
        with self._lock:
            if self._active is None and self._queue_owner is None:
                try:
                    pending = self._pending.get_nowait()
                except queue.Empty:
                    pending = None
                if pending is not None:
                    if pending.finished:
                        pass
                    elif pending.cancelled or self.clock() >= pending.deadline:
                        self._finish(pending, False, reason="время запроса вышло")
                    elif pending.rows and set(pending.rows) <= {row.uid for row in self._granted_rows(pending.project)}:
                        pending.result = self._status(pending.project, pending.session)
                        pending.finished = True
                        pending.event.set()
                    elif not self._hold_queue(pending):
                        self._finish(pending, False, reason="очередь подтверждений занята или недоступна")
                    else:
                        self._active = pending
                        pending.presented = True
                        # Резервируем lease до выхода из lock: close может прийти до/внутри ask.
                        pending.defer_release = True
                        present = pending
        if present is not None:
            self._present(present)
        with self._lock:
            owner = self._queue_owner
            cancel_ui = None
            if owner is not None and owner.cancelled:
                cancel_ui, owner.cancel_ui = owner.cancel_ui, None
        if cancel_ui is not None:
            cancel_ui()  # только основной поток, без broker lock
        owner = self._queue_owner
        if owner is not None and self.clock() - self._queue_refreshed >= QUEUE_REFRESH_SECONDS:
            if owner.finished and not owner.defer_release:
                self._release_queue(owner)
            elif not self._hold_queue(owner):
                if owner.cancel_ui is not None:
                    owner.cancel_ui()
                self._finish(owner, False, reason="потеряно владение очередью подтверждений")
        if self.clock() - self._last_sweep >= SWEEP_SECONDS:
            self.sweep()

    def _present(self, pending: _Pending) -> None:
        listing = self._current_listing()
        visible = listing.visible(pending.project)
        items = [visible[uid] for uid in pending.rows if uid in visible]
        items.sort(key=lambda item: pending.project not in item.projects)  # свои строки первыми
        request = AccessRequest(pending.project, pending.session, default_hours(self.profile), listing,
                                tuple(items), pending.why, test=self.profile.name == "test")
        remote = self._make_remote(request)
        with self._lock:
            skip = pending.finished or pending.cancelled
        if skip:
            self._channels_closed(pending)  # ask не вызывался, каналов ещё нет
            return
        cancel_ui = self.ui.ask(
            request,
            unlock=lambda password, chosen, hours: self._unlock(pending, password, chosen, hours),
            done=lambda granted, via="", reason="": self._finish(pending, granted, via, reason),
            remote=remote,
            unlock_remote=lambda code, kind: self._unlock_by_code(pending, remote[kind], code, request.hours),
            request_deadline=time.monotonic() + max(0, pending.deadline - self.clock()),
            on_channels_closed=lambda: self._channels_closed(pending))
        with self._lock:
            if not pending.finished or pending.cancelled and pending.defer_release:
                pending.cancel_ui = cancel_ui

    def _hold_queue(self, pending: _Pending) -> bool:
        with self._lock:
            self._queue_refreshed = self.clock()
            if self._queue_owner is not None and self._queue_owner is not pending:
                return False
            if self.bot_api is not None and self.queue_lock is not None:
                try:
                    pending.queue_token = self.queue_lock.refresh(pending.queue_token)
                except (RuntimeError, OSError) as error:
                    self.audit.write("queue_failed", reason=type(error).__name__)
                    return False
            self._queue_owner = pending
            return True

    def _channels_closed(self, pending: _Pending) -> None:
        with self._lock:
            pending.cancel_ui = None
            pending.defer_release = False
            self._release_queue(pending)

    def _release_queue(self, pending: _Pending) -> None:
        with self._lock:
            if self._queue_owner is not pending:
                return
            self._queue_refreshed = self.clock()
            if pending.queue_token is not None:
                try:
                    self.queue_lock.release(pending.queue_token)
                except (RuntimeError, OSError) as error:
                    try:
                        self.audit.write("queue_release_failed", reason=type(error).__name__)
                    except Exception:
                        pass
                    return
            self._queue_owner = None
            pending.queue_token = None

    def sweep(self) -> None:
        """Снимает истёкшие доступы проектов независимо от жизни отдельных сессий."""
        self._last_sweep = self.clock()
        with self._lock:
            for project, grant in list(self.grants.items()):
                if grant.expires > self.clock():
                    continue
                del self.grants[project]
                self.issued.pop(project, None)
                self.audit.write("access_expired", project=project, reason="истёк срок")
            self._drop_vault_if_unused()

    def _drop_vault_if_unused(self) -> None:
        if not self.grants and self.vault is not None:
            self.vault = None
            gc.collect()

    def should_exit(self) -> bool:
        if self.stop_requested:
            return True
        with self._lock:
            busy = self.grants or self._active is not None or self._queue_owner is not None or not self._pending.empty()
        return not busy and self.clock() - self._last_activity >= IDLE_EXIT_SECONDS

    def stop(self) -> None:
        self.stop_requested = True
        with self._lock:
            active = self._active
            cancel_ui = None
            if active is not None:
                active.cancelled = True
                cancel_ui, active.cancel_ui = active.cancel_ui, None
        if active is not None:
            if cancel_ui is not None:
                cancel_ui()
            self._finish(active, False, reason="посредник остановлен")
        while True:
            try:
                pending = self._pending.get_nowait()
            except queue.Empty:
                break
            pending.cancelled = True
            self._finish(pending, False, reason="посредник остановлен")
        with self._lock:
            self.grants.clear()
            self.issued.clear()
            self.vault = None
            self._totp = None
        if self._listener is not None:
            try:
                self._listener.close()
            except OSError:
                pass


def main() -> int:
    parser = argparse.ArgumentParser(description="Посредник PW_STORAGE")
    parser.add_argument("--profile", choices=sorted(PROFILES), default="main")
    args = parser.parse_args()
    profile = PROFILES[args.profile]

    from .window import TkUi, make_root

    root = make_root()
    on_forgot = None
    if profile.name == "test":  # восстановление для основного хранилища — на этапе его подготовки
        from .admin import recovery_window
        on_forgot = recovery_window
    telegram_on = telegram_enabled(profile)
    lock_path = queue_lock_path(profile)
    broker = Broker(profile, TpmKey(profile.catalog_key), TkUi(root, on_forgot=on_forgot),
                    queue_lock=QueueLock(lock_path) if lock_path else None)
    try:
        broker.start()
    except OSError:
        root.destroy()
        print("Посредник уже работает.", flush=True)
        return 0
    telegram = ("включится из хранилища после ввода пароля" if telegram_on else "выключен в settings.json")
    print(f"Посредник PW_STORAGE, профиль {profile.name}. Журнал: {profile.audit}", flush=True)
    print(f"Telegram: {telegram}. Закрыть окно — закрыть все доступы.", flush=True)

    def tick():
        broker.pump()
        if broker.should_exit():
            root.quit()
            return
        root.after(200, tick)

    root.after(200, tick)
    try:
        root.mainloop()
    finally:
        broker.stop()
        root.destroy()
        broker.ui.window = None
        gc.collect()
    print("Посредник завершён, файл хранилища выгружен из памяти.", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
