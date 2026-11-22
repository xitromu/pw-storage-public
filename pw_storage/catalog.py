"""Перечень для окна доступа (Т22, Т26): номер строки, список проектов, ALL, комментарий; зашифрован ключом TPM без кода.

Окно показывает его до ввода пароля, сессия по нему выбирает строки для запроса. Сервиса, ключа и значения
в нём нет. Строки без комментария не входят: считается только их число по проекту, для предупреждения.
Пересобирается при каждом изменении записей и при каждом открытии хранилища. Устаревшим считается,
если файл хранилища изменился после сборки перечня. В Google не копируется.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from .tpm import TpmError, seal, unseal
from .vault import Row, VaultChanged, _atomic_bytes, _hash_or_none

FRESH = "fresh"
STALE = "stale"
MISSING = "missing"
FORMAT = 2


@dataclass(frozen=True)
class Item:
    uid: str
    group: str
    projects: tuple[str, ...]
    shared: bool
    comment: str

    def to_dict(self) -> dict:
        """Для сессии: без списка проектов, чтобы не раскрывать, кто ещё пользуется записью."""
        return {"id": self.uid, "comment": self.comment, "all": self.shared}


@dataclass(frozen=True)
class Listing:
    state: str
    items: tuple[Item, ...] = ()
    unnamed: tuple[tuple[tuple[str, ...], bool], ...] = ()  # строки без комментария: проекты и ALL

    def own(self, project: str) -> list[Item]:
        return [item for item in self.items if project in item.projects]

    def common(self, project: str) -> list[Item]:
        """Строки из ALL, которых нет в списке проекта: их одобрение добавит проект в список."""
        return [item for item in self.items if item.shared and project not in item.projects]

    def visible(self, project: str) -> dict[str, Item]:
        return {item.uid: item for item in (*self.own(project), *self.common(project))}

    def unnamed_count(self, project: str) -> int:
        return sum(1 for projects, shared in self.unnamed if project in projects or shared)


def listing_from_rows(rows: list[Row], state: str = FRESH) -> Listing:
    named = [row for row in rows if row.comment.strip()]
    return Listing(
        state,
        tuple(Item(row.uid, row.group, row.projects, row.shared, row.comment) for row in named),
        tuple((row.projects, row.shared) for row in rows if not row.comment.strip()),
    )


def write(key, path: Path, rows: list[Row], vault_path: Path, *, source_hash: str) -> None:
    if _hash_or_none(vault_path) != source_hash:
        raise VaultChanged("Снимок хранилища устарел: перечень не записан")
    if not key.exists():
        key.create()
    listing = listing_from_rows(rows)
    payload = {
        "format": FORMAT,
        "vault_sha256": source_hash,
        "items": [[i.uid, i.group, list(i.projects), i.shared, i.comment] for i in listing.items],
        "unnamed": [[list(projects), shared] for projects, shared in listing.unnamed],
    }
    _atomic_bytes(Path(path), seal(key, json.dumps(payload, ensure_ascii=False).encode("utf-8")))


def read(key, path: Path, vault_path: Path) -> Listing:
    path = Path(path)
    if not path.exists():
        return Listing(MISSING)
    try:
        payload = json.loads(unseal(key, path.read_bytes()).decode("utf-8"))
        if payload.get("format") != FORMAT:
            return Listing(MISSING)  # перечень прежнего вида: соберётся заново после пароля
        items = tuple(Item(uid, group, tuple(projects), bool(shared), comment)
                      for uid, group, projects, shared, comment in payload["items"])
        unnamed = tuple((tuple(projects), bool(shared)) for projects, shared in payload["unnamed"])
    except (TpmError, ValueError, KeyError, TypeError):
        return Listing(MISSING)  # например, файл принесён с другого компьютера
    current = _hash_or_none(vault_path) == payload["vault_sha256"]
    return Listing(FRESH if current else STALE, items, unnamed)
