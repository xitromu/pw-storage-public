"""Журнал выдачи (Т6, Т8): время, событие, проект, сервис, имя ключа. Значений и пароля здесь не бывает."""

from __future__ import annotations

import json
import threading
from datetime import datetime
from pathlib import Path

ALLOWED_FIELDS = {"project", "session", "scope", "service", "key", "pid", "script", "via", "reason", "state", "rows",
                  "row", "group", "hours", "why", "target", "count"}


class Audit:
    def __init__(self, path: Path, echo: bool = True):
        self.path = Path(path)
        self.echo = echo
        self._lock = threading.Lock()

    def write(self, event: str, **fields) -> None:
        unknown = set(fields) - ALLOWED_FIELDS
        if unknown:
            raise ValueError(f"Поля вне списка не пишем в журнал: {sorted(unknown)}")
        record = {"time": datetime.now().isoformat(timespec="seconds"), "event": event, **fields}
        line = json.dumps(record, ensure_ascii=False)
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as f:
                f.write(line + "\n")
            if self.echo:
                print(line, flush=True)
