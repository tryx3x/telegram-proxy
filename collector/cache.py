"""Кэш уже проверенных прокси с честным TTL.

В прошлой версии сохранение перештамповывало каждую запись текущим временем,
поэтому попавший в кэш прокси не перепроверялся никогда, а итоговые списки
постепенно пустели. Здесь время первой проверки сохраняется как есть,
и запись действительно истекает.
"""

from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime, timedelta, timezone

Key = tuple[str, str, int, str]


class SeenCache:
    def __init__(self, path: str | None, ttl_hours: int = 6, limit: int = 200_000) -> None:
        self.path = path
        self.ttl = timedelta(hours=ttl_hours)
        self.limit = limit
        self._stamps: dict[Key, datetime] = {}

    def load(self) -> int:
        """Читает кэш, отбрасывая просроченное. Возвращает число живых записей."""
        self._stamps.clear()
        if not self.path or not os.path.isfile(self.path):
            return 0
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, json.JSONDecodeError):
            return 0

        now = datetime.now(timezone.utc)
        for item in data.get("seen", []):
            try:
                key = tuple(item["k"])
                stamp = datetime.fromisoformat(str(item["ts"]).replace("Z", "+00:00"))
            except (KeyError, TypeError, ValueError):
                continue
            if len(key) != 4:
                continue
            if now - stamp <= self.ttl:
                self._stamps[(str(key[0]), str(key[1]), int(key[2]), str(key[3]))] = stamp
        return len(self._stamps)

    def __contains__(self, key: Key) -> bool:
        return key in self._stamps

    def mark(self, key: Key) -> None:
        """Отмечает прокси проверенным сейчас, не трогая уже известное время."""
        self._stamps.setdefault(key, datetime.now(timezone.utc))

    def forget(self, key: Key) -> None:
        self._stamps.pop(key, None)

    def save(self) -> int:
        if not self.path:
            return 0
        items = sorted(self._stamps.items(), key=lambda kv: kv[1], reverse=True)[: self.limit]
        payload = {
            "updated": datetime.now(timezone.utc).isoformat(),
            "ttl_hours": round(self.ttl.total_seconds() / 3600, 2),
            "seen": [{"k": list(key), "ts": stamp.isoformat()} for key, stamp in items],
        }
        directory = os.path.dirname(self.path) or "."
        os.makedirs(directory, exist_ok=True)
        # Пишем через временный файл: прерванный прогон не оставит битый JSON.
        handle, tmp = tempfile.mkstemp(dir=directory, suffix=".tmp")
        try:
            with os.fdopen(handle, "w", encoding="utf-8") as fh:
                json.dump(payload, fh)
            os.replace(tmp, self.path)
        except BaseException:
            if os.path.exists(tmp):
                os.unlink(tmp)
            raise
        return len(items)

    def __len__(self) -> int:
        return len(self._stamps)
