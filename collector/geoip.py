"""GeoIP по базе MaxMind.

Определение страны делается по реальному IP, полученному из установленного
соединения, а не по имени хоста: в прошлой версии доменные прокси всегда
проваливали lookup и проходили фильтр без проверки.
"""

from __future__ import annotations

import os

try:
    import maxminddb
except ImportError:  # pragma: no cover
    maxminddb = None  # type: ignore

try:
    from geoip2.database import Reader as GeoIP2Reader
except ImportError:  # pragma: no cover
    GeoIP2Reader = None  # type: ignore


class GeoIP:
    """Обёртка над базой стран. Работает и без базы, тогда country() даёт None."""

    def __init__(self, path: str | None = None) -> None:
        self.mode: str | None = None
        self._reader = None
        if path:
            self._open(path)

    def _open(self, path: str) -> None:
        if not os.path.isfile(path):
            raise FileNotFoundError(f"база GeoIP не найдена: {path}")
        errors = []
        if maxminddb is not None:
            try:
                self._reader = maxminddb.open_database(path)
                self.mode = "maxminddb"
                return
            except Exception as exc:
                errors.append(f"maxminddb: {exc}")
        if GeoIP2Reader is not None:
            try:
                self._reader = GeoIP2Reader(path)
                self.mode = "geoip2"
                return
            except Exception as exc:
                errors.append(f"geoip2: {exc}")
        raise RuntimeError(
            "не удалось открыть базу GeoIP. "
            "Нужен файл формата MaxMind .mmdb. " + "; ".join(errors)
        )

    @property
    def enabled(self) -> bool:
        return self._reader is not None

    def country(self, ip: str) -> str | None:
        if self._reader is None:
            return None
        try:
            if self.mode == "maxminddb":
                info = self._reader.get(ip)
                if not info:
                    return None
                return (info.get("country") or {}).get("iso_code")
            info = self._reader.country(ip)
            return info.country.iso_code if info.country else None
        except Exception:
            return None

    def close(self) -> None:
        if self._reader is not None:
            try:
                self._reader.close()
            except Exception:
                pass
            self._reader = None

    def __enter__(self) -> "GeoIP":
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()
