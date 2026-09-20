"""Загрузка списка источников и параллельное скачивание.

Раньше 50 источников качались строго по очереди, по три попытки с таймаутом
15 секунд каждая: худший случай упирался в лимит шага CI. Теперь загрузка
идёт пулом потоков.
"""

from __future__ import annotations

import concurrent.futures
import os
from dataclasses import dataclass, field

import requests

DEFAULT_SOURCES_FILE = "sources.txt"

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)


@dataclass
class SourceStat:
    url: str
    kind: str
    ok: bool = False
    bytes: int = 0
    found: int = 0
    error: str = ""


@dataclass
class SourceList:
    mtproto: list[str] = field(default_factory=list)
    socks5: list[str] = field(default_factory=list)

    def __len__(self) -> int:
        return len(self.mtproto) + len(self.socks5)

    def items(self) -> list[tuple[str, str]]:
        return [("mtproto", u) for u in self.mtproto] + [("socks5", u) for u in self.socks5]


def load_sources(path: str = DEFAULT_SOURCES_FILE) -> SourceList:
    """Читает sources.txt: секции [mtproto] и [socks5], по URL в строке."""
    if not os.path.isfile(path):
        raise FileNotFoundError(f"файл источников не найден: {path}")

    result = SourceList()
    bucket: list[str] | None = None
    with open(path, "r", encoding="utf-8") as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("[") and line.endswith("]"):
                name = line[1:-1].strip().lower()
                bucket = result.mtproto if name == "mtproto" else (
                    result.socks5 if name == "socks5" else None)
                if bucket is None:
                    raise ValueError(f"неизвестная секция в {path}: {line}")
                continue
            if bucket is None:
                raise ValueError(f"URL вне секции в {path}: {line}")
            bucket.append(line)
    return result


def make_session() -> requests.Session:
    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT, "Accept": "*/*"})
    adapter = requests.adapters.HTTPAdapter(pool_connections=32, pool_maxsize=32)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session


def fetch_all(
    sources: SourceList,
    *,
    timeout: float = 20.0,
    retries: int = 2,
    workers: int = 16,
    progress=None,
) -> list[tuple[str, str, SourceStat]]:
    """Качает все источники параллельно.

    Возвращает список (kind, text, stat). Текст пустой, если источник упал.
    """
    session = make_session()

    def fetch(item: tuple[str, str]) -> tuple[str, str, SourceStat]:
        kind, url = item
        stat = SourceStat(url=url, kind=kind)
        for attempt in range(retries + 1):
            try:
                response = session.get(url, timeout=timeout)
                if response.status_code == 200:
                    stat.ok = True
                    stat.bytes = len(response.content)
                    return kind, response.text, stat
                stat.error = f"HTTP {response.status_code}"
            except requests.RequestException as exc:
                stat.error = type(exc).__name__
            if attempt == retries:
                break
        return kind, "", stat

    results: list[tuple[str, str, SourceStat]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        for kind, text, stat in pool.map(fetch, sources.items()):
            results.append((kind, text, stat))
            if progress:
                progress(stat)
    session.close()
    return results
