"""Запись результатов.

Прошлая версия писала десять файлов, шесть из которых были побайтово
одинаковыми, а файлы с "tme" в имени содержали обычные tg:// ссылки.
Здесь у каждого файла своё содержимое.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone

from .model import REGIONS, Result

HEADER = "# {title}\n# Обновлено: {stamp}\n# Прокси: {count}\n\n"


def _write_links(path: str, title: str, results: list[Result], stamp: str,
                 tme: bool = False) -> None:
    lines = [r.proxy.tme_link if tme else r.proxy.link for r in results]
    body = HEADER.format(title=title, stamp=stamp, count=len(results)) + "\n".join(lines)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(body + ("\n" if lines else ""))


def write_all(results: list[Result], out_dir: str, *, top: int = 0,
              run_info: dict | None = None) -> dict:
    """Пишет списки и статистику. top=0 означает без ограничения."""
    os.makedirs(out_dir, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    mtproto = [r for r in results if r.proxy.kind == "mtproto"]
    socks5 = [r for r in results if r.proxy.kind == "socks5"]
    by_region = {reg: [r for r in mtproto if r.region == reg] for reg in REGIONS}

    limit = (lambda items: items[:top]) if top > 0 else (lambda items: items)

    titles = {
        "ru": "MTProto RU: маскировка под российские сервисы",
        "eu": "MTProto EU и остальной мир",
        "us": "MTProto US и Канада",
        "asia": "MTProto Азия",
    }
    for region in REGIONS:
        _write_links(os.path.join(out_dir, f"proxy_{region}.txt"),
                     titles[region], limit(by_region[region]), stamp)

    _write_links(os.path.join(out_dir, "mtproto.txt"), "Все MTProto", limit(mtproto), stamp)
    _write_links(os.path.join(out_dir, "socks5.txt"), "SOCKS5", limit(socks5), stamp)
    _write_links(os.path.join(out_dir, "all.txt"), "Все прокси", limit(results), stamp)
    _write_links(os.path.join(out_dir, "tme_links.txt"), "Все прокси, ссылки t.me",
                 limit(results), stamp, tme=True)

    with open(os.path.join(out_dir, "proxies.json"), "w", encoding="utf-8", newline="\n") as fh:
        json.dump([r.as_dict() for r in limit(results)], fh, indent=2, ensure_ascii=False)

    stats = {
        "updated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "total": len(results),
        "mtproto": len(mtproto),
        "socks5": len(socks5),
        "by_region": {reg: len(by_region[reg]) for reg in REGIONS},
        "by_method": _count(r.method for r in results),
        "by_country": _count(r.country or "unknown" for r in results),
        "probe_resistant": sum(1 for r in mtproto if r.probe_resistant),
        "median_ping": _median([r.ping for r in results]),
        **(run_info or {}),
    }
    with open(os.path.join(out_dir, "stats.json"), "w", encoding="utf-8", newline="\n") as fh:
        json.dump(stats, fh, indent=2, ensure_ascii=False)
    return stats


def _count(values) -> dict[str, int]:
    out: dict[str, int] = {}
    for value in values:
        out[value] = out.get(value, 0) + 1
    return dict(sorted(out.items(), key=lambda kv: -kv[1]))


def _median(values: list[float]) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    middle = len(ordered) // 2
    if len(ordered) % 2:
        return round(ordered[middle], 3)
    return round((ordered[middle - 1] + ordered[middle]) / 2, 3)
