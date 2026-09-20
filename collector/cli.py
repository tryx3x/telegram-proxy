"""Точка входа: сбор, фильтрация, проверка, запись."""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import random
import sys
import time

from .cache import SeenCache
from .geoip import GeoIP
from .model import (
    ALLOWED_COUNTRIES,
    SUSPICIOUS_PORTS,
    Proxy,
    Result,
    is_blocked_domain,
    region_from_country,
    region_from_domain,
    sort_results,
)
from .output import write_all
from .parse import decode_faketls_domain, inner_secret, parse_text
from .probe import HAS_AES, ProbeError, is_local_resource_error, probe, tcp_connect
from .sources import DEFAULT_SOURCES_FILE, fetch_all, load_sources


def log(message: str = "") -> None:
    print(message, flush=True)


# --- этапы --------------------------------------------------------------------

def harvest(sources_file: str, *, timeout: float, workers: int,
            quiet: bool) -> tuple[set[Proxy], dict]:
    sources = load_sources(sources_file)
    log(f"Источников: {len(sources.mtproto)} MTProto, {len(sources.socks5)} SOCKS5")

    candidates: set[Proxy] = set()
    per_source: dict[str, int] = {}
    dead: list[str] = []
    for kind, text, stat in fetch_all(sources, timeout=timeout, workers=workers):
        if not text:
            dead.append(f"{stat.url} ({stat.error})")
            if not quiet:
                log(f"  [нет ответа] {stat.error:<14} {stat.url[:80]}")
            continue
        found = parse_text(text, expect=kind)
        stat.found = len(found)
        per_source[stat.url] = len(found)
        candidates |= found
        if not quiet:
            log(f"  [{len(found):>6}] {stat.url[:80]}")
    if dead:
        log(f"Не ответили источников: {len(dead)}")
    summary = {
        "sources_ok": len(per_source),
        "sources_dead": dead,
        "by_source": dict(sorted(per_source.items(), key=lambda kv: -kv[1])),
    }
    return candidates, summary


def prefilter(candidates: set[Proxy]) -> tuple[list[Proxy], dict[str, int]]:
    """Отбрасывает то, что заведомо не может быть рабочим прокси."""
    dropped = {"порт": 0, "маска заблокирована": 0, "короткий секрет": 0}
    kept: list[Proxy] = []
    for proxy in candidates:
        if proxy.kind == "mtproto":
            if proxy.port in SUSPICIOUS_PORTS:
                dropped["порт"] += 1
                continue
            if len(inner_secret(proxy.secret or "")) < 32:
                dropped["короткий секрет"] += 1
                continue
            if is_blocked_domain(decode_faketls_domain(proxy.secret)):
                dropped["маска заблокирована"] += 1
                continue
        kept.append(proxy)
    return kept, dropped


def load_previous(out_dir: str) -> set[Proxy]:
    """Победители прошлого прогона.

    Публикуется только то, что подтвердилось в текущем прогоне, поэтому
    прошлые рабочие прокси обязаны перепроверяться всегда. Иначе один неудачный
    прогон обнуляет весь список.
    """
    path = os.path.join(out_dir, "proxies.json")
    if not os.path.isfile(path):
        return set()
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError):
        return set()
    links = "\n".join(str(item.get("link", "")) for item in data if isinstance(item, dict))
    return parse_text(links)


def apply_limit(proxies: list[Proxy], max_check: int,
                keep: set | None = None) -> list[Proxy]:
    """Ограничивает объём прогона, не жертвуя MTProto.

    SOCKS5-источников на два порядка больше (около 180 000 против 1900), и при
    общей случайной выборке MTProto почти не попадал в проверку. Поэтому
    MTProto берётся целиком, а урезается хвост SOCKS5.

    Порядок в конце перемешивается: очередь проверки не должна начинаться с
    одного и того же класса прокси, иначе при нехватке локальных сокетов
    страдают всегда одни и те же.
    """
    keep = keep or set()
    if not max_check or len(proxies) <= max_check:
        result = list(proxies)
    else:
        must = [p for p in proxies if p.kind == "mtproto" or p.key in keep]
        rest = [p for p in proxies if not (p.kind == "mtproto" or p.key in keep)]
        if len(must) >= max_check:
            result = random.sample(must, max_check)
        else:
            result = must + random.sample(rest, max_check - len(must))
    random.shuffle(result)
    return result


def reachable(proxies: list[Proxy], *, timeout: float, workers: int,
              geoip: GeoIP) -> tuple[list[tuple[Proxy, str]], dict[str, int]]:
    """Быстрый TCP-проход. Заодно даёт реальный IP для GeoIP-фильтра."""
    stats = {"не отвечает": 0, "страна не в списке": 0, "живы": 0}
    alive: list[tuple[Proxy, str]] = []

    def touch(proxy: Proxy):
        try:
            sock, _ = tcp_connect(proxy.host, proxy.port, timeout)
        except OSError:
            return None
        try:
            return proxy, sock.getpeername()[0]
        finally:
            sock.close()

    done = 0
    total = len(proxies)
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        for outcome in pool.map(touch, proxies):
            done += 1
            if done % 2000 == 0 or done == total:
                log(f"  [{done}/{total}] живых: {stats['живы']}")
            if outcome is None:
                stats["не отвечает"] += 1
                continue
            proxy, ip = outcome
            if geoip.enabled:
                country = geoip.country(ip)
                if country and country.upper() not in ALLOWED_COUNTRIES:
                    stats["страна не в списке"] += 1
                    continue
            stats["живы"] += 1
            alive.append((proxy, ip))
    return alive, stats


def verify(alive: list[tuple[Proxy, str]], *, timeout: float, workers: int, geoip: GeoIP,
           connect_test: bool) -> tuple[list[Result], dict[str, int], set]:
    """Полноценный хендшейк по протоколу.

    Третьим значением возвращает ключи прокси, которые не удалось проверить
    из-за нехватки локальных сокетов: их нельзя заносить в кэш неудач.
    """
    failures: dict[str, int] = {}
    results: list[Result] = []
    unreliable: set = set()

    def check(item: tuple[Proxy, str]):
        proxy, ip = item
        for attempt in (0, 1):
            try:
                ping, method = probe(proxy, timeout, connect_test)
                return proxy, (ping, method, ip), ""
            except (ProbeError, OSError) as exc:
                if is_local_resource_error(exc):
                    if attempt == 0:
                        time.sleep(0.5 + random.random())
                        continue
                    return proxy, None, "__local__"
                return proxy, None, f"{exc}"[:60]
        return proxy, None, "__local__"

    done = 0
    total = len(alive)
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        for proxy, outcome, error in pool.map(check, alive):
            done += 1
            if done % 500 == 0 or done == total:
                log(f"  [{done}/{total}] подтверждено: {len(results)}")
            if outcome is None:
                if error == "__local__":
                    unreliable.add(proxy.key)
                    error = "не хватило локальных сокетов, проверка отложена"
                failures[error] = failures.get(error, 0) + 1
                continue
            ping, method, ip = outcome
            country = geoip.country(ip)
            domain = decode_faketls_domain(proxy.secret) or ""
            region = (region_from_domain(domain) if domain else None) \
                or region_from_country(country) or "eu"
            results.append(Result(
                proxy=proxy,
                ping=ping,
                method=method,
                region=region,
                domain=domain,
                country=country,
                probe_resistant=(method == "faketls_hmac"),
            ))
    return results, failures, unreliable


# --- сборка -------------------------------------------------------------------

def run(args: argparse.Namespace) -> int:
    started = time.monotonic()

    log("Telegram Proxy Collector")
    log("=" * 60)
    if not HAS_AES:
        log("Внимание: нет cryptography и pycryptodome, obfuscated2-прокси "
            "проверить не получится (fake-TLS и SOCKS5 работают).")

    geoip = GeoIP(args.geoip) if args.geoip else GeoIP()
    log(f"GeoIP: {geoip.mode if geoip.enabled else 'выключен'}")

    log("\nСбор источников")
    candidates, source_summary = harvest(args.sources, timeout=args.fetch_timeout,
                                         workers=args.fetch_workers, quiet=args.quiet)
    log(f"Уникальных кандидатов: {len(candidates)}")
    if not candidates:
        log("Ничего не собрано, выходим.")
        return 1

    kept, dropped = prefilter(candidates)
    log("Отсеяно до проверки: " + ", ".join(f"{k} {v}" for k, v in dropped.items() if v))

    previous = {p.key for p in load_previous(args.output_dir)}
    if previous:
        log(f"Рабочих в прошлом прогоне: {len(previous)}, они проверяются заново")

    cache = SeenCache(args.seen_file, ttl_hours=args.seen_ttl)
    cached = cache.load()
    if cached:
        log(f"В кэше неудачных попыток: {cached} (TTL {args.seen_ttl} ч)")

    # Кэш нужен только для SOCKS5: их около 180 000 и перебрать всех за прогон
    # нельзя. MTProto-кандидатов меньше двух тысяч, они дешевле в проверке и
    # живут недолго, поэтому проверяются каждый раз. Прошлые победители тоже.
    def skip(proxy: Proxy) -> bool:
        if proxy.kind == "mtproto" or proxy.key in previous:
            return False
        return proxy.key in cache

    fresh = [p for p in kept if not skip(p)]
    log(f"К проверке: {len(fresh)} (пропущено по кэшу: {len(kept) - len(fresh)})")

    fresh = apply_limit(fresh, args.max_check, keep=previous)
    mtproto_count = sum(1 for p in fresh if p.kind == "mtproto")
    log(f"В работе: {mtproto_count} MTProto, {len(fresh) - mtproto_count} SOCKS5")
    if not fresh:
        log("Нечего проверять.")
        return 0

    log(f"\nЭтап 1: TCP ({len(fresh)} шт, таймаут {args.tcp_timeout} с)")
    alive, reach_stats = reachable(fresh, timeout=args.tcp_timeout,
                                   workers=args.workers, geoip=geoip)
    log("  " + ", ".join(f"{k}: {v}" for k, v in reach_stats.items()))

    log(f"\nЭтап 2: хендшейк по протоколу ({len(alive)} шт, таймаут {args.timeout} с)")
    results, failures, unreliable = verify(
        alive, timeout=args.timeout, workers=args.probe_workers,
        geoip=geoip, connect_test=not args.no_connect_test)
    if unreliable:
        log(f"  Не проверено из-за лимита сокетов на этой машине: {len(unreliable)}. "
            f"Уменьшите --probe-workers.")

    # Рабочие перепроверяем каждый раз, неудачные придерживаем до истечения TTL.
    working = {r.proxy.key for r in results}
    for proxy in fresh:
        if proxy.key in working:
            cache.forget(proxy.key)
        elif proxy.kind == "socks5" and proxy.key not in unreliable:
            cache.mark(proxy.key)
    saved = cache.save()

    results = sort_results(results)
    stats = write_all(results, args.output_dir, top=args.top, run_info={
        "checked": len(fresh),
        "tcp_alive": len(alive),
        "checked_mtproto": mtproto_count,
        "seconds": round(time.monotonic() - started, 1),
        "geoip": geoip.mode,
        **source_summary,
    })
    geoip.close()

    log("\n" + "=" * 60)
    log(f"Подтверждено рабочих: {len(results)} из {len(fresh)} проверенных")
    log(f"  MTProto {stats['mtproto']} (RU {stats['by_region']['ru']}, "
        f"EU {stats['by_region']['eu']}, US {stats['by_region']['us']}, "
        f"ASIA {stats['by_region']['asia']}), из них probe-resistant "
        f"{stats['probe_resistant']}")
    log(f"  SOCKS5  {stats['socks5']}")
    log(f"  Методы: {stats['by_method']}")
    log(f"  Медианный пинг: {stats['median_ping']} с")
    log(f"  Кэш: {saved} записей")
    if failures:
        log("  Частые причины отказа:")
        for reason, count in sorted(failures.items(), key=lambda kv: -kv[1])[:6]:
            log(f"    {count:>6}  {reason}")
    log(f"Готово за {round(time.monotonic() - started, 1)} с, файлы в {args.output_dir}/")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m collector",
        description="Сбор и настоящая проверка MTProto/SOCKS5 прокси для Telegram",
    )
    parser.add_argument("--sources", default=DEFAULT_SOURCES_FILE,
                        help="файл со списком источников")
    parser.add_argument("--output-dir", default="lists", help="куда складывать списки")
    parser.add_argument("--geoip", help="путь к базе MaxMind .mmdb")
    parser.add_argument("--top", type=int, default=0,
                        help="сколько прокси оставить в каждом файле, 0 = все")
    parser.add_argument("--max-check", type=int, default=40000,
                        help="максимум прокси на один прогон")

    parser.add_argument("--tcp-timeout", type=float, default=2.0, help="таймаут этапа 1")
    parser.add_argument("--timeout", type=float, default=5.0, help="таймаут хендшейка")
    parser.add_argument("--workers", type=int, default=150, help="потоков на этапе 1")
    parser.add_argument("--probe-workers", type=int, default=80, help="потоков на этапе 2")
    parser.add_argument("--fetch-timeout", type=float, default=20.0, help="таймаут источника")
    parser.add_argument("--fetch-workers", type=int, default=16, help="потоков на скачивание")
    parser.add_argument("--no-connect-test", action="store_true",
                        help="для SOCKS5 не проверять CONNECT до Telegram")

    parser.add_argument("--cooldown", type=float, default=5.0,
                        help="пауза между этапами, чтобы ОС освободила сокеты")
    parser.add_argument("--seen-file", default="data/seen.json",
                        help="кэш неудачных SOCKS5")
    parser.add_argument("--seen-ttl", type=int, default=6, help="TTL кэша в часах")
    parser.add_argument("--quiet", action="store_true", help="меньше вывода")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return run(args)
    except KeyboardInterrupt:
        log("\nПрервано.")
        return 130
    except (FileNotFoundError, ValueError, RuntimeError) as exc:
        log(f"Ошибка: {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
