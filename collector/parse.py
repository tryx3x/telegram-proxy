"""Разбор сырых списков прокси в любом из встречающихся форматов."""

from __future__ import annotations

import json
import re
from urllib.parse import unquote

from .model import Proxy

# tg://proxy?server=..&port=..&secret=..  и t.me/proxy?...
_RE_TG_PROXY = re.compile(
    r"(?:tg://proxy|t\.me/proxy|telegram\.me/proxy)\?"
    r"server=([^&\s\"']+)&(?:amp;)?port=(\d{1,5})&(?:amp;)?secret=([A-Za-z0-9_=+/%-]+)",
    re.I,
)
# tg://socks?server=..&port=..[&user=..&pass=..]
_RE_TG_SOCKS = re.compile(
    r"(?:tg://socks|t\.me/socks)\?server=([^&\s\"']+)&(?:amp;)?port=(\d{1,5})"
    r"(?:&(?:amp;)?user=([^&\s\"']*))?(?:&(?:amp;)?pass=([^&\s\"']*))?",
    re.I,
)
# host:port:secret
_RE_TRIPLET = re.compile(r"\b([A-Za-z0-9][A-Za-z0-9.\-]{2,253}):(\d{1,5}):([A-Fa-f0-9]{32,})\b")
# socks5://[user:pass@]host:port
_RE_SOCKS_URL = re.compile(
    r"socks5(?:h)?://(?:([^:@/\s]+):([^@/\s]+)@)?([A-Za-z0-9][A-Za-z0-9.\-]{2,253}):(\d{1,5})",
    re.I,
)
# голые ip:port в socks5-списках
_RE_BARE_HOSTPORT = re.compile(r"^\s*((?:\d{1,3}\.){3}\d{1,3}):(\d{1,5})\s*$", re.M)

_HEX_RE = re.compile(r"^[A-Fa-f0-9]+$")


def valid_port(value: object) -> bool:
    try:
        return 1 <= int(value) <= 65535
    except (TypeError, ValueError):
        return False


def normalize_secret(secret: str) -> str | None:
    """Приводит секрет к hex. Понимает base64url, percent-encoding и префиксы ee/dd."""
    if not secret:
        return None
    secret = unquote(secret).strip()
    if _HEX_RE.match(secret) and len(secret) % 2 == 0:
        return secret.lower()
    # base64url -> hex
    padded = secret.replace("-", "+").replace("_", "/")
    padded += "=" * (-len(padded) % 4)
    try:
        import base64

        raw = base64.b64decode(padded, validate=True)
    except Exception:
        return None
    if len(raw) < 16:
        return None
    return raw.hex()


_DOMAIN_TAIL = re.compile(r"([a-z0-9][a-z0-9\-]{0,62}(?:\.[a-z0-9][a-z0-9\-]{0,62})+)\.?$", re.I)


def decode_faketls_domain(secret: str | None) -> str | None:
    """Домен-маска из fake-TLS секрета.

    Формат: "ee" + 32 hex (16 байт собственно секрета) + hex(домен).
    Прошлая версия начинала читать с позиции 2 и подмешивала в домен сам
    секрет, из-за чего в списках оказывались строки вида "v,+u0up75www.google.com".

    Часть публикуемых секретов держит перед доменом лишний служебный байт
    (например "\\xdd"), поэтому домен берётся как хвост строки, а не всё
    содержимое целиком.
    """
    if not secret:
        return None
    low = secret.lower()
    if not low.startswith("ee") or len(low) <= 34:
        return None
    try:
        raw = bytes.fromhex(low[34:])
    except ValueError:
        return None
    match = _DOMAIN_TAIL.search(raw.decode("latin-1"))
    if not match:
        return None
    return match.group(1).lower()


def inner_secret(secret: str) -> str:
    """16 байт собственно секрета без префиксов ee/dd и без хвоста с доменом."""
    low = secret.lower()
    if low.startswith("ee"):
        return low[2:34]
    if low.startswith("dd"):
        return low[2:34]
    return low[:32]


def _add_mtproto(out: set[Proxy], host: str, port: str, secret: str) -> None:
    if not valid_port(port):
        return
    norm = normalize_secret(secret)
    if not norm or len(norm) < 32:
        return
    host = host.strip().strip(".").lower()
    if not host:
        return
    out.add(Proxy("mtproto", host, int(port), secret=norm))


def _add_socks(out: set[Proxy], host: str, port: str, user: str | None = None,
               password: str | None = None) -> None:
    if not valid_port(port):
        return
    host = host.strip().lower()
    if not host:
        return
    out.add(Proxy("socks5", host, int(port),
                  username=unquote(user) if user else None,
                  password=unquote(password) if password else None))


def _parse_json(text: str, out: set[Proxy]) -> None:
    stripped = text.strip()
    if not stripped or stripped[0] not in "[{":
        return
    try:
        data = json.loads(stripped)
    except json.JSONDecodeError:
        return

    items: list = []
    if isinstance(data, list):
        items = data
    elif isinstance(data, dict):
        for key in ("proxies", "items", "data", "results", "list", "all"):
            if isinstance(data.get(key), list):
                items = data[key]
                break
        else:
            items = [data]

    for item in items:
        if not isinstance(item, dict):
            continue
        host = item.get("host") or item.get("server") or item.get("ip") or item.get("address")
        port = item.get("port")
        if not host or not valid_port(port):
            continue
        secret = item.get("secret")
        if secret:
            _add_mtproto(out, str(host), str(port), str(secret))
        elif str(item.get("type", "")).lower() in ("socks5", "socks"):
            _add_socks(out, str(host), str(port),
                       item.get("username") or item.get("user"),
                       item.get("password") or item.get("pass"))


def _parse_yaml(text: str, out: set[Proxy]) -> None:
    if "proxies:" not in text:
        return
    try:
        import yaml
    except ImportError:
        return
    try:
        data = yaml.safe_load(text)
    except Exception:
        return
    if not isinstance(data, dict) or not isinstance(data.get("proxies"), list):
        return
    for item in data["proxies"]:
        if not isinstance(item, dict) or str(item.get("type", "")).lower() != "socks5":
            continue
        if item.get("server") and valid_port(item.get("port")):
            _add_socks(out, str(item["server"]), str(item["port"]),
                       item.get("username"), item.get("password"))


def parse_text(text: str, *, expect: str | None = None) -> set[Proxy]:
    """Достаёт все прокси из произвольного текста.

    expect="socks5" дополнительно включает разбор голых строк ip:port,
    которые в MTProto-списках означали бы совсем другое.
    """
    out: set[Proxy] = set()

    for host, port, secret in _RE_TG_PROXY.findall(text):
        _add_mtproto(out, host, port, secret)
    for host, port, user, password in _RE_TG_SOCKS.findall(text):
        _add_socks(out, host, port, user or None, password or None)
    for host, port, secret in _RE_TRIPLET.findall(text):
        _add_mtproto(out, host, port, secret)
    for user, password, host, port in _RE_SOCKS_URL.findall(text):
        _add_socks(out, host, port, user or None, password or None)

    if expect == "socks5":
        for host, port in _RE_BARE_HOSTPORT.findall(text):
            _add_socks(out, host, port)

    _parse_json(text, out)
    _parse_yaml(text, out)
    return out
