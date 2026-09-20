"""Модель прокси и справочники регионов, стран и портов."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable
from urllib.parse import quote

# --- Домены-маски fake-TLS, по которым определяется регион -------------------

RU_DOMAINS = (
    ".ru", ".su", ".by", ".kz", "yandex", "vk.com", "mail.ru", "ok.ru", "dzen",
    "rutube", "sber", "tinkoff", "vtb", "gosuslugi", "nalog", "mos.ru", "ozon",
    "wildberries", "avito", "kinopoisk", "mts", "beeline", "megafon",
)
US_DOMAINS = (
    ".us", ".gov", "amazonaws.com", "digitalocean.com", "cloudflare.com",
    "akamai", "steampowered.com", "microsoft.com", "windows.net",
)
ASIA_DOMAINS = (
    ".asia", ".jp", ".cn", ".sg", ".hk", ".kr", ".in", ".tw", ".ph", ".my",
    ".id", ".vn", ".th", ".mn",
)

# Маски под заведомо заблокированные в RU ресурсы: такой прокси сам привлекает DPI.
BLOCKED_DOMAINS = (
    "instagram", "facebook", "twitter", "bbc", "meduza", "linkedin",
    "torproject", "tiktok",
)

# --- Страны ------------------------------------------------------------------

COUNTRY_TO_REGION: dict[str, str] = {}
for _code in ("RU", "BY", "KZ", "UA", "MD", "AM", "GE", "AZ", "UZ", "KG", "TJ", "TM"):
    COUNTRY_TO_REGION[_code] = "ru"
for _code in (
    "DE", "NL", "FI", "GB", "FR", "SE", "PL", "CZ", "AT", "CH", "IT", "ES",
    "NO", "DK", "BE", "IE", "LU", "EE", "LV", "LT", "PT", "GR", "RO", "BG",
    "HU", "SK", "SI", "HR", "RS", "TR",
):
    COUNTRY_TO_REGION[_code] = "eu"
for _code in ("US", "CA"):
    COUNTRY_TO_REGION[_code] = "us"
for _code in ("JP", "KR", "SG", "HK", "IN", "TW", "PH", "MY", "ID", "VN", "TH", "MN"):
    COUNTRY_TO_REGION[_code] = "asia"

ALLOWED_COUNTRIES = frozenset(COUNTRY_TO_REGION)
REGIONS = ("ru", "eu", "us", "asia")

# Порты, на которых MTProto не живёт: системные службы, БД, веб-панели, игры.
SUSPICIOUS_PORTS = frozenset({
    21, 22, 23, 25, 53, 110, 111, 135, 139, 143, 161, 162,
    389, 445, 465, 514, 587, 631, 993, 995,
    1433, 1521, 2049, 3306, 5432, 5900, 6379, 9200, 11211, 27017,
    80, 1080, 3389, 8009, 8080, 8443, 25565,
})


def region_from_domain(domain: str | None) -> str | None:
    """Регион по домену-маске fake-TLS. None, если домена нет."""
    if not domain:
        return None
    low = domain.lower()
    if any(m in low for m in RU_DOMAINS):
        return "ru"
    if any(m in low for m in US_DOMAINS):
        return "us"
    if any(m in low for m in ASIA_DOMAINS):
        return "asia"
    return "eu"


def region_from_country(country: str | None) -> str | None:
    if not country:
        return None
    return COUNTRY_TO_REGION.get(country.upper())


def is_blocked_domain(domain: str | None) -> bool:
    if not domain:
        return False
    low = domain.lower()
    return any(b in low for b in BLOCKED_DOMAINS)


@dataclass(frozen=True, slots=True)
class Proxy:
    """Кандидат до проверки. Ключ дедупликации и seen-кэша: kind+host+port+secret/логин."""

    kind: str                      # "mtproto" | "socks5"
    host: str
    port: int
    secret: str | None = None      # только mtproto, hex
    username: str | None = None    # только socks5
    password: str | None = None

    @property
    def key(self) -> tuple[str, str, int, str]:
        if self.kind == "mtproto":
            return (self.kind, self.host, self.port, (self.secret or "").lower())
        return (self.kind, self.host, self.port, f"{self.username or ''}:{self.password or ''}")

    @property
    def link(self) -> str:
        if self.kind == "mtproto":
            return f"tg://proxy?server={self.host}&port={self.port}&secret={self.secret}"
        base = f"tg://socks?server={self.host}&port={self.port}"
        if self.username:
            base += f"&user={quote(self.username, safe='')}"
        if self.password:
            base += f"&pass={quote(self.password, safe='')}"
        return base

    @property
    def tme_link(self) -> str:
        return self.link.replace("tg://proxy?", "https://t.me/proxy?").replace(
            "tg://socks?", "https://t.me/socks?"
        )


@dataclass(slots=True)
class Result:
    """Прокси, прошедший проверку."""

    proxy: Proxy
    ping: float                    # секунды, время установки TCP-соединения
    method: str                    # чем именно подтверждён
    region: str
    domain: str = ""               # домен-маска fake-TLS
    country: str | None = None
    probe_resistant: bool = False  # проксирует чужой трафик на домен-маску

    def as_dict(self) -> dict[str, Any]:
        p = self.proxy
        return {
            "type": p.kind,
            "host": p.host,
            "port": p.port,
            "secret": p.secret,
            "link": p.link,
            "ping": self.ping,
            "region": self.region,
            "domain": self.domain,
            "country": self.country,
            "method": self.method,
            "probe_resistant": self.probe_resistant,
        }


def sort_results(results: Iterable[Result]) -> list[Result]:
    """Сначала probe-resistant MTProto, затем остальной MTProto, затем SOCKS5. Внутри по пингу."""

    def rank(r: Result) -> tuple[int, float]:
        if r.proxy.kind == "mtproto":
            return (0 if r.probe_resistant else 1, r.ping)
        return (2, r.ping)

    return sorted(results, key=rank)
