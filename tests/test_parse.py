"""Тесты разбора и построения хендшейков. Запуск: python -m unittest discover tests"""

import hashlib
import hmac
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from collector.cache import SeenCache  # noqa: E402
from collector.model import Proxy, region_from_domain  # noqa: E402
from collector.parse import (  # noqa: E402
    decode_faketls_domain,
    inner_secret,
    normalize_secret,
    parse_text,
)
from collector.probe import DIGEST_LEN, DIGEST_POS, build_client_hello  # noqa: E402


class TestSecret(unittest.TestCase):
    def test_faketls_domain_skips_secret_bytes(self):
        # ee + 32 hex секрета + hex("www.google.com")
        secret = "ee7f568e2c2b75b68b3075d35008aa37357777772e676f6f676c652e636f6d"
        self.assertEqual(decode_faketls_domain(secret), "www.google.com")

    def test_faketls_domain_cyrillic_free(self):
        self.assertEqual(
            decode_faketls_domain("ee426b729ff683efc4a976f79d276aa413647a656e2e7275"), "dzen.ru")

    def test_faketls_domain_tolerates_stray_byte(self):
        # Встречается в реальных списках: перед доменом лежит служебный \xdd.
        secret = "eeeeb30662ee79541fb143515ad872d2e9dd7777772e636c6f7564666c6172652e636f6d"
        self.assertEqual(decode_faketls_domain(secret), "www.cloudflare.com")

    def test_plain_secret_has_no_domain(self):
        self.assertIsNone(decode_faketls_domain("ddd77ecc3d0cc0bbed1809bd5ae989e197"))
        self.assertIsNone(decode_faketls_domain(None))

    def test_inner_secret_is_16_bytes(self):
        for secret in (
            "ee7f568e2c2b75b68b3075d35008aa37357777772e676f6f676c652e636f6d",
            "dd7f568e2c2b75b68b3075d35008aa3735",
            "7f568e2c2b75b68b3075d35008aa3735",
        ):
            self.assertEqual(len(bytes.fromhex(inner_secret(secret))), 16, secret)

    def test_normalize_secret(self):
        import base64

        raw = bytes(range(16))
        b64 = base64.urlsafe_b64encode(raw).decode().rstrip("=")
        self.assertEqual(normalize_secret(b64), raw.hex())
        self.assertEqual(normalize_secret("7F568E2C" * 4), "7f568e2c" * 4)
        self.assertIsNone(normalize_secret("не секрет"))


class TestParse(unittest.TestCase):
    def test_tg_proxy_link(self):
        found = parse_text(
            "tg://proxy?server=1.2.3.4&port=443&secret=7f568e2c2b75b68b3075d35008aa3735")
        self.assertEqual(len(found), 1)
        proxy = next(iter(found))
        self.assertEqual((proxy.kind, proxy.host, proxy.port), ("mtproto", "1.2.3.4", 443))

    def test_socks_credentials_survive_into_link(self):
        found = parse_text("socks5://bob:s3cr3t@5.6.7.8:1080")
        proxy = next(iter(found))
        self.assertEqual((proxy.username, proxy.password), ("bob", "s3cr3t"))
        self.assertIn("user=bob", proxy.link)
        self.assertIn("pass=s3cr3t", proxy.link)

    def test_bare_hostport_only_for_socks_sources(self):
        self.assertEqual(len(parse_text("9.9.9.9:1080\n")), 0)
        self.assertEqual(len(parse_text("9.9.9.9:1080\n", expect="socks5")), 1)

    def test_json_and_triplet(self):
        found = parse_text('[{"host": "1.1.1.1", "port": 443, "secret": "'
                           + "7f" * 16 + '"}]')
        self.assertEqual(len(found), 1)
        found = parse_text("2.2.2.2:8443:" + "ab" * 16)
        self.assertEqual(len(found), 1)

    def test_invalid_port_rejected(self):
        self.assertEqual(len(parse_text("tg://proxy?server=1.2.3.4&port=99999&secret="
                                        + "7f" * 16)), 0)

    def test_duplicates_collapse(self):
        line = "tg://proxy?server=1.2.3.4&port=443&secret=" + "7f" * 16
        self.assertEqual(len(parse_text(line + "\n" + line.upper().replace("TG://", "tg://"))), 1)


class TestRegion(unittest.TestCase):
    def test_masks(self):
        self.assertEqual(region_from_domain("dzen.ru"), "ru")
        self.assertEqual(region_from_domain("cloudflare.com"), "us")
        self.assertEqual(region_from_domain("www.rakuten.jp"), "asia")
        self.assertEqual(region_from_domain("example.de"), "eu")
        self.assertIsNone(region_from_domain(""))


class TestClientHello(unittest.TestCase):
    def test_structure_and_hmac(self):
        secret = bytes(range(16))
        hello = build_client_hello(secret, "www.google.com")
        self.assertEqual(len(hello), 517)
        self.assertEqual(hello[:3], b"\x16\x03\x01")
        self.assertEqual(int.from_bytes(hello[3:5], "big"), 512)

        # Сервер обнуляет digest и проверяет HMAC: повторяем его арифметику.
        digest = hello[DIGEST_POS:DIGEST_POS + DIGEST_LEN]
        zeroed = hello[:DIGEST_POS] + b"\x00" * DIGEST_LEN + hello[DIGEST_POS + DIGEST_LEN:]
        computed = hmac.new(secret, zeroed, hashlib.sha256).digest()
        xored = bytes(a ^ b for a, b in zip(digest, computed))
        self.assertEqual(xored[:28], b"\x00" * 28, "первые 28 байт обязаны занулиться")


class TestSeenCache(unittest.TestCase):
    def test_ttl_expires_and_timestamp_is_not_refreshed(self):
        import json
        import tempfile
        from datetime import datetime, timedelta, timezone

        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / "seen.json")
            old = (datetime.now(timezone.utc) - timedelta(hours=5)).isoformat()
            fresh_key = ["mtproto", "1.1.1.1", 443, "aa"]
            Path(path).write_text(json.dumps({"seen": [{"k": fresh_key, "ts": old}]}),
                                  encoding="utf-8")

            cache = SeenCache(path, ttl_hours=6)
            self.assertEqual(cache.load(), 1)
            cache.mark(tuple(fresh_key))  # type: ignore[arg-type]
            cache.save()

            # Время первой проверки должно сохраниться, иначе TTL никогда не наступит.
            saved = json.loads(Path(path).read_text(encoding="utf-8"))
            self.assertEqual(saved["seen"][0]["ts"], old)

            expired = SeenCache(path, ttl_hours=4)
            self.assertEqual(expired.load(), 0)

    def test_forget_removes_entry(self):
        cache = SeenCache(None)
        key = Proxy("socks5", "1.1.1.1", 1080).key
        cache.mark(key)
        self.assertIn(key, cache)
        cache.forget(key)
        self.assertNotIn(key, cache)


if __name__ == "__main__":
    unittest.main()
