"""Настоящая проверка прокси на уровне протокола.

Прошлая версия считала прокси рабочим, если открывался TCP-порт. Любой
веб-сервер на 443 проходил такую проверку. Здесь для каждого типа делается
реальный хендшейк:

* MTProto fake-TLS (секрет "ee..") — ClientHello с HMAC по секрету; ответ
  сервера содержит digest, который проверяется криптографически. Совпал —
  значит на том конце именно MTProto-прокси с этим секретом.
* MTProto obfuscated2 ("dd.." и обычные секреты) — 64-байтовый init-пакет и
  реальный req_pq_multi. Прокси обязан передать его в Telegram и вернуть resPQ.
* SOCKS5 — приветствие, при наличии логина авторизация по RFC 1929 и CONNECT
  на адрес Telegram.
"""

from __future__ import annotations

import errno
import hashlib
import hmac
import os
import socket
import struct
import time

from .model import Proxy
from .parse import decode_faketls_domain, inner_secret

# --- опциональная криптография для obfuscated2 -------------------------------

try:  # pragma: no cover - зависит от окружения
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    def _aes_ctr(key: bytes, iv: bytes):
        return Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor()

    HAS_AES = True
except ImportError:  # pragma: no cover
    try:
        from Crypto.Cipher import AES  # type: ignore

        class _PyCryptoCtr:
            def __init__(self, key: bytes, iv: bytes):
                self._c = AES.new(key, AES.MODE_CTR, initial_value=iv, nonce=b"")

            def update(self, data: bytes) -> bytes:
                return self._c.encrypt(data)

        def _aes_ctr(key: bytes, iv: bytes):
            return _PyCryptoCtr(key, iv)

        HAS_AES = True
    except ImportError:
        HAS_AES = False

        def _aes_ctr(key: bytes, iv: bytes):  # type: ignore
            raise RuntimeError("нет AES: установите cryptography или pycryptodome")


# Адрес Telegram DC2, через него проверяется, что SOCKS5 реально проксирует.
TELEGRAM_DC = ("149.154.167.51", 443)

PROTO_TAG_ABRIDGED = b"\xef\xef\xef\xef"
PROTO_TAG_INTERMEDIATE = b"\xee\xee\xee\xee"
PROTO_TAG_SECURE = b"\xdd\xdd\xdd\xdd"

_FORBIDDEN_STARTS = {
    b"HEAD", b"POST", b"GET ", b"OPTI", b"PUT ",
    PROTO_TAG_SECURE, PROTO_TAG_INTERMEDIATE, b"\x16\x03\x01\x02",
}

DIGEST_POS = 11
DIGEST_LEN = 32


class ProbeError(Exception):
    """Проверка не пройдена. Текст пригоден для лога."""


# Windows: 10048 порт занят, 10055 кончились буферы сокетов.
# POSIX: EADDRINUSE, ENOBUFS, EMFILE. Всё это проблемы нашей машины,
# а не прокси, поэтому такие попытки нельзя засчитывать как провал.
_LOCAL_ERRNOS = {
    errno.EADDRINUSE, errno.ENOBUFS, errno.EMFILE, errno.ENFILE,
    getattr(errno, "WSAEADDRINUSE", 10048), getattr(errno, "WSAENOBUFS", 10055),
}


def is_local_resource_error(exc: BaseException) -> bool:
    """Мы исчерпали локальные ресурсы: порты, буферы или дескрипторы."""
    if not isinstance(exc, OSError):
        return False
    codes = {exc.errno, getattr(exc, "winerror", None)}
    return bool(codes & _LOCAL_ERRNOS)


# --- низкоуровневые помощники -------------------------------------------------

def _recv_exactly(sock: socket.socket, count: int) -> bytes:
    buf = bytearray()
    while len(buf) < count:
        chunk = sock.recv(count - len(buf))
        if not chunk:
            raise ProbeError(f"соединение закрыто на {len(buf)}/{count} байт")
        buf += chunk
    return bytes(buf)


def tcp_connect(host: str, port: int, timeout: float) -> tuple[socket.socket, float]:
    """Соединение и время его установки."""
    start = time.monotonic()
    sock = socket.create_connection((host, port), timeout)
    ping = round(time.monotonic() - start, 3)
    sock.settimeout(timeout)
    return sock, ping


# --- MTProto fake-TLS ---------------------------------------------------------

def _ext(ext_type: int, payload: bytes) -> bytes:
    return struct.pack(">HH", ext_type, len(payload)) + payload


def build_client_hello(secret: bytes, domain: str) -> bytes:
    """ClientHello с HMAC-digest, как его строит настоящий Telegram-клиент."""
    session_id = os.urandom(32)
    ciphers = bytes.fromhex(
        "130113021303c02bc02fc02cc030cca9cca8c013c014009c009d002f0035000a"
    )

    try:
        sni_host = domain.encode("idna") if domain else b""
    except UnicodeError:
        sni_host = b""
    server_name = _ext(0x0000, struct.pack(">HBH", len(sni_host) + 3, 0, len(sni_host)) + sni_host)
    supported_groups = _ext(0x000A, b"\x00\x08\x00\x1d\x00\x17\x00\x18\x00\x19")
    ec_formats = _ext(0x000B, b"\x01\x00")
    sig_algs = _ext(0x000D, b"\x00\x12\x04\x03\x08\x04\x04\x01\x05\x03\x08\x05"
                            b"\x05\x01\x08\x06\x06\x01\x02\x01")
    alpn = _ext(0x0010, b"\x00\x0c\x02h2\x08http/1.1")
    session_ticket = _ext(0x0023, b"")
    supported_versions = _ext(0x002B, b"\x04\x03\x04\x03\x03")
    key_share = _ext(0x0033, b"\x00\x24\x00\x1d\x00\x20" + os.urandom(32))

    extensions = (server_name + supported_groups + ec_formats + sig_algs + alpn
                  + session_ticket + supported_versions + key_share)

    # Тело handshake должно быть ровно 508 байт: запись 512 байт, как требует сервер.
    body_target = 508
    fixed = 2 + DIGEST_LEN + 1 + len(session_id) + 2 + len(ciphers) + 2 + 2
    pad_total = body_target - fixed - len(extensions)
    if pad_total < 4:
        raise ProbeError("расширения не влезают в ClientHello")
    extensions += _ext(0x0015, b"\x00" * (pad_total - 4))

    body = (b"\x03\x03" + b"\x00" * DIGEST_LEN
            + bytes([len(session_id)]) + session_id
            + struct.pack(">H", len(ciphers)) + ciphers
            + b"\x01\x00"
            + struct.pack(">H", len(extensions)) + extensions)
    if len(body) != body_target:
        raise ProbeError(f"неверная длина ClientHello: {len(body)}")

    hello = (b"\x16\x03\x01" + struct.pack(">H", len(body) + 4)
             + b"\x01" + len(body).to_bytes(3, "big") + body)

    computed = hmac.new(secret, hello, hashlib.sha256).digest()
    stamp = int(time.time()).to_bytes(4, "little")
    digest = bytes(a ^ b for a, b in zip(computed, b"\x00" * 28 + stamp))
    return hello[:DIGEST_POS] + digest + hello[DIGEST_POS + DIGEST_LEN:]


def _read_server_hello(sock: socket.socket) -> bytes:
    head = _recv_exactly(sock, 5)
    if head[:3] != b"\x16\x03\x03":
        raise ProbeError(f"не ServerHello: {head[:3].hex()}")
    packet = head + _recv_exactly(sock, struct.unpack(">H", head[3:5])[0])

    change_cipher = _recv_exactly(sock, 6)
    if change_cipher != b"\x14\x03\x03\x00\x01\x01":
        raise ProbeError("нет ChangeCipherSpec")
    packet += change_cipher

    app_head = _recv_exactly(sock, 5)
    if app_head[:3] != b"\x17\x03\x03":
        raise ProbeError("нет ApplicationData")
    return packet + app_head + _recv_exactly(sock, struct.unpack(">H", app_head[3:5])[0])


def check_faketls(proxy: Proxy, timeout: float) -> tuple[float, str]:
    """Возвращает (ping, метод). Бросает ProbeError, если это не прокси."""
    secret = bytes.fromhex(inner_secret(proxy.secret or ""))
    domain = decode_faketls_domain(proxy.secret) or ""

    sock, ping = tcp_connect(proxy.host, proxy.port, timeout)
    try:
        hello = build_client_hello(secret, domain)
        sock.sendall(hello)
        response = _read_server_hello(sock)

        client_digest = hello[DIGEST_POS:DIGEST_POS + DIGEST_LEN]
        zeroed = response[:DIGEST_POS] + b"\x00" * DIGEST_LEN + response[DIGEST_POS + DIGEST_LEN:]
        expected = hmac.new(secret, client_digest + zeroed, hashlib.sha256).digest()
        if not hmac.compare_digest(expected, response[DIGEST_POS:DIGEST_POS + DIGEST_LEN]):
            raise ProbeError("digest не сошёлся: это не MTProto-прокси с таким секретом")
        return ping, "faketls_hmac"
    finally:
        sock.close()


# --- MTProto obfuscated2 ------------------------------------------------------

def _init_packet(secret: bytes, proto_tag: bytes, dc_id: int = 2):
    while True:
        buf = bytearray(os.urandom(64))
        if buf[0] == 0xEF or bytes(buf[:4]) in _FORBIDDEN_STARTS or buf[4:8] == b"\x00\x00\x00\x00":
            continue
        break
    buf[56:60] = proto_tag
    buf[60:62] = struct.pack("<h", dc_id)

    enc_key = hashlib.sha256(bytes(buf[8:40]) + secret).digest()
    encryptor = _aes_ctr(enc_key, bytes(buf[40:56]))

    reversed_material = bytes(buf[8:56])[::-1]
    dec_key = hashlib.sha256(reversed_material[:32] + secret).digest()
    decryptor = _aes_ctr(dec_key, reversed_material[32:48])

    encrypted = encryptor.update(bytes(buf))
    return bytes(buf[:56]) + encrypted[56:64], encryptor, decryptor


def _req_pq_frame() -> bytes:
    """Запрос req_pq_multi без auth_key в intermediate-обёртке."""
    payload = b"\xf1\x8e\x7e\xbe" + os.urandom(16)          # req_pq_multi#be7e8ef1
    msg_id = (int(time.time()) << 32) & ~3
    message = struct.pack("<qqi", 0, msg_id, len(payload)) + payload
    return struct.pack("<I", len(message)) + message


def check_obfuscated(proxy: Proxy, timeout: float, proto_tag: bytes) -> tuple[float, str]:
    if not HAS_AES:
        raise ProbeError("нет библиотеки AES, obfuscated2 не проверяется")
    secret = bytes.fromhex(inner_secret(proxy.secret or ""))

    sock, ping = tcp_connect(proxy.host, proxy.port, timeout)
    try:
        init, encryptor, decryptor = _init_packet(secret, proto_tag)
        sock.sendall(init + encryptor.update(_req_pq_frame()))

        # Ответ может прийти несколькими сегментами, добираем до заголовка resPQ.
        raw = bytearray()
        while len(raw) < 28:
            chunk = sock.recv(512 - len(raw))
            if not chunk:
                break
            raw += chunk
        if not raw:
            raise ProbeError("прокси закрыл соединение без ответа")
        plain = decryptor.update(bytes(raw))
        if len(plain) < 28:
            raise ProbeError("слишком короткий ответ")
        # intermediate: 4 байта длины, дальше сообщение с auth_key_id = 0
        if plain[4:12] != b"\x00" * 8:
            raise ProbeError("ответ не похож на MTProto")
        if plain[24:28] == b"\x63\x24\x16\x05":               # resPQ#05162463
            return ping, "mtproto_respq"
        return ping, "mtproto_reply"
    finally:
        sock.close()


# --- SOCKS5 -------------------------------------------------------------------

def check_socks5(proxy: Proxy, timeout: float, connect_test: bool = True) -> tuple[float, str]:
    sock, ping = tcp_connect(proxy.host, proxy.port, timeout)
    try:
        has_auth = bool(proxy.username)
        sock.sendall(b"\x05\x02\x00\x02" if has_auth else b"\x05\x01\x00")
        greeting = _recv_exactly(sock, 2)
        if greeting[0] != 0x05:
            raise ProbeError("не SOCKS5")

        method = greeting[1]
        if method == 0x02:
            if not has_auth:
                raise ProbeError("нужен логин, а его нет в ссылке")
            user = (proxy.username or "").encode()
            password = (proxy.password or "").encode()
            sock.sendall(b"\x01" + bytes([len(user)]) + user + bytes([len(password)]) + password)
            if _recv_exactly(sock, 2)[1] != 0x00:
                raise ProbeError("логин или пароль не подошли")
        elif method != 0x00:
            raise ProbeError(f"сервер требует метод авторизации {method:#04x}")

        if not connect_test:
            return ping, "socks5_greeting"

        host, port = TELEGRAM_DC
        sock.sendall(b"\x05\x01\x00\x01" + socket.inet_aton(host) + struct.pack(">H", port))
        reply = _recv_exactly(sock, 4)
        if reply[1] != 0x00:
            raise ProbeError(f"CONNECT отклонён, код {reply[1]}")
        # дочитываем адрес привязки, чтобы не оставлять мусор в сокете
        atyp = reply[3]
        if atyp == 0x01:
            _recv_exactly(sock, 6)
        elif atyp == 0x03:
            _recv_exactly(sock, _recv_exactly(sock, 1)[0] + 2)
        elif atyp == 0x04:
            _recv_exactly(sock, 18)
        return ping, "socks5_connect"
    finally:
        sock.close()


# --- общая точка входа --------------------------------------------------------

def probe(proxy: Proxy, timeout: float, connect_test: bool = True) -> tuple[float, str]:
    """Проверяет прокси по его типу. Бросает ProbeError или OSError при неудаче."""
    if proxy.kind == "socks5":
        return check_socks5(proxy, timeout, connect_test)

    secret = (proxy.secret or "").lower()
    if secret.startswith("ee"):
        return check_faketls(proxy, timeout)
    if secret.startswith("dd"):
        return check_obfuscated(proxy, timeout, PROTO_TAG_SECURE)

    last: Exception = ProbeError("нет подходящего режима")
    for tag in (PROTO_TAG_INTERMEDIATE, PROTO_TAG_SECURE):
        try:
            return check_obfuscated(proxy, timeout, tag)
        except (ProbeError, OSError) as exc:
            last = exc
    raise last
