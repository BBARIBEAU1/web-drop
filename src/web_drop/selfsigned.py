"""Minimal RSA key and self-signed certificate generator.

Used only when ``openssl`` is not installed. The certificate is enough for a
lab HTTPS listener; clients are expected to skip verification.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
from datetime import datetime, timedelta, timezone

_SMALL_PRIMES = (
    3,
    5,
    7,
    11,
    13,
    17,
    19,
    23,
    29,
    31,
    37,
    41,
    43,
    47,
    53,
    59,
    61,
    67,
    71,
    73,
    79,
    83,
    89,
    97,
)


def _tlv(tag: int, body: bytes) -> bytes:
    return bytes([tag]) + _length(len(body)) + body


def _length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    raw = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def _integer(value: int) -> bytes:
    if value < 0:
        raise ValueError("ASN.1 integer must be non-negative")
    if value == 0:
        body = b"\x00"
    else:
        body = value.to_bytes((value.bit_length() + 7) // 8, "big")
        if body[0] & 0x80:
            body = b"\x00" + body
    return _tlv(0x02, body)


def _oid(dotted: str) -> bytes:
    arcs = [int(part) for part in dotted.split(".")]
    body = bytearray([40 * arcs[0] + arcs[1]])
    for arc in arcs[2:]:
        body.extend(_base128(arc))
    return _tlv(0x06, bytes(body))


def _base128(value: int) -> bytes:
    chunks = [value & 0x7F]
    value >>= 7
    while value:
        chunks.append(0x80 | (value & 0x7F))
        value >>= 7
    return bytes(reversed(chunks))


def _sequence(*parts: bytes) -> bytes:
    return _tlv(0x30, b"".join(parts))


def _set(*parts: bytes) -> bytes:
    return _tlv(0x31, b"".join(parts))


def _null() -> bytes:
    return b"\x05\x00"


def _octet(payload: bytes) -> bytes:
    return _tlv(0x04, payload)


def _bit_string(payload: bytes) -> bytes:
    return _tlv(0x03, b"\x00" + payload)


def _printable(text: str) -> bytes:
    return _tlv(0x13, text.encode("ascii"))


def _utc_time(moment: datetime) -> bytes:
    return _tlv(0x17, moment.strftime("%y%m%d%H%M%SZ").encode("ascii"))


def _algorithm(oid: str) -> bytes:
    return _sequence(_oid(oid), _null())


def _name(common_name: str) -> bytes:
    return _sequence(_set(_sequence(_oid("2.5.4.3"), _printable(common_name))))


def _subject_public_key(modulus: int, exponent: int) -> bytes:
    public = _sequence(_integer(modulus), _integer(exponent))
    return _sequence(_algorithm("1.2.840.113549.1.1.1"), _bit_string(public))


def _probable_prime(candidate: int) -> bool:
    if candidate < 3 or candidate % 2 == 0:
        return False
    if any(candidate % prime == 0 for prime in _SMALL_PRIMES):
        return False
    degree = candidate - 1
    shift = 0
    while degree % 2 == 0:
        degree //= 2
        shift += 1
    for _ in range(8):
        witness = secrets.randbelow(candidate - 3) + 2
        value = pow(witness, degree, candidate)
        if value in (1, candidate - 1):
            continue
        for _ in range(shift - 1):
            value = pow(value, 2, candidate)
            if value == candidate - 1:
                break
        else:
            return False
    return True


def _prime(bits: int) -> int:
    while True:
        candidate = secrets.randbits(bits) | 1 | (1 << (bits - 1))
        if _probable_prime(candidate):
            return candidate


def _rsa_pair(bits: int) -> tuple[int, int, int, int, int]:
    exponent = 65537
    half = bits // 2
    while True:
        first = _prime(half)
        second = _prime(half)
        if first == second:
            continue
        if first < second:
            first, second = second, first
        modulus = first * second
        if modulus.bit_length() != bits:
            continue
        totient = (first - 1) * (second - 1)
        if totient % exponent == 0:
            continue
        private = pow(exponent, -1, totient)
        return modulus, exponent, private, first, second


def _pkcs1(modulus: int, exponent: int, private: int, first: int, second: int) -> bytes:
    exponent1 = private % (first - 1)
    exponent2 = private % (second - 1)
    coefficient = pow(second, -1, first)
    return _sequence(
        _integer(0),
        _integer(modulus),
        _integer(exponent),
        _integer(private),
        _integer(first),
        _integer(second),
        _integer(exponent1),
        _integer(exponent2),
        _integer(coefficient),
    )


def _pkcs8(pkcs1: bytes) -> bytes:
    return _sequence(
        _integer(0),
        _algorithm("1.2.840.113549.1.1.1"),
        _octet(pkcs1),
    )


def _sign(tbs: bytes, modulus: int, private: int) -> bytes:
    digest = hashlib.sha256(tbs).digest()
    info = _sequence(_algorithm("2.16.840.1.101.3.4.2.1"), _octet(digest))
    width = (modulus.bit_length() + 7) // 8
    padding_len = width - len(info) - 3
    if padding_len < 8:
        raise ValueError("RSA key is too small to sign a certificate")
    encoded = b"\x00\x01" + (b"\xff" * padding_len) + b"\x00" + info
    signature = pow(int.from_bytes(encoded, "big"), private, modulus)
    return _bit_string(signature.to_bytes(width, "big"))


def _certificate(
    common_name: str,
    modulus: int,
    exponent: int,
    private: int,
    days: int,
) -> bytes:
    now = datetime.now(timezone.utc)
    serial = secrets.randbelow(2**63 - 1) + 1
    body = _sequence(
        _integer(serial),
        _algorithm("1.2.840.113549.1.1.11"),
        _name(common_name),
        _sequence(_utc_time(now - timedelta(days=1)), _utc_time(now + timedelta(days=days))),
        _name(common_name),
        _subject_public_key(modulus, exponent),
    )
    return _sequence(body, _algorithm("1.2.840.113549.1.1.11"), _sign(body, modulus, private))


def pem(label: str, der: bytes) -> str:
    body = base64.encodebytes(der).decode("ascii")
    return f"-----BEGIN {label}-----\n{body}-----END {label}-----\n"


def generate_self_signed(
    common_name: str = "web-drop",
    *,
    bits: int = 2048,
    days: int = 365,
) -> tuple[str, str]:
    """Return ``(certificate_pem, private_key_pem)`` for a new RSA key."""
    if bits < 2048 or bits % 2:
        raise ValueError("bits must be an even integer >= 2048")
    modulus, exponent, private, first, second = _rsa_pair(bits)
    certificate = _certificate(common_name, modulus, exponent, private, days)
    key = _pkcs8(_pkcs1(modulus, exponent, private, first, second))
    return pem("CERTIFICATE", certificate), pem("PRIVATE KEY", key)
