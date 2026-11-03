"""Pure-Python APZ-451 wire protocol (no Home Assistant, no Bluetooth).

Layers, outermost last:  ASPE message -> ZECommand -> ZEDataEncoder
(AES-128-CTR + CRC16) -> 17-byte DataBlock PDUs -> GATT writes.
See APZ-451-protocol.md in the GermGuardianBLE project for the derivation.
"""
from __future__ import annotations

import base64
import binascii
import os
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

FUNCTION_NUMBER = 0x0001000F
MAX_PDU = 17

# ASPE message types
SET_DATA = 0x01
GET_DATA = 0x02
INPUT_REPORT = 0x04
RESPONSE = 0xEE
DATA_RESPONSE = 0xEF

# Device data types
DT_STATUS = 0x80
DT_POWER = 0x81
DT_WIND = 0x82
DT_AUTO = 0x83
DT_TIMER = 0x84
DT_UV = 0x85

TIMER_HOURS = (0, 1, 2, 4, 8)


class ProtocolError(Exception):
    """Malformed or corrupt frame."""


def parse_key(text: str) -> bytes:
    """Accept a 16-byte key as base64 (22/24 chars) or hex (32 chars)."""
    t = "".join(text.split())
    if len(t) == 32:
        try:
            k = bytes.fromhex(t)
            if len(k) == 16:
                return k
        except ValueError:
            pass
    try:
        k = base64.b64decode(t + "=" * (-len(t) % 4), validate=True)
    except (binascii.Error, ValueError) as err:
        raise ValueError("not valid base64 or hex") from err
    if len(k) != 16:
        raise ValueError("key must be 16 bytes")
    return k


def crc16(data: bytes) -> int:
    """Reflected CRC-16-CCITT, poly 0x8408, init 0xFFFF, no final xor."""
    crc = 0xFFFF
    for b in data:
        for _ in range(8):
            x = (b ^ crc) & 1
            crc >>= 1
            if x:
                crc ^= 0x8408
            b >>= 1
    return crc & 0xFFFF


class Cipher16:
    """Single-block AES-128-ECB helper."""

    def __init__(self, key: bytes) -> None:
        if len(key) != 16:
            raise ValueError("key must be 16 bytes")
        self._key = key

    def block(self, data: bytes) -> bytes:
        enc = Cipher(algorithms.AES(self._key), modes.ECB()).encryptor()
        return enc.update(data) + enc.finalize()


def _ctr_block(nonce: bytes, i: int) -> bytes:
    b = bytearray(nonce)
    last = nonce[15]
    if last + i > 0xFF:
        b[14] |= 0x01  # an OR, not a carry: matches the stock firmware
    b[15] = (last + i) & 0xFF
    return bytes(b)


def _xor_body(c: Cipher16, nonce: bytes, body: bytes) -> bytes:
    out = bytearray(body)
    for i in range(len(body) // 16):
        ks = c.block(_ctr_block(nonce, i))
        for j in range(16):
            out[i * 16 + j] ^= ks[j]
    return bytes(out)


def encode_data(plain: bytes, c: Cipher16, nonce: bytes | None = None) -> bytes:
    n = len(plain)
    body_len = n + 2
    total = n + 0x14
    total += (16 - (total & 0xF)) & 0xF
    nonce = nonce if nonce is not None else os.urandom(16)
    body = bytearray(total - 16)
    body[0:2] = body_len.to_bytes(2, "big")
    body[2:2 + n] = plain
    body[body_len:body_len + 2] = crc16(bytes(body[:body_len])).to_bytes(2, "big")
    return nonce + _xor_body(c, nonce, bytes(body))


def decode_data(enc: bytes, c: Cipher16) -> bytes:
    if len(enc) < 32 or (len(enc) - 16) % 16:
        raise ProtocolError("bad length")
    body = _xor_body(c, enc[:16], enc[16:])
    body_len = int.from_bytes(body[0:2], "big")
    if body_len < 2 or body_len + 2 > len(body):
        raise ProtocolError("bad body length")
    got = int.from_bytes(body[body_len:body_len + 2], "big")
    if got != crc16(body[:body_len]):
        raise ProtocolError("CRC mismatch")
    return body[2:body_len]


def aspe_build(msg_type: int, payload: bytes = b"") -> bytes:
    d = bytes([0, msg_type]) + payload
    d = bytes([len(d) + 1]) + d
    return d + bytes([sum(d) & 0xFF])


def aspe_blocks(entries: list[tuple[int, bytes]]) -> bytes:
    out = b""
    for t, pl in entries:
        b = bytes([t]) + pl
        out += bytes([len(b)]) + b
    return out


def aspe_parse(raw: bytes) -> tuple[int, bytes]:
    d = bytes(raw)
    if d and d[0] == 0xFF:
        d = d[5:]
    if len(d) < 4:
        raise ProtocolError("short packet")
    ln = d[0]
    if len(d) <= ln:
        raise ProtocolError("short packet")
    pkt = d[:ln + 1]
    if sum(pkt[:-1]) & 0xFF != pkt[-1]:
        raise ProtocolError("bad checksum")
    return pkt[2], pkt[3:ln]


def report_blocks(payload: bytes) -> list[tuple[int, bytes]]:
    out, i = [], 0
    while i < len(payload):
        n = payload[i]
        i += 1
        if not n:
            break
        if i + n <= len(payload):
            out.append((payload[i], payload[i + 1:i + n]))
        i += n
    return out


def ze_command(payload: bytes, counter: int, to_device: bool = True) -> bytes:
    return (
        bytes([(1 if to_device else 0) ^ 1])
        + (counter & 0xFFFFFFFF).to_bytes(4, "big")
        + b"\xff"
        + FUNCTION_NUMBER.to_bytes(4, "big")
        + payload
    )


def ze_parse(raw: bytes) -> tuple[int, int, bytes]:
    if len(raw) < 10:
        raise ProtocolError("short command")
    return int.from_bytes(raw[1:5], "big"), raw[5], raw[10:]


def chunk(data: bytes, seq: int) -> list[bytes]:
    """Split an encoded block into 20-byte-max PDUs (isDivide stays clear)."""
    total = max(1, -(-len(data) // MAX_PDU))
    out = []
    for i in range(total):
        part = data[i * MAX_PDU:(i + 1) * MAX_PDU]
        b0 = ((i == 0) << 7) | ((i == total - 1) << 6) | (seq & 0x0F)
        out.append(bytes([b0, i & 0x3F, len(part) & 0x1F]) + part)
    return out


class Reassembler:
    """Collects PDUs from characteristic 0010 into whole encoded blocks."""

    def __init__(self) -> None:
        self._parts: list[bytes] = []
        self._active = False
        self._last: tuple[int, int] | None = None

    def feed(self, p: bytes) -> tuple[bytes | None, bool]:
        """Return (completed block or None, is_duplicate)."""
        if len(p) < 3:
            return None, False
        tag = (p[0], p[1])
        is_start, is_end = bool(p[0] >> 7 & 1), bool(p[0] >> 6 & 1)
        if tag == self._last and not is_start:
            return None, True
        self._last = tag
        if is_start:
            self._parts, self._active = [], True
        elif not self._active:
            return None, False
        self._parts.append(p[3:3 + (p[2] & 0x1F)])
        if not is_end:
            return None, False
        self._active = False
        blk = b"".join(self._parts)
        self._parts = []
        return blk, False


@dataclass
class Status:
    power: bool
    wind: int  # 0 when off, else 1..5
    auto: bool
    timer: int
    uv: bool
    air_quality: int
    filter_hours: int
    bulb_hours: int


def _bcd(b: bytes) -> int:
    v = 0
    for x in b:
        v = v * 100 + (x >> 4) * 10 + (x & 15)
    return v


def parse_status(d: bytes) -> Status:
    if len(d) != 11:
        raise ProtocolError(f"status length {len(d)}")
    wind = 0 if d[1] == 0xFF else d[1] + 1
    return Status(
        power=d[0] == 1,
        wind=wind,
        auto=d[2] == 1,
        timer=d[3],
        uv=d[4] == 1,
        air_quality=_bcd(d[5:7]),
        filter_hours=int.from_bytes(d[7:9], "big"),
        bulb_hours=int.from_bytes(d[9:11], "big"),
    )


def build_set(
    power: bool | None = None,
    auto: bool | None = None,
    wind: int | None = None,
    timer: int | None = None,
    uv: bool | None = None,
) -> bytes:
    """SET_DATA with the firmware's ordering: power, auto, wind/timer/uv.

    Turning power off must carry nothing else (the MCU stops answering).
    """
    entries: list[tuple[int, bytes]] = []
    powered = True
    if power is not None:
        entries.append((DT_POWER, bytes([1 if power else 0])))
        powered = power
    if powered:
        if auto is not None:
            entries.append((DT_AUTO, bytes([1 if auto else 0])))
        if wind is not None:
            entries.append((DT_WIND, bytes([wind - 1])))
        if timer is not None:
            entries.append((DT_TIMER, bytes([timer])))
        if uv is not None:
            entries.append((DT_UV, bytes([1 if uv else 0])))
    if not entries:
        raise ValueError("nothing to set")
    return aspe_build(SET_DATA, aspe_blocks(entries))


GET_STATUS = aspe_build(GET_DATA, bytes([DT_STATUS]))
