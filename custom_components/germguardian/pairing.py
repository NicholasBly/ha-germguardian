"""Registration: obtain the local key from the unit + Aplix's IoTS server.

Reconstructed from the official app's code (see APZ-451-protocol.md section 14).
Request formats were checked against a capture of the real app (tests/test_pairing.py).
Before touching Bluetooth the app asks the server about the unit (/setup validateDevices);
the answer includes the unit's protocol number, which we use too.
Sequence, with the LINK button held:
  1. f000 <- protocol number
  2. default-key challenge/response, AES done by the server (/imper)
  3. server's registry-mode blob -> f010            (/setup getRegistryModeData)
  4. read the key slot from f011, server decrypts   (/setup decryptLocalKey)
  5. if the slot is empty: server issues a key blob -> f011, read back, decrypt
     (/setup generateLocalKey)
"""
from __future__ import annotations

import asyncio
import base64
import http.client
import json
import logging
import os
import re
import ssl
from typing import Any, Awaitable, Callable, NamedTuple

from .client import (
    GuardianError, U_F000, U_F004, U_F005, U_F012, SFX,
)

_LOGGER = logging.getLogger(__name__)

U_F010 = f"0000f010{SFX}"
U_F011 = f"0000f011{SFX}"

HOST = "a.iots.net"
SETUP_VERSION = "20140716"      # registration calls (getRegistryModeData, ...)
VALIDATE_VERSION = "20150818"   # validateDevices
IMPER_VERSION = "20141224"
# The server's request format carries these descriptive fields. The values are copied from
# a capture of the official app: they are part of the format, not a claim about who is
# calling. The HTTP User-Agent below, in contrast, honestly names this integration.
CENTRAL = "i:iPhone18,1"
CLIENT_INFO = {"model": CENTRAL, "osVersion": "27.2", "sdkVersion": "i:1.6.4."}
DEVICE_TYPES = ("93240", "82567")   # purifier, gateway: what the app asks about
USER_AGENT = "ha-germguardian (+https://github.com/NicholasBly/ha-germguardian)"
BLOCK = 16
MAX_BLOCKS = 15


class PairError(GuardianError):
    """Pairing failed."""


class Http:
    """Blocking HTTPS client with a connection that can be opened early.

    The unit drops an unauthenticated link after ~5 s, so the TLS session is
    established before Bluetooth connects.
    """

    def __init__(self, host: str = HOST, timeout: float = 10.0) -> None:
        self.host, self.timeout = host, timeout
        self._conn: http.client.HTTPSConnection | None = None
        self.last_headers: dict[str, str] = {}

    def warm(self) -> None:
        self._conn = http.client.HTTPSConnection(
            self.host, timeout=self.timeout, context=ssl.create_default_context()
        )
        self._conn.connect()

    @staticmethod
    def encode(obj: dict) -> bytes:
        return json.dumps(obj, separators=(",", ":")).encode()   # compact, like the app

    @staticmethod
    def headers() -> dict[str, str]:
        return {
            "Content-Type": "application/json",
            "Accept": "*/*",
            "Accept-Language": "en-us",
            "User-Agent": USER_AGENT,
        }

    def post_json(self, path: str, obj: dict) -> tuple[int, bytes]:
        body = self.encode(obj)
        for attempt in (0, 1):
            try:
                if self._conn is None:
                    self.warm()
                self._conn.request("POST", path, body, self.headers())
                r = self._conn.getresponse()
                self.last_headers = dict(r.getheaders())
                return r.status, r.read()
            except (OSError, http.client.HTTPException) as err:
                self._conn = None
                if attempt:
                    raise PairError(f"cannot reach {self.host}: {err}") from err
        raise AssertionError

    def close(self) -> None:
        if self._conn:
            self._conn.close()


def _plain(master_uuid: str) -> str:
    return master_uuid.replace("-", "")


def body_get_challenge(master_uuid: str, device_challenge: bytes) -> dict:
    return {
        "deviceChallenge": device_challenge.hex(), "masterUUID": _plain(master_uuid).lower(),
        "clientInformation": CLIENT_INFO, "request": "getChallenge", "version": IMPER_VERSION,
    }


def body_verify(master_uuid: str, server_challenge: bytes, device_response: bytes) -> dict:
    return {
        "clientInformation": CLIENT_INFO, "masterUUID": _plain(master_uuid).lower(),
        "deviceResponse": device_response.hex(), "serverChallenge": server_challenge.hex(),
        "request": "verifyResponse", "version": IMPER_VERSION,
    }


def body_validate(master_uuid: str) -> dict:
    return {
        "validateOption": {"types": list(DEVICE_TYPES)}, "clientInformation": CLIENT_INFO,
        "devices": [{"masterUUID": _plain(master_uuid).lower()}],
        "central": CENTRAL, "request": "validateDevices", "version": VALIDATE_VERSION,
    }


def body_setup(request: str, master_uuid: str, *, central: bool = False, **extra: Any) -> dict:
    """Registration calls on /setup. Not captured yet: layout follows the other /setup calls."""
    o: dict[str, Any] = {"clientInformation": CLIENT_INFO, "masterUUID": _plain(master_uuid).upper()}
    if central:
        o["central"] = CENTRAL
    o.update(extra)
    o["request"], o["version"] = request, SETUP_VERSION
    return o


_KEEP_HEADERS = ("server", "via", "x-cache", "content-type", "x-amzn-requestid", "x-amz-cf-id", "cf-ray")


def _server_error(path: str, status: int, body: bytes, headers: dict | None) -> PairError:
    """A readable error that shows who answered (a front server vs. the app's own service)."""
    text = re.sub(r"<[^>]+>", " ", body[:600].decode("utf-8", "replace"))
    text = " ".join(text.split())[:120]
    keep = ", ".join(f"{k}: {v}" for k, v in (headers or {}).items() if k.lower() in _KEEP_HEADERS)
    return PairError(f"server said HTTP {status} for {path}: {text}" + (f" [{keep}]" if keep else ""))


async def _post(http: Any, path: str, obj: dict) -> bytes:
    st, body = await asyncio.to_thread(http.post_json, path, obj)
    if st != 200:
        raise _server_error(path, st, body, getattr(http, "last_headers", None))
    return body


class Validated(NamedTuple):
    protocol: int | None
    types: list
    function_number: int | None


async def validate(http: Any, master_uuid: str) -> Validated:
    """What the app asks first: does the server know this unit, and what protocol does it speak?"""
    body = await _post(http, "/setup", body_validate(master_uuid))
    try:
        results = json.loads(body)["results"]
        mine = next(r for r in results if r["masterUUID"].lower() == _plain(master_uuid).lower())
    except (ValueError, KeyError, TypeError, StopIteration) as err:
        raise PairError(f"unexpected server reply: {body[:120]!r}") from err
    if mine.get("result") != "OK":
        raise PairError(f"the server does not recognise this unit ({mine.get('result')})")
    proto = mine.get("protocolNumber")
    return Validated(
        int(proto) if proto is not None else None,
        list(mine.get("types") or []),
        mine.get("functionNumber"),
    )


async def carousel_write(client: Any, uuid: str, data: bytes) -> None:
    if len(data) > BLOCK * MAX_BLOCKS or not data:
        raise PairError(f"blob of {len(data)} bytes does not fit a carousel")
    n = -(-len(data) // BLOCK)
    for i in range(1, n + 1):
        hdr = i | (0x80 if i == n else 0)
        await client.write_gatt_char(
            uuid, bytes([hdr]) + data[(i - 1) * BLOCK:i * BLOCK], response=True
        )


async def carousel_read(client: Any, uuid: str) -> bytes:
    out, expect, started, tries = b"", 1, False, 15
    for _ in range(40):
        pkt = bytes(await client.read_gatt_char(uuid))
        if not pkt:
            continue
        seq, last = pkt[0] & 0x0F, bool(pkt[0] & 0x80)
        if not started and seq != 1:
            tries -= 1
            if tries <= 0:
                raise PairError("could not find the start of the key data")
            continue
        if seq != expect:
            raise PairError("key data packet lost")
        started = True
        out += pkt[1:1 + BLOCK]
        if last:
            return out
        expect += 1
    raise PairError("end of key data not found")


Progress = Callable[[str], None]


async def pair(
    client: Any,
    master_uuid: str,
    http: Any,
    protocol_number: int,
    key_id: int = 1,
    progress: Progress | None = None,
) -> bytes:
    """Run registration on a connected `client`; returns the 16-byte key."""
    say = progress or (lambda _m: None)

    async def post(path: str, obj: dict) -> tuple[int, bytes]:
        return 200, await _post(http, path, obj)

    def jload(body: bytes) -> dict:
        try:
            return json.loads(body)
        except ValueError as err:
            raise PairError(f"unexpected server reply: {body[:120]!r}") from err

    # 1. protocol number
    await client.write_gatt_char(U_F000, protocol_number.to_bytes(4, "little"), response=False)

    # 2. default-key CRAM via the server
    say("Authenticating with the factory key")
    d_chal = bytes(await client.read_gatt_char(U_F004))[:16]
    _, b = await post("/imper", body_get_challenge(master_uuid, d_chal))
    j = jload(b)
    try:
        s_resp, s_chal = bytes.fromhex(j["serverResponse"]), bytes.fromhex(j["serverChallenge"])
    except (KeyError, ValueError) as err:
        raise PairError(f"bad getChallenge reply: {b[:120]!r}") from err
    await client.write_gatt_char(U_F005, s_resp, response=True)
    await client.write_gatt_char(U_F004, s_chal, response=True)
    d_resp = bytes(await client.read_gatt_char(U_F005))[:16]
    _, b = await post("/imper", body_verify(master_uuid, s_chal, d_resp))
    if jload(b).get("result") != "OK":
        raise PairError("the server rejected the unit's answer (wrong masterUuid?)")

    # 3. registry mode (the app retries up to 6 times, 500 ms apart)
    say("Entering registry mode - keep holding LINK")
    last: Exception | None = None
    for _ in range(6):
        try:
            _, blob = await post(
                "/setup", body_setup("getRegistryModeData", master_uuid, central=True)
            )
            await carousel_write(client, U_F010, blob)
            last = None
            break
        except Exception as err:  # noqa: BLE001
            last = err
            await asyncio.sleep(0.5)
    if last is not None:
        raise PairError(f"unit refused registry mode (is LINK held?): {last}") from last

    sel = key_id.to_bytes(2, "big")

    async def read_slot() -> bytes | None:
        await client.write_gatt_char(U_F012, sel, response=True)
        blob = await carousel_read(client, U_F011)
        _, b = await post("/setup", body_setup(
            "decryptLocalKey", master_uuid, data=base64.b64encode(blob).decode()
        ))
        j = jload(b)
        if int(j.get("keyId", 0)) == 0:
            return None
        if int(j["keyId"]) != key_id:
            raise PairError(f"server returned key id {j['keyId']}, wanted {key_id}")
        key = bytes.fromhex(j["key"])
        if len(key) != 16:
            raise PairError("server returned a key of the wrong length")
        return key

    # 4. existing key?
    say("Reading the key slot")
    key = await read_slot()
    if key is not None:
        return key

    # 5. empty slot: have the server issue one
    say("Creating a new key")
    await client.write_gatt_char(U_F012, sel, response=True)
    _, blob = await post(
        "/setup", body_setup("generateLocalKey", master_uuid, central=True, keyId=key_id)
    )
    await carousel_write(client, U_F011, blob)
    key = await read_slot()
    if key is None:
        raise PairError("the unit did not accept the new key")
    return key


class PairResult(NamedTuple):
    key: bytes
    protocol: int


async def pair_over_ble(
    ble_device: Any, master_uuid: str, protocol_number: int, progress: Progress | None = None,
) -> PairResult:
    """Ask the server about the unit, connect, register, disconnect.

    Used by the CLI and config flow. The protocol number the server reports for the
    unit wins over `protocol_number`; the one actually used is returned with the key.
    """
    from bleak_retry_connector import BleakClientWithServiceCache, establish_connection

    http = Http()
    try:
        await asyncio.to_thread(http.warm)
    except OSError as err:
        raise PairError(f"cannot reach {HOST}: {err}") from err
    try:
        if progress:
            progress("Asking Aplix's server about this unit")
        info = await validate(http, master_uuid)
        if info.protocol is not None:
            protocol_number = info.protocol
    except BaseException:
        http.close()
        raise
    try:
        if progress:
            progress("Connecting to the purifier")
        client = await establish_connection(
            BleakClientWithServiceCache, ble_device, ble_device.address, max_attempts=3
        )
    except Exception as err:  # noqa: BLE001
        http.close()
        raise PairError(f"cannot connect: {err}") from err
    try:
        key = await pair(client, master_uuid, http, protocol_number, progress=progress)
        return PairResult(key, protocol_number)
    finally:
        http.close()
        try:
            await client.disconnect()
        except Exception:  # noqa: BLE001
            pass
