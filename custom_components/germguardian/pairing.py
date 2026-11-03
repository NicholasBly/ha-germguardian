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
from typing import Any, Awaitable, Callable, Iterable, NamedTuple

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
PURIFIER_TYPE, GATEWAY_TYPE = "93240", "82567"
DEVICE_TYPES = (PURIFIER_TYPE, GATEWAY_TYPE)   # what the app asks about
USER_AGENT = "ha-germguardian (+https://github.com/NicholasBly/ha-germguardian)"
BLOCK = 16
MAX_BLOCKS = 15

# The unit only opens its key registry while LINK is held, and it can take a moment to
# notice. Ask a few times on one connection, then start over on a fresh connection.
REGISTRY_TRIES = 8              # asks per connection (the app itself asks 6 times)
REGISTRY_RETRY_DELAY = 0.6      # seconds between asks
PAIR_ROUNDS = 3                 # connections to try before giving up
PAIR_ROUND_PAUSE = 2.0          # seconds between connections


class PairError(GuardianError):
    """Pairing failed."""


class RegistryError(PairError):
    """The unit would not open (or read) its key registry - LINK is not held (yet).

    Worth another try on a fresh connection; other pairing errors are not.
    """


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


def plain_id(master_uuid: str) -> str:
    """The id as the server writes it: no dashes (case is applied where it is sent)."""
    return master_uuid.replace("-", "")


def body_get_challenge(master_uuid: str, device_challenge: bytes) -> dict:
    return {
        "deviceChallenge": device_challenge.hex(), "masterUUID": plain_id(master_uuid).lower(),
        "clientInformation": CLIENT_INFO, "request": "getChallenge", "version": IMPER_VERSION,
    }


def body_verify(master_uuid: str, server_challenge: bytes, device_response: bytes) -> dict:
    return {
        "clientInformation": CLIENT_INFO, "masterUUID": plain_id(master_uuid).lower(),
        "deviceResponse": device_response.hex(), "serverChallenge": server_challenge.hex(),
        "request": "verifyResponse", "version": IMPER_VERSION,
    }


def body_validate(master_uuids: "str | Iterable[str]") -> dict:
    ids = [master_uuids] if isinstance(master_uuids, str) else list(master_uuids)
    return {
        "validateOption": {"types": list(DEVICE_TYPES)}, "clientInformation": CLIENT_INFO,
        "devices": [{"masterUUID": plain_id(m).lower()} for m in ids],
        "central": CENTRAL, "request": "validateDevices", "version": VALIDATE_VERSION,
    }


def body_setup(request: str, master_uuid: str, *, central: bool = False, **extra: Any) -> dict:
    """Registration calls on /setup. Not captured yet: layout follows the other /setup calls."""
    o: dict[str, Any] = {"clientInformation": CLIENT_INFO, "masterUUID": plain_id(master_uuid).upper()}
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

    @property
    def is_purifier(self) -> bool:
        return PURIFIER_TYPE in self.types


def _results(body: bytes) -> list[dict]:
    try:
        results = json.loads(body)["results"]
        return [r for r in results if isinstance(r, dict)]
    except (ValueError, KeyError, TypeError) as err:
        raise PairError(f"unexpected server reply: {body[:120]!r}") from err


def _validated(r: dict) -> Validated:
    proto = r.get("protocolNumber")
    return Validated(
        int(proto) if proto is not None else None,
        list(r.get("types") or []),
        r.get("functionNumber"),
    )


async def validate_many(http: Any, master_uuids: Iterable[str]) -> dict[str, Validated]:
    """Ask the server about several units at once (as the app does).

    Returns {plain lowercase id: Validated} for the units it knows; unknown ones are left out.
    """
    body = await _post(http, "/setup", body_validate(master_uuids))
    return {
        r["masterUUID"].lower(): _validated(r)
        for r in _results(body) if r.get("result") == "OK" and "masterUUID" in r
    }


async def validate(http: Any, master_uuid: str) -> Validated:
    """What the app asks first: does the server know this unit, and what protocol does it speak?"""
    body = await _post(http, "/setup", body_validate(master_uuid))
    want = plain_id(master_uuid).lower()
    mine = next((r for r in _results(body) if str(r.get("masterUUID", "")).lower() == want), None)
    if mine is None:
        raise PairError(f"unexpected server reply: {body[:120]!r}")
    if mine.get("result") != "OK":
        raise PairError(f"the server does not recognise this unit ({mine.get('result')})")
    return _validated(mine)


def ensure_purifier(info: Validated) -> None:
    """The integration only drives purifiers; refuse gateways and anything else."""
    if not info.is_purifier:
        if GATEWAY_TYPE in info.types:
            raise PairError("the server says this unit is a gateway, not a purifier - pick the other unit")
        kind = ", ".join(info.types) or "unknown"
        raise PairError(f"the server says this unit is not a purifier (type {kind}) - pick the purifier instead")


def _write_mode(client: Any, uuid: str) -> bool | None:
    """True = Write Request, False = Write Command, None = the table does not say."""
    try:
        props = set(client.services.get_characteristic(uuid).properties)
    except Exception:  # noqa: BLE001 - no table (or no such characteristic)
        return None
    if "write" in props:
        return True
    if "write-without-response" in props:
        return False
    return None


async def write_adaptive(client: Any, uuid: str, data: bytes, mode: bool | None = None) -> bool:
    """Write the way the characteristic's property table says (Request if it is unclear).

    Windows quietly adapts a Write Request to what a characteristic supports; Linux (BlueZ)
    sends exactly what was asked. Returns the mode used (reuse it for the next block).

    A refused write is NOT retried the other way: a Write Command is never answered, so it
    can never be refused, and 'succeeding' with one only hides the unit's real answer.
    """
    if mode is None:
        mode = _write_mode(client, uuid)
    if mode is None:
        mode = True
    await client.write_gatt_char(uuid, data, response=mode)
    return mode


def gatt_summary(client: Any, uuids: Iterable[str]) -> str:
    """'f010:write-without-response f004:read/write ...' for the log."""
    try:
        return " ".join(
            f"{u[4:8]}:{'/'.join(client.services.get_characteristic(u).properties)}" for u in uuids
        )
    except Exception as err:  # noqa: BLE001
        return f"(unavailable: {err})"


async def carousel_write(client: Any, uuid: str, data: bytes) -> None:
    if len(data) > BLOCK * MAX_BLOCKS or not data:
        raise PairError(f"blob of {len(data)} bytes does not fit a carousel")
    n = -(-len(data) // BLOCK)
    mode: bool | None = None
    for i in range(1, n + 1):
        hdr = i | (0x80 if i == n else 0)
        mode = await write_adaptive(client, uuid, bytes([hdr]) + data[(i - 1) * BLOCK:i * BLOCK], mode)


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
    say("Characteristics: " + gatt_summary(client, [U_F000, U_F004, U_F005, U_F010, U_F011, U_F012]))
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

    # 3. registry mode. The unit answers 'Write Not Permitted' until LINK is held and noticed,
    #    so ask again a few times (the app asks 6 times, 500 ms apart).
    say("Entering registry mode - keep holding LINK")
    last: Exception | None = None
    for attempt in range(REGISTRY_TRIES):
        # A server problem is not the unit's fault: let it through as an ordinary error.
        _, blob = await post(
            "/setup", body_setup("getRegistryModeData", master_uuid, central=True)
        )
        try:
            await carousel_write(client, U_F010, blob)
        except PairError:
            raise
        except Exception as err:  # noqa: BLE001 - the unit's answer (or a lost link)
            last = err
            _LOGGER.debug("pairing: registry mode try %d refused: %s", attempt + 1, err)
            await asyncio.sleep(REGISTRY_RETRY_DELAY)
            continue
        last = None
        break
    if last is not None:
        raise RegistryError(f"unit refused registry mode (is LINK held?): {last}") from last

    sel = key_id.to_bytes(2, "big")

    async def read_slot() -> bytes | None:
        try:
            await write_adaptive(client, U_F012, sel)
            blob = await carousel_read(client, U_F011)
        except PairError:
            raise
        except Exception as err:  # noqa: BLE001 - the unit refuses this until registry mode is open
            raise RegistryError(
                f"cannot read the key slot (registry mode is not open - is LINK held?): {err}"
            ) from err
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
    await write_adaptive(client, U_F012, sel)
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

    If the unit will not open its key registry (LINK not held yet), it starts over on a
    fresh connection, up to PAIR_ROUNDS times. Every failure leaves as a PairError.
    """
    from bleak_retry_connector import BleakClientWithServiceCache, establish_connection

    say = progress or (lambda _m: None)
    http = Http()
    try:
        try:
            await asyncio.to_thread(http.warm)
        except OSError as err:
            raise PairError(f"cannot reach {HOST}: {err}") from err
        say("Asking Aplix's server about this unit")
        info = await validate(http, master_uuid)
        ensure_purifier(info)
        if info.protocol is not None:
            protocol_number = info.protocol
        for rnd in range(1, PAIR_ROUNDS + 1):
            say(
                "Connecting to the purifier" if rnd == 1 else
                f"Connecting again (attempt {rnd} of {PAIR_ROUNDS}) - keep holding LINK"
            )
            try:
                client = await establish_connection(
                    BleakClientWithServiceCache, ble_device, ble_device.address, max_attempts=3
                )
            except Exception as err:  # noqa: BLE001
                raise PairError(f"cannot connect: {err}") from err
            try:
                key = await pair(client, master_uuid, http, protocol_number, progress=progress)
                return PairResult(key, protocol_number)
            except RegistryError as err:
                if rnd == PAIR_ROUNDS:
                    raise
                say(f"The purifier is not ready yet: {err}")
            except GuardianError:
                raise
            except Exception as err:  # noqa: BLE001 - never leak a raw library error
                raise PairError(f"unexpected {type(err).__name__} while pairing: {err}") from err
            finally:
                try:
                    await client.disconnect()
                except Exception:  # noqa: BLE001
                    pass
            await asyncio.sleep(PAIR_ROUND_PAUSE)
        raise AssertionError("unreachable")   # the last round returns or raises
    finally:
        http.close()
