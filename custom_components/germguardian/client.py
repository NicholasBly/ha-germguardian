"""BLE session for a GermGuardian / Guardian Technologies purifier.

Works with any bleak-style client object, so it can be unit-tested against a
fake device and reused by tools/gg_probe.py without Home Assistant.
"""
from __future__ import annotations

import asyncio
import logging
import os
import time
from typing import Any

from . import protocol as P

_LOGGER = logging.getLogger(__name__)

SFX = "-24f6-4000-a000-000000000000"
U_F000 = f"0000f000{SFX}"
U_F004 = f"0000f004{SFX}"
U_F005 = f"0000f005{SFX}"
U_F012 = f"0000f012{SFX}"
U_FFFE = f"0000fffe{SFX}"
U_FFFF = f"0000ffff{SFX}"
U_IN = f"00000010{SFX}"      # device -> app data chunks (notify)
U_IN_ACK = f"00000011{SFX}"  # app acks received block
U_OUT = f"00000012{SFX}"     # app -> device data chunks
U_OUT_ACK = f"00000013{SFX}"  # device acks our block (notify)

REPLY_TIMEOUT = 6.0

# A poll or command makes up to this many connect+login attempts. The purifier's Bluetooth
# link sometimes drops right after connecting; one more try usually works.
CONNECT_TRIES = 3
AUTH_TRIES = 2                  # a refused key is retried once, not hammered
CONNECT_RETRY_PAUSE = 1.5       # seconds between attempts


class GuardianError(Exception):
    """Base error."""


class AuthError(GuardianError):
    """The device refused the key (wrong key, or key slot empty)."""


class CommError(GuardianError):
    """Link or protocol failure."""


class UnlockError(CommError):
    """The unit refused the purifier handshake (usually a different Aplix product)."""


class LinkLostError(CommError):
    """The Bluetooth link dropped before or during login (not a refused key)."""


def _connected(client: Any) -> bool:
    """False only when the client says so (fakes without the attribute count as connected)."""
    return getattr(client, "is_connected", True) is not False


class Session:
    def __init__(self, client: Any, key: bytes, protocol_number: int) -> None:
        self._c = client
        self._cipher = P.Cipher16(key)
        self._unlock = protocol_number.to_bytes(4, "little")
        self._counter = 0
        self._chunk_seq = 1
        self._rx = P.Reassembler()
        self._msgs: asyncio.Queue[tuple[int, bytes]] = asyncio.Queue()
        self._tasks: set[asyncio.Task] = set()
        self._lock = asyncio.Lock()

    # -- link setup ---------------------------------------------------
    async def start(self) -> None:
        await self._c.start_notify(U_IN, self._on_in)
        for uuid in (U_OUT_ACK, U_FFFF):
            try:
                await self._c.start_notify(uuid, lambda *_: None)
            except Exception:  # noqa: BLE001 - optional, stock app does it
                _LOGGER.debug("notify %s not available", uuid)

    async def authenticate(self) -> None:
        """Unlock, then mutual challenge/response with the local key.

        Raises AuthError only when the unit really answered 'no'. If the Bluetooth link
        dropped (the purifier or the adapter hung up), that is a LinkLostError - the key
        may be fine.
        """
        try:
            await self._write(U_F000, self._unlock, response=False)
        except Exception as err:  # noqa: BLE001 - e.g. Bleak: 'Service Discovery has not been performed yet'
            raise self._link_error("unlock", err) from err
        if await self._auth_round():
            return
        # Stock-app fallback: mode byte, unlock, explicit key selection.
        try:
            await self._write(U_FFFE, b"\x80", response=False)
        except Exception:  # noqa: BLE001
            pass
        await self._write(U_F000, self._unlock, response=False)
        for key_id in (1, 0):
            try:
                await self._write(U_F012, key_id.to_bytes(2, "big"), response=True)
            except Exception:  # noqa: BLE001
                continue
            if await self._auth_round():
                return
        if not _connected(self._c):
            raise LinkLostError("the purifier dropped the Bluetooth link during login")
        raise AuthError("device did not accept the key")

    def _link_error(self, what: str, err: Exception) -> CommError:
        if not _connected(self._c):
            return LinkLostError(f"the purifier dropped the Bluetooth link ({what}: {err})")
        return CommError(f"{what} failed: {type(err).__name__}: {err}")

    async def _auth_round(self) -> bool:
        try:
            d_chal = bytes(await self._c.read_gatt_char(U_F004))[:16]
        except Exception as err:  # noqa: BLE001
            if not _connected(self._c):
                raise self._link_error("reading the challenge", err) from err
            raise UnlockError(f"cannot read challenge: {err}") from err
        if len(d_chal) != 16:
            return False
        try:
            await self._write(U_F005, self._cipher.block(d_chal), response=True)
        except Exception as err:  # noqa: BLE001
            if not _connected(self._c):
                raise self._link_error("answering the challenge", err) from err
            return False        # still connected: the device rejected our response
        my_chal = os.urandom(16)
        while my_chal == d_chal:
            my_chal = os.urandom(16)
        try:
            await self._write(U_F004, my_chal, response=True)
            d_resp = bytes(await self._c.read_gatt_char(U_F005))[:16]
        except Exception as err:  # noqa: BLE001
            raise self._link_error("challenge exchange", err) from err
        if d_resp != self._cipher.block(my_chal):
            return False
        self._counter = int.from_bytes(d_chal[12:16], "big")
        return True

    # -- data ---------------------------------------------------------
    async def _write(self, uuid: str, data: bytes, response: bool) -> None:
        await self._c.write_gatt_char(uuid, data, response=response)

    def _on_in(self, _char: Any, data: bytearray) -> None:
        blk, dup = self._rx.feed(bytes(data))
        if dup or blk is not None:
            self._spawn(self._ack())
        if blk is None:
            return
        try:
            _, _, payload = P.ze_parse(P.decode_data(blk, self._cipher))
            self._msgs.put_nowait(P.aspe_parse(payload))
        except P.ProtocolError as err:
            _LOGGER.debug("dropping bad frame: %s", err)

    def _spawn(self, coro: Any) -> None:
        t = asyncio.get_running_loop().create_task(coro)
        self._tasks.add(t)
        t.add_done_callback(self._tasks.discard)

    async def _ack(self) -> None:
        try:
            await self._write(U_IN_ACK, b"\x00", response=False)
        except Exception:  # noqa: BLE001
            _LOGGER.debug("rx ack failed")

    async def request(self, aspe: bytes, want: set[int]) -> tuple[int, bytes]:
        """Send one ASPE message and wait for a reply of a wanted type."""
        async with self._lock:
            while not self._msgs.empty():
                self._msgs.get_nowait()
            enc = P.encode_data(
                P.ze_command(aspe, self._counter), self._cipher
            )
            self._counter = (self._counter + 1) & 0xFFFFFFFF
            pdus = P.chunk(enc, self._chunk_seq)
            self._chunk_seq = self._chunk_seq % 15 + 1
            try:
                for p in pdus:
                    await self._write(U_OUT, p, response=False)
                    await asyncio.sleep(0.02)
                async with asyncio.timeout(REPLY_TIMEOUT):
                    while True:
                        typ, pl = await self._msgs.get()
                        if typ in want:
                            return typ, pl
            except TimeoutError as err:
                raise CommError("device did not reply") from err
            except GuardianError:
                raise
            except Exception as err:  # noqa: BLE001
                raise CommError(str(err)) from err

    async def get_status(self) -> P.Status:
        _, pl = await self.request(P.GET_STATUS, {P.INPUT_REPORT})
        for typ, data in P.report_blocks(pl):
            if typ == P.DT_STATUS:
                return P.parse_status(data)
        raise CommError("reply had no status block")

    async def set(self, **kw: Any) -> None:
        _, pl = await self.request(P.build_set(**kw), {P.DATA_RESPONSE, P.RESPONSE})
        # payload: pairs of (dataType, code) or a single code; 1 == SUCCESS
        codes = [pl[i + 1] for i in range(0, len(pl) - 1, 2)] if len(pl) > 1 else list(pl)
        if any(c != 1 for c in codes):
            raise CommError(f"device rejected the change: {pl.hex()}")


async def _open_once(ble_device: Any, key: bytes, protocol_number: int, name: str) -> tuple[Any, Session]:
    from bleak_retry_connector import BleakClientWithServiceCache, establish_connection

    try:
        client = await establish_connection(
            BleakClientWithServiceCache, ble_device, name or ble_device.address,
            max_attempts=3,
        )
    except Exception as err:  # noqa: BLE001
        raise CommError(f"cannot connect: {err}") from err
    connected_at = time.monotonic()
    sess = Session(client, key, protocol_number)
    try:
        # Log in FIRST: the unit refuses notification setup until authenticated.
        await sess.authenticate()
        try:
            await sess.start()
        except Exception as err:  # noqa: BLE001
            raise sess._link_error("starting notifications", err) from err
    except BaseException as err:     # includes cancellation: never leave the unit connected
        try:
            await client.disconnect()
        except Exception:  # noqa: BLE001
            pass
        if isinstance(err, LinkLostError):
            # How soon after connecting it dropped is the clue to why.
            raise LinkLostError(
                f"{err} [{time.monotonic() - connected_at:.1f} s after connecting]"
            ) from err
        raise
    return client, sess


async def open_session(ble_device: Any, key: bytes, protocol_number: int, name: str = "") -> tuple[Any, Session]:
    """Connect and authenticate; caller must disconnect.

    A link that drops during login is retried on a fresh connection (CONNECT_TRIES), a
    refused key once more (AUTH_TRIES). Failing to connect at all is not retried here:
    the connector has already tried several times.
    """
    attempt = 0
    while True:
        attempt += 1
        try:
            return await _open_once(ble_device, key, protocol_number, name)
        except (LinkLostError, AuthError) as err:
            limit = AUTH_TRIES if isinstance(err, AuthError) else CONNECT_TRIES
            if attempt >= limit:
                raise
            _LOGGER.debug("login attempt %d of %d failed (%s); trying again", attempt, limit, err)
            await asyncio.sleep(CONNECT_RETRY_PAUSE)
