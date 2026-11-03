"""A GATT-level fake of the purifier, speaking the real wire protocol."""
import asyncio, os
from germguardian import protocol as P
from germguardian import client as C


class FakePurifier:
    def __init__(self, key: bytes, proto=0xEEF3C48D, slot_ok=True):
        self.cipher = P.Cipher16(key)
        self.unlock = proto.to_bytes(4, "little")
        self.unlocked = False
        self.slot_ok = slot_ok
        self.notify = {}
        self.chal = None
        self.host_chal = None
        self.rx = P.Reassembler()
        self.counter = 1000
        self.seq = 1
        self.state = dict(power=0, wind=4, auto=0, timer=0, uv=0)
        self.writes = []

    async def start_notify(self, uuid, cb):
        self.notify[uuid] = cb

    async def disconnect(self):
        pass

    async def read_gatt_char(self, uuid):
        if uuid == C.U_F004:
            if not self.unlocked:
                raise RuntimeError("Read Not Permitted")
            self.chal = os.urandom(16)
            return bytearray(self.chal)
        if uuid == C.U_F005:
            return bytearray(self.cipher.block(self.host_chal))
        raise RuntimeError("unreadable " + uuid)

    async def write_gatt_char(self, uuid, data, response=False):
        data = bytes(data)
        self.writes.append((uuid, data))
        if uuid == C.U_F000:
            self.unlocked = data == self.unlock
        elif uuid == C.U_F005:
            if not self.slot_ok or data != self.cipher.block(self.chal):
                raise RuntimeError("rejected")
        elif uuid == C.U_F004:
            self.host_chal = data
        elif uuid == C.U_OUT:
            blk, _ = self.rx.feed(data)
            if blk:
                self._handle(blk)

    def _status(self):
        s = self.state
        wind = 0xFF if not s["power"] else s["wind"] - 1
        return bytes([s["power"], wind, s["auto"], s["timer"], s["uv"], 0x01, 0x23, 0x05, 0x69, 0x00, 0x70])

    def _handle(self, blk):
        _, _, pl = P.ze_parse(P.decode_data(blk, self.cipher))
        typ, body = P.aspe_parse(pl)
        if typ == P.GET_DATA:
            reply = P.aspe_build(P.INPUT_REPORT, P.aspe_blocks([(P.DT_STATUS, self._status())]))
        else:
            codes = b""
            for t, d in P.report_blocks(body):
                key = {P.DT_POWER: "power", P.DT_WIND: "wind", P.DT_AUTO: "auto",
                       P.DT_TIMER: "timer", P.DT_UV: "uv"}[t]
                self.state[key] = d[0] + (1 if key == "wind" else 0)
                codes += bytes([t, 1])
            reply = P.aspe_build(P.DATA_RESPONSE, codes)
        enc = P.encode_data(P.ze_command(reply, self.counter, to_device=False), self.cipher)
        self.counter += 1
        pdus = P.chunk(enc, self.seq)
        self.seq = self.seq % 15 + 1
        loop = asyncio.get_running_loop()
        for p in pdus:
            loop.call_soon(self.notify[C.U_IN], None, bytearray(p))
