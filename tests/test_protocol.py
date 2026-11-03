import pytest
from germguardian import protocol as P

KEY = bytes(range(16))


def test_crc_check_value():
    assert P.crc16(b"123456789") == 0x6F91


def test_known_answer_regression():
    # Same layout as the worked example in APZ-451-protocol.md section 9, which was
    # checked byte-for-byte against a real unit's key. Dummy key here on purpose.
    c = P.Cipher16(bytes(range(16)))
    cmd = bytes(5) + b"\xff" + bytes(4) + bytes.fromhex("09000102810102820416")
    enc = P.encode_data(cmd, c, bytes(range(16)))
    assert enc.hex() == "000102030405060708090a0b0c0d0e0f0a820bb5416ef0baf1c39458cf53eb588362ee16620e03899adafd0f4ba40fdc"


def test_roundtrip_and_corruption():
    c = P.Cipher16(KEY)
    enc = P.encode_data(b"hello world!!", c)
    assert P.decode_data(enc, c) == b"hello world!!"
    bad = bytearray(enc); bad[20] ^= 1
    with pytest.raises(P.ProtocolError):
        P.decode_data(bytes(bad), c)


def test_ctr_or_quirk_long_frame():
    c = P.Cipher16(KEY)
    nonce = bytes(15) + b"\xff"          # forces the OR into nonce[14]
    enc = P.encode_data(bytes(range(60)), c, nonce)
    assert P.decode_data(enc, c) == bytes(range(60))


def test_stock_aspe_vectors():
    assert P.build_set(power=True).hex() == "060001028101" + "8b"
    assert P.build_set(power=False).hex() == "060001028100" + "8a"
    assert P.build_set(auto=True).hex() == "06000102830" + "18d"
    assert P.GET_STATUS.hex() == "0400028086"


def test_power_off_carries_nothing_else():
    assert P.build_set(power=False, wind=3, uv=True) == P.build_set(power=False)


def test_status_from_capture():
    # DEVICE_STATUS reply decoded from the hardware capture.
    t, pl = P.aspe_parse(bytes.fromhex("1000040c800004000000016705690070ea"))
    assert t == P.INPUT_REPORT
    (typ, data), = P.report_blocks(pl)
    s = P.parse_status(data)
    assert (s.power, s.wind, s.air_quality, s.filter_hours, s.bulb_hours) == (False, 5, 167, 1385, 112)


def test_chunk_headers():
    pdus = P.chunk(bytes(48), 5)
    assert [p[:3].hex() for p in pdus] == ["850011", "050111", "45020e"]


def test_parse_key_forms():
    b64 = "AAECAwQFBgcICQoLDA0ODw=="
    k = P.parse_key(b64)
    assert P.parse_key(b64.rstrip("=")) == k and P.parse_key(k.hex()) == k
    with pytest.raises(ValueError):
        P.parse_key("abc")
