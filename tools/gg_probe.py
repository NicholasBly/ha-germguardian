#!/usr/bin/env python3
"""Test a purifier + key from any computer, without Home Assistant.

  pip install bleak bleak-retry-connector cryptography
  python tools/gg_probe.py --pair              (hold LINK; needs internet)
  python tools/gg_probe.py --key <base64-or-hex> [--address AA:BB:...] [--on|--off]
"""
import argparse, asyncio, pathlib, sys, types

root = pathlib.Path(__file__).parent.parent / "custom_components" / "germguardian"
pkg = types.ModuleType("germguardian"); pkg.__path__ = [str(root)]
sys.modules["germguardian"] = pkg
from germguardian import client as C, protocol as P, pairing as PR  # noqa: E402

from bleak import BleakScanner  # noqa: E402


async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--key", help="omit with --pair")
    ap.add_argument("--pair", action="store_true", help="hold LINK, fetch the key via a.iots.net")
    ap.add_argument("--address")
    ap.add_argument("--protocol", default="EEF3C48D")
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--on", action="store_true")
    g.add_argument("--off", action="store_true")
    a = ap.parse_args()
    if not a.pair and not a.key:
        sys.exit("give --key, or use --pair")
    key = P.parse_key(a.key) if a.key else None
    master = None
    print("scanning 10 s for Aplix units...")
    found = await BleakScanner.discover(timeout=10, return_adv=True)
    cands = []
    for d, adv in found.values():
        m = next((u for u in adv.service_uuids if u.lower().startswith("00000000-24f6-4000-a000-")), None)
        if m and (not a.address or d.address.lower() == a.address.lower()):
            cands.append((d, m))
            print("  ", d.address, adv.rssi, m)
    cands.sort(key=lambda c: c[0].address)
    dev, master = (None, None)
    if len(cands) == 1:
        dev, master = cands[0]
    elif cands:
        print("\nMore than one Aplix unit is in range (one may be a gateway, not a purifier).")
        for i, (d, m) in enumerate(cands):
            print(f"  [{i}] {d.address}")
        pick = input("Which one is your PURIFIER? number: ").strip()
        dev, master = cands[int(pick)]
    if not dev:
        sys.exit("no purifier found - is it powered and in range?")
    if a.pair:
        print("\nPress and HOLD the purifier's LINK button until it beeps/flashes,")
        input("keep holding it, then press Enter here... ")
        try:
            key = await PR.pair_over_ble(dev, master, int(a.protocol, 16), progress=lambda m: print("  *", m))
        except Exception as e:
            sys.exit(f"PAIRING FAILED: {e}")
        import base64
        print("KEY (save this!):", base64.b64encode(key).decode(), "  hex:", key.hex())
        await asyncio.sleep(2)
    print("connecting to", dev.address)
    client, s = await C.open_session(dev, key, int(a.protocol, 16))
    try:
        print("AUTHENTICATED")
        print(await s.get_status())
        if a.on or a.off:
            await s.set(power=a.on)
            await asyncio.sleep(0.5)
            print(await s.get_status())
    finally:
        await client.disconnect()

asyncio.run(main())
