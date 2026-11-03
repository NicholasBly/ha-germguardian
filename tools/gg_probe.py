#!/usr/bin/env python3
"""Test a purifier + key from any computer, without Home Assistant.

  pip install bleak bleak-retry-connector cryptography
  python tools/gg_probe.py --key <base64-or-hex> [--address AA:BB:...] [--on|--off]
"""
import argparse, asyncio, pathlib, sys, types

root = pathlib.Path(__file__).parent.parent / "custom_components" / "germguardian"
pkg = types.ModuleType("germguardian"); pkg.__path__ = [str(root)]
sys.modules["germguardian"] = pkg
from germguardian import client as C, protocol as P  # noqa: E402

from bleak import BleakScanner  # noqa: E402


async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--key", required=True)
    ap.add_argument("--address")
    ap.add_argument("--protocol", default="EEF3C48D")
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--on", action="store_true")
    g.add_argument("--off", action="store_true")
    a = ap.parse_args()
    key = P.parse_key(a.key)
    if a.address:
        dev = await BleakScanner.find_device_by_address(a.address, timeout=15)
    else:
        print("scanning 10 s for Aplix units (service FEF8)...")
        found = await BleakScanner.discover(timeout=10, return_adv=True)
        cands = [(d, adv) for d, adv in found.values()
                 if any(u.startswith("0000fef8") or u.startswith("00000000-24f6") for u in adv.service_uuids)]
        for d, adv in cands:
            print("  ", d.address, adv.rssi, adv.service_uuids)
        dev = cands[0][0] if cands else None
    if not dev:
        sys.exit("no purifier found - is it powered and in range?")
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
