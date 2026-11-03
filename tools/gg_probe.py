#!/usr/bin/env python3
"""Test a purifier from any computer, without Home Assistant.

  pip install bleak bleak-retry-connector cryptography
  python tools/gg_probe.py --pair                 # then go hold LINK; needs internet
  python tools/gg_probe.py --key <base64-or-hex> [--on | --off]
"""
import argparse, asyncio, base64, pathlib, sys, types

root = pathlib.Path(__file__).parent.parent / "custom_components" / "germguardian"
pkg = types.ModuleType("germguardian"); pkg.__path__ = [str(root)]
sys.modules["germguardian"] = pkg
from germguardian import client as C, protocol as P, pairing as PR  # noqa: E402

from bleak import BleakScanner  # noqa: E402

PREFIX = "00000000-24f6-4000-a000-"


def master_of(adv):
    return next((u for u in adv.service_uuids if u.lower().startswith(PREFIX)), None)


def units(seen):
    """Connectable Aplix units seen so far, strongest first: [(rssi, device, master)]."""
    out = []
    for d, adv in seen.values():
        m = master_of(adv)
        if m:
            out.append((adv.rssi, d, m))
    return sorted(out, key=lambda x: -x[0])


def link_mode(seen, us):
    """Units whose LINK beacon (c1/c2/c3 + same low address bytes) is on the air."""
    tails = {a[3:] for a in seen if a[:2] in ("C1", "C2", "C3")}
    return [u for u in us if u[1].address.upper()[3:] in tails]


async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--key", help="omit with --pair")
    ap.add_argument("--pair", action="store_true")
    ap.add_argument("--address", help="only consider this unit")
    ap.add_argument("--protocol", default="EEF3C48D")
    ap.add_argument("--wait", type=int, default=90, help="seconds to wait for LINK (default 90)")
    ap.add_argument("--delay", type=int, help="with --pair --address: skip beacon detection, start after N s")
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--on", action="store_true")
    g.add_argument("--off", action="store_true")
    a = ap.parse_args()
    if not a.pair and not a.key:
        sys.exit("give --key, or use --pair")
    proto = int(a.protocol, 16)

    seen = {}
    def cb(d, adv):
        seen[d.address.upper()] = (d, adv)
    def pick(us):
        return [u for u in us if not a.address or u[1].address.upper() == a.address.upper()]

    http, is_purifier = PR.Http(), {}     # server's verdict per unit: plain id -> bool

    async def purifiers_only(us):
        """Ask Aplix's server which of these units are purifiers (the other kind is a gateway)."""
        new = [u for u in us if PR.plain_id(u[2]).lower() not in is_purifier]
        if new:
            try:
                found = await PR.validate_many(http, [u[2] for u in new])
            except PR.PairError as e:
                sys.exit(f"Cannot ask Aplix's server which unit is the purifier: {e}")
            for _, d, m in new:
                v = found.get(PR.plain_id(m).lower())
                is_purifier[PR.plain_id(m).lower()] = bool(v and v.is_purifier)
                print("  %s: %s" % (d.address, "purifier" if is_purifier[PR.plain_id(m).lower()]
                                    else "not a purifier (ignored)"))
        return [u for u in us if is_purifier.get(PR.plain_id(u[2]).lower())]

    scanner = BleakScanner(detection_callback=cb)
    await scanner.start()
    try:
        if a.pair:
            print("Go to the purifier now and press and HOLD the LINK button.")
            print("I'm watching for it (up to %d s) - keep holding until I say DONE.\n" % a.wait)
            target = None
            for t in range(a.wait):
                us = await purifiers_only(pick(units(seen)))
                if a.delay is not None:
                    if t >= a.delay and us:
                        target = us[0]; break
                else:
                    lm = link_mode(seen, us)
                    if lm:
                        target = lm[0]; break
                if t % 5 == 4:
                    print("  ... waiting (%d purifier(s) in range)" % len(us))
                await asyncio.sleep(1)
            if not target:
                sys.exit("Never saw a unit in LINK mode. Is the button held until it signals?\n"
                         "(Windows sometimes hides the signal: retry with  --address AA:BB:..  --delay 20)")
            tries = [target]
        else:
            print("scanning 8 s...")
            await asyncio.sleep(8)
            tries = pick(units(seen))
            if not tries:
                sys.exit("no purifier found - is it powered and in range?")
    finally:
        await scanner.stop()

    if a.pair:
        _, dev, master = tries[0]
        print("LINK detected on %s - keep holding!" % dev.address)
        try:
            res = await PR.pair_over_ble(dev, master, proto, progress=lambda m: print("  *", m))
        except Exception as e:
            sys.exit(f"PAIRING FAILED: {e}")
        key, proto = res.key, res.protocol      # the server's protocol number wins
        print("\nDONE - you can let go of LINK.")
        print("protocol number: %08X" % proto)
        print("KEY (save this!):", base64.b64encode(key).decode(), "  hex:", key.hex())
        # Windows will not reuse the old device handle after a disconnect: look it up afresh.
        print("waiting for the purifier to come back...")
        await asyncio.sleep(3)
        fresh = await BleakScanner.find_device_by_address(dev.address, timeout=20)
        tries = [(0, fresh or dev, master)]
    else:
        key = P.parse_key(a.key)

    for _, dev, master in tries:
        print("connecting to", dev.address)
        try:
            client, s = await C.open_session(dev, key, proto)
        except (Exception, asyncio.CancelledError) as e:     # bleak/winrt can cancel a connect
            print("  not this one:", e or type(e).__name__)
            continue
        try:
            print("AUTHENTICATED")
            print(await s.get_status())
            if a.on or a.off:
                await s.set(power=a.on)
                await asyncio.sleep(0.5)
                print(await s.get_status())
        finally:
            await client.disconnect()
        return
    if a.pair:
        sys.exit("Pairing finished (key above - save it), but reconnecting with it failed. "
                 "Wait a few seconds and run:  python tools/gg_probe.py --key <key>")
    sys.exit("No unit accepted that key.")

asyncio.run(main())
