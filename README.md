# GermGuardian BLE for Home Assistant

Local Bluetooth control of the abandoned Guardian Technologies / GermGuardian smart
purifiers (APZ-451 = **CDAP4500BCA**, APZ-453 = **CDAP5500BCA**). No cloud, no vendor
app, no internet.

**Status: first test version (0.1.0).** The protocol layer is verified against captures
from real hardware and a simulated purifier, but the Home Assistant glue has not yet been
run on a live Home Assistant. Expect to report bugs.

## Pairing (needs internet once)

Each purifier is controlled with a 16-byte *local key*. The official app obtains it from
Aplix's server **`a.iots.net`** while you hold the LINK button; that server is still up.
This integration repeats that exchange (reconstructed from the app's code, so the first
real run may need fixes). After pairing, everything is local and works with no internet.

Or skip pairing and paste a key you already have (base64 such as
`AAECAwQFBgcICQoLDA0ODw==`, or 32 hex characters). **Save the key** - it is shown by
`gg_probe.py --pair` and stored in the integration's config entry.

## Entities

Fan (on/off, 5 speeds, `auto` preset), UV light switch, timer select (off/1/2/4/8 h),
sensors for air quality, filter hours and life, UV bulb hours and life.

## Test it without Home Assistant first (recommended)

On any computer with Bluetooth, Python 3.11+:

```
pip install bleak bleak-retry-connector cryptography
git clone https://github.com/NicholasBly/ha-germguardian
cd ha-germguardian
python tools/gg_probe.py --pair                  # hold LINK; prints your key
python tools/gg_probe.py --key YOUR_KEY          # control test
python tools/gg_probe.py --key YOUR_KEY --on     # also turns it on
```

Close the phone app first (the purifier talks to one device at a time). You want to see
`AUTHENTICATED` and a status line. If it fails, send the full output.

## Install in Home Assistant

1. HACS -> three-dot menu -> **Custom repositories** -> add
   `https://github.com/NicholasBly/ha-germguardian`, category **Integration**.
2. Install **GermGuardian BLE**, then **restart Home Assistant**.
3. The purifier should appear under Settings -> Devices & services as *Discovered*. If not,
   click **Add integration** -> GermGuardian BLE.
4. Choose your model. To pair: leave the key empty, press and HOLD LINK, and keep holding
   it while you press Submit. Otherwise paste a key. Leave the protocol number alone. The
   form checks the key against the unit before saving.

Home Assistant needs a Bluetooth adapter or an ESPHome Bluetooth proxy within range. Keep
the phone app closed.

## How it works

The integration connects briefly every 30 s (and for each command), authenticates with the
key, reads or writes, and disconnects.

## Tests

`pip install pytest cryptography && pytest`
