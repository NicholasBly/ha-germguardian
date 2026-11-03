# GermGuardian BLE for Home Assistant

Local Bluetooth control of the abandoned Guardian Technologies / GermGuardian smart
purifiers (APZ-451 = **CDAP4500BCA**, APZ-453 = **CDAP5500BCA**). No cloud, no vendor
app, no internet.

**Status: first test version (0.1.0).** The protocol layer is verified against captures
from real hardware and a simulated purifier, but the Home Assistant glue has not yet been
run on a live Home Assistant. Expect to report bugs.

## Important: you need a key you already have

Each purifier is controlled with a 16-byte *local key*. The only way the official app ever
got one was from Aplix's servers, which are gone, so **this integration cannot pair a brand
new or factory-reset unit.** It can control any purifier whose key you already have, e.g.
the key stored by a phone app that was paired before, or the one your Web Bluetooth page
uses. Back it up; if it is lost and the unit is reset, there is currently no way to make a
new one.

Accepted formats: base64 (for example `AAECAwQFBgcICQoLDA0ODw==`) or 32 hex characters.

## Entities

Fan (on/off, 5 speeds, `auto` preset), UV light switch, timer select (off/1/2/4/8 h),
sensors for air quality, filter hours and life, UV bulb hours and life.

## Test it without Home Assistant first (recommended)

On any computer with Bluetooth, Python 3.11+:

```
pip install bleak bleak-retry-connector cryptography
git clone https://github.com/NicholasBly/ha-germguardian
cd ha-germguardian
python tools/gg_probe.py --key YOUR_KEY
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
4. Choose your model, paste the key, leave the protocol number at its default, submit. The
   form connects to the unit to check the key before saving.

Home Assistant needs a Bluetooth adapter or an ESPHome Bluetooth proxy within range. Keep
the phone app closed.

## How it works

The integration connects briefly every 30 s (and for each command), authenticates with the
key, reads or writes, and disconnects.

## Tests

`pip install pytest cryptography && pytest`
