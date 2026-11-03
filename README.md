# GermGuardian BLE for Home Assistant

Local Bluetooth control of the abandoned Guardian Technologies / GermGuardian smart
purifiers (APZ-451 = **CDAP4500BCA**, APZ-453 = **CDAP5500BCA**). No cloud, no vendor
app, no internet.

**Status: test version (0.1.5).**
- **Local control: works on real hardware** (power on/off and status, tested on an APZ-451
  with `tools/gg_probe.py`).
- **Pairing through Aplix's server: works.** Run against a real APZ-451 with LINK held, it
  returned the same key the phone app uses (an already-paired unit is read back, not reset).
- **Home Assistant glue: not yet confirmed on a live Home Assistant.** Expect to report bugs.

If you already have a key, you do not need pairing at all: paste it in the setup form.

## Pairing (needs internet once)

Each purifier is controlled with a 16-byte *local key*. The official app obtains it from
Aplix's server **`a.iots.net`** while you hold the LINK button; that server is still up.
This integration repeats that exchange, reconstructed from the app's code and checked
against a capture of the app's traffic (`tools/capture_app.py`, see `APZ-451-protocol.md`
section 14.8). The registration calls themselves have not been captured yet, so the first
real run may need fixes. After pairing, everything is local and works with no internet.

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
python tools/gg_probe.py --pair                  # start it, walk over, hold LINK; prints your key
python tools/gg_probe.py --key YOUR_KEY          # control test
python tools/gg_probe.py --key YOUR_KEY --on     # also turns it on
```

Close the phone app first (the purifier talks to one device at a time). You want to see
`AUTHENTICATED` and a status line. If it fails, send the full output.

`--pair` asks Aplix's server which nearby Aplix units are purifiers (a gateway is ignored),
then waits up to 90 s for that purifier's LINK signal, so you can start it and walk to the unit. If Windows never shows the signal, use
`--address 00:1C:4D:4B:XX:XX --delay 20` (counts down 20 s, then starts anyway).

## Install in Home Assistant

1. HACS -> three-dot menu -> **Custom repositories** -> add
   `https://github.com/NicholasBly/ha-germguardian`, category **Integration**.
2. Install **GermGuardian BLE**, then **restart Home Assistant**.
3. The purifier should appear under Settings -> Devices & services as *Discovered*. If not,
   click **Add integration** -> GermGuardian BLE.
4. Choose your model. To pair: leave the key empty, press **Submit**, then within 20 s press
   and HOLD LINK and keep holding it until the form finishes (it starts as soon as it sees
   the LINK signal). Otherwise paste a key. Leave the protocol number alone. The form checks
   the key against the unit before saving. Pairing writes its steps to the Home Assistant
   log as lines starting `pairing:` (for Docker: `docker logs homeassistant 2>&1 | grep -i pairing`).

Home Assistant needs a Bluetooth adapter or an ESPHome Bluetooth proxy within range. Keep
the phone app closed.

### "No purifiers found" when adding

The message now says why:
- *no Bluetooth adapter or proxy*: Home Assistant has nothing that can connect to Bluetooth
  devices. Check Settings -> Devices & services -> Bluetooth.
- *can see N devices, none is a purifier*: Home Assistant's Bluetooth works but cannot hear
  the unit. Put the adapter or proxy within ~10 ft (3 m) of it, make sure the unit is on, and
  close the phone app (a connected phone can hide the unit). To see what Home Assistant
  hears, open Settings -> Devices & services -> Bluetooth -> Configure -> advertisement
  monitor and look for an address starting `00:1C:4D:`.

### Home Assistant in Docker (for example on a Raspberry Pi)

If Settings -> Devices & services -> Bluetooth shows your adapter as *Failed setup ...
DBus service not found; docker config may be missing `-v /run/dbus:/run/dbus:ro`*, the
container cannot reach the host's Bluetooth, so nothing (this integration included) can
find a device. Per [Home Assistant's Bluetooth docs](https://www.home-assistant.io/integrations/bluetooth/),
the container needs the host's D-Bus socket and two capabilities. In `docker-compose.yml`:

```yaml
    cap_add:
      - NET_ADMIN
      - NET_RAW
    volumes:
      - /run/dbus:/run/dbus:ro
```

(or `--cap-add=NET_ADMIN --cap-add=NET_RAW -v /run/dbus:/run/dbus:ro` with `docker run`).
Apply it by **recreating** the container (`docker compose up -d`); a restart is not enough.
The host also needs BlueZ (5.43 or newer, 5.63+ recommended): `sudo apt-get install bluez`.
Home Assistant OS and Supervised installs set this up automatically.

## Capturing the official app (for developers)

`tools/capture_app.py` runs mitmproxy and logs the app's traffic to `a_iots_capture.txt`
(it prints the iPhone steps). The log contains your unit's ID and, if you pair during the
capture, your key - do not post it publicly.

## How it works

The integration connects briefly every 30 s (and for each command), authenticates with the
key, reads or writes, and disconnects.

## Tests

`pip install pytest cryptography voluptuous && pytest`
