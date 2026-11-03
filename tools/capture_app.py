#!/usr/bin/env python3
"""Record what the official Guardian iPhone app sends to a.iots.net.

Needs mitmproxy (https://mitmproxy.org/downloads/ -> Windows installer is easiest).
Run:  python tools/capture_app.py     (then follow the printed steps)
Result: a_iots_capture.txt
"""
import os, pathlib, shutil, socket, subprocess, sys

here = pathlib.Path(__file__).parent
addon = str(here / "mitm_addon.py")
out = pathlib.Path("a_iots_capture.txt").resolve()

exe = shutil.which("mitmdump")
for guess in (r"C:\Program Files\mitmproxy\bin\mitmdump.exe", "/usr/local/bin/mitmdump"):
    if not exe and os.path.exists(guess):
        exe = guess
if not exe:
    sys.exit("mitmdump not found.\nInstall mitmproxy first: https://mitmproxy.org/downloads/ "
             "(Windows installer), then reopen this window and run again.")

ips = set()
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.connect(("8.8.8.8", 80)); ips.add(s.getsockname()[0])
except OSError:
    pass
ip = next(iter(ips), "<your PC's IP from ipconfig>")

print(f"""
=== STEPS (about 5 minutes) =========================================
Your PC's address: {ip}    Port: 8080
Phone and PC must be on the same Wi-Fi. If Windows asks about the
firewall, allow it on PRIVATE networks.

ON THE IPHONE
 1. Settings > Wi-Fi > (i) next to your network > Configure Proxy >
    Manual:  Server {ip}   Port 8080   Authentication OFF > Save
 2. Safari: open  http://mitm.it  > tap Apple > "Get mitmproxy-ca-cert"
    > Allow.  Settings > top banner "Profile Downloaded" > Install.
 3. Settings > General > About > Certificate Trust Settings >
    switch ON  "mitmproxy".
 4. Force-quit the Guardian app, open it again, let it connect to
    the purifier (it contacts a.iots.net each time it connects).
    Optional, for the pairing request: also do the add-device / LINK flow.
 5. Come back here and press Ctrl+C.
AFTERWARDS (important): turn the Wi-Fi proxy back to Off, and delete
the profile: Settings > General > VPN & Device Management > mitmproxy.

Then send me:  {out}
(It contains your unit's ID, and your key if you paired. Look it over first.)
=====================================================================
Capturing... (Ctrl+C to stop)
""")
env = dict(os.environ, GG_CAPTURE_FILE=str(out))
try:
    subprocess.run([exe, "-s", addon, "--listen-port", "8080", "-q"], env=env)
except KeyboardInterrupt:
    pass
print("\nSaved:", out, "(exists)" if out.exists() else "(EMPTY - the app sent nothing through the proxy)")
