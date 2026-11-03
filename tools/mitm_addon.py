"""mitmproxy add-on: write everything the Guardian app sends to a.iots.net into a file."""
import datetime, os

OUT = os.environ.get("GG_CAPTURE_FILE", "a_iots_capture.txt")
WATCH = ("iots.net",)


def _w(text):
    with open(OUT, "a", encoding="utf-8") as f:
        f.write(text + "\n")


def _body(b):
    if not b:
        return "(empty)"
    try:
        return b.decode("utf-8")
    except UnicodeDecodeError:
        return "(binary %d bytes) hex=%s" % (len(b), b.hex())


class Capture:
    def _watch(self, host):
        return any(w in host for w in WATCH)

    def response(self, flow):
        r, p = flow.request, flow.response
        if not self._watch(r.pretty_host):
            _w("[other host] %s %s" % (r.method, r.pretty_url.split("?")[0])); return
        _w("=" * 70)
        _w("%s  %s %s  (HTTP %s)" % (datetime.datetime.now().isoformat(timespec="seconds"),
                                     r.method, r.pretty_url, r.http_version))
        _w("--- request headers (exact order)")
        for k, v in r.headers.fields:
            _w("  %s: %s" % (k.decode("latin1"), v.decode("latin1")))
        _w("--- request body")
        _w("  " + _body(r.content))
        _w("--- response: %s %s" % (p.status_code, p.reason))
        for k, v in p.headers.fields:
            _w("  %s: %s" % (k.decode("latin1"), v.decode("latin1")))
        _w("--- response body")
        _w("  " + _body(p.content))

    def tls_failed_client(self, data):
        _w("[TLS FAILED] %s - the app may be refusing the proxy certificate (pinning)"
           % (data.conn.sni or data.conn.address))

    def error(self, flow):
        _w("[flow error] %s: %s" % (flow.request.pretty_host, flow.error))


addons = [Capture()]
