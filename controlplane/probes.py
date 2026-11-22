"""Probe primitives shared by the agent (egress side) and prober.py (entry side). Standard library only."""
import http.client
import socket
import ssl
import time
import urllib.parse

USER_AGENT = "Mozilla/5.0 (compatible; egress-health/0.1)"


def http_probe(url, source_ip=None, timeout=10.0):
    """GET url with the connection bound to source_ip. Latency is time to response headers.

    ok means 2xx/3xx; 403 and 429 are the usual signs that a target has started to block an IP, so they count
    as failures and their status lands in detail."""
    u = urllib.parse.urlsplit(url)
    if u.scheme not in ("http", "https"):
        return {"ok": False, "latency_ms": None, "detail": "unsupported scheme %s" % u.scheme}
    port = u.port or (443 if u.scheme == "https" else 80)
    source = (source_ip, 0) if source_ip else None
    if u.scheme == "https":
        conn = http.client.HTTPSConnection(u.hostname, port, timeout=timeout, source_address=source,
                                           context=ssl.create_default_context())
    else:
        conn = http.client.HTTPConnection(u.hostname, port, timeout=timeout, source_address=source)
    path = (u.path or "/") + ("?" + u.query if u.query else "")
    start = time.monotonic()
    try:
        conn.request("GET", path, headers={"User-Agent": USER_AGENT, "Connection": "close"})
        resp = conn.getresponse()
        latency = (time.monotonic() - start) * 1000
        resp.read(65536)
        ok = 200 <= resp.status < 400
        return {"ok": ok, "latency_ms": round(latency, 1), "detail": "HTTP %d" % resp.status}
    except (OSError, http.client.HTTPException) as e:
        return {"ok": False, "latency_ms": None, "detail": "%s: %s" % (e.__class__.__name__, e)}
    finally:
        conn.close()


def tcp_probe(host, port, tries=3, timeout=5.0):
    """Best TCP connect time over a few tries; ok if any try connected."""
    best, last_error = None, ""
    for _ in range(tries):
        start = time.monotonic()
        try:
            with socket.create_connection((host, int(port)), timeout=timeout):
                ms = (time.monotonic() - start) * 1000
                best = ms if best is None else min(best, ms)
        except OSError as e:
            last_error = "%s: %s" % (e.__class__.__name__, e)
    if best is None:
        return {"ok": False, "latency_ms": None, "detail": last_error}
    return {"ok": True, "latency_ms": round(best, 1), "detail": ""}
