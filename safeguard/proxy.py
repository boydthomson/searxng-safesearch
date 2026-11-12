# SPDX-License-Identifier: AGPL-3.0-or-later
"""Layer 1 + Layer 2 guard in front of the SearXNG "safe" instance.

Sits on the public port; SearXNG itself is moved to loopback.  Every request is
rewritten so the client cannot lower safe search, and every search query is
classified before it is allowed anywhere near an upstream engine.
"""

from __future__ import annotations

import base64
import binascii
import ipaddress
import json
import logging
import os
import threading
from collections import Counter
from urllib.parse import quote, urlencode

import flask
import httpx

from .blocklist import get_blocklist, host_of
from .classifier import get_classifier
from .pages import block_page, crisis_page

log = logging.getLogger("safeguard.proxy")

UPSTREAM = os.environ.get("SAFEGUARD_UPSTREAM", "http://127.0.0.1:8899")
FORCED_SAFESEARCH = "2"

# Response headers we must not blindly forward.
_HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade", "content-encoding",
    "content-length", "set-cookie",
}

# static_folder=None is load-bearing: Flask otherwise registers its own
# /static/<path> route, which is more specific than the catch-all below and
# shadows it.  Every SearXNG stylesheet, script and icon then 404s, the theme
# renders unstyled, and the SVG icons blow up to full size.
app = flask.Flask(__name__, static_folder=None)
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024

_client = httpx.Client(base_url=UPSTREAM, timeout=30.0, follow_redirects=False)

# Privacy-preserving counters: category names only, never queries.
_metrics = Counter()
_metrics_lock = threading.Lock()


def _bump(key: str) -> None:
    with _metrics_lock:
        _metrics[key] += 1


def _is_local(req: flask.Request) -> bool:
    """True only for a request made on this machine, not through a proxy.

    A reverse proxy on the same host also connects from loopback, so any
    forwarding header disqualifies the request.
    """
    if any(h in req.headers for h in ("X-Forwarded-For", "X-Real-IP", "Forwarded", "Via")):
        return False
    try:
        return ipaddress.ip_address(req.remote_addr or "").is_loopback
    except ValueError:
        return False


# Who may use the machine-readable formats (json/csv/rss).  "local" keeps the
# harness and nightly job working while stopping anyone else from scraping the
# instance as a free API, which is what trips the engines' CAPTCHA suspensions.
JSON_CLIENTS = os.environ.get("SAFEGUARD_JSON_CLIENTS", "local").lower()


def _format_allowed(req: flask.Request) -> bool:
    return JSON_CLIENTS == "all" or _is_local(req)


def _wants_json() -> bool:
    req = flask.request
    if not _format_allowed(req):
        return False
    return any((v or "").lower() == "json" for v in req.values.getlist("format"))


def _queries_of(req: flask.Request) -> list[str]:
    """Every ``q`` the client sent, from the URL *and* the form body.

    SearXNG reads the form on POST and the URL on GET; classifying all of them
    means the guard can never look at a different query than the one searched.
    """
    out = []
    for q in req.values.getlist("q"):
        q = (q or "").strip()
        if q and q not in out:
            out.append(q)
    return out


# --------------------------------------------------------------------- L1 --
ALLOWED_CATEGORIES = {"general", "science", "it", "news", "map", "images"}

# Client-supplied knobs that are always discarded, in the URL and the body.
_DROPPED = {"safesearch", "preferences", "disabled_engines", "enabled_engines",
            "disabled_plugins", "enabled_plugins", "categories"}


def _forced(items: list[tuple[str, str]], req: flask.Request) -> list[tuple[str, str]]:
    """``items`` with every client-supplied safe-search knob overwritten."""
    out = []
    cats: list[str] = []
    for k, v in items:
        key = k.lower()
        if key == "categories":
            # may be repeated or comma-separated; keep only the ones we allow
            cats += [c.strip().lower() for c in v.split(",")]
            continue
        if key in _DROPPED:
            continue
        if key.startswith("category_") and key[len("category_"):] not in ALLOWED_CATEGORIES:
            continue
        if key == "format" and not _format_allowed(req):
            continue
        out.append((k, v))
    out.append(("safesearch", FORCED_SAFESEARCH))
    kept = [c for c in dict.fromkeys(cats) if c in ALLOWED_CATEGORIES]
    if kept:
        out.append(("categories", ",".join(kept)))
    return out


def _forced_args(req: flask.Request) -> list[tuple[str, str]]:
    return _forced(list(req.args.items(multi=True)), req)


def _forced_form(req: flask.Request) -> list[tuple[str, str]]:
    return _forced(list(req.form.items(multi=True)), req)


def _safe_path(path: str) -> bool:
    """Reject paths that mean something different upstream than they do here.

    Flask hands us the percent-decoded path.  ``/search%3Fq=x`` decodes to a
    path containing ``?``; forwarded as-is it becomes a real query string that
    was never classified.  Dot segments are normalised away by the HTTP client,
    so ``/x/../search`` would dodge the ``/search`` prefix test.
    """
    if any(c in path for c in "?#\\") or any(ord(c) < 0x20 or ord(c) == 0x7F for c in path):
        return False
    return not any(seg in (".", "..") for seg in path.split("/")) and "//" not in path


# --------------------------------------------------------------------- L2 --
def _scopes_for(req: flask.Request, queries: list[str]) -> tuple[str, ...]:
    """Image searches get the stricter lexicon as well as the general one.

    The tab is not the only way to reach the image engines: a ``!bang`` in the
    query or an ``engines`` parameter selects them directly.  The shortcuts are
    not enumerable from here, so any bang or engine selection gets the strict
    lexicon.
    """
    values: list[str] = []
    for v in req.values.getlist("categories"):
        values += [c.strip().lower() for c in v.split(",")]
    if any("image" in v for v in values):
        return ("all", "images")
    if any(k.lower() == "category_images" for k in req.values.keys()):
        return ("all", "images")
    if any(k.lower() == "engines" for k in req.values.keys()):
        return ("all", "images")
    if any(tok.startswith("!") for q in queries for tok in q.split()):
        return ("all", "images")
    return ("all",)


def _guard_query(q: str, scopes: tuple[str, ...] = ("all",)):
    """Return a flask response to short-circuit with, or ``None`` to proceed."""
    if not q:
        return None
    verdict = get_classifier().classify_query(q, scopes=scopes)
    if not verdict.hit:
        return None

    _bump(f"query_block.{verdict.category}")
    log.info("blocked query category=%s tier=%s action=%s", verdict.category, verdict.tier, verdict.action)

    if verdict.action == "crisis":
        _bump("crisis_served")
        if _wants_json():
            payload = {
                "query": q,
                "number_of_results": 0,
                "results": [],
                "answers": [],
                "corrections": [],
                "infoboxes": [],
                "suggestions": [],
                "unresponsive_engines": [],
                "safeguard": {
                    "action": "crisis",
                    "category": verdict.category,
                    "interstitial": True,
                    "resources": [
                        {"name": "Kids Help Phone", "phone": "1-800-668-6868",
                         "text": "CONNECT to 686868"},
                        {"name": "9-8-8 Suicide Crisis Helpline", "phone": "988",
                         "text": "988"},
                    ],
                },
            }
            resp = flask.Response(json.dumps(payload), status=200, mimetype="application/json")
        else:
            resp = flask.Response(crisis_page(verdict.category), status=200, mimetype="text/html")
        resp.headers["X-Safeguard"] = f"crisis:{verdict.category}"
        return resp

    if _wants_json():
        payload = {
            "query": q,
            "number_of_results": 0,
            "results": [],
            "answers": [],
            "corrections": [],
            "infoboxes": [],
            "suggestions": [],
            "unresponsive_engines": [],
            "safeguard": {"action": "block", "category": verdict.category, "tier": verdict.tier},
        }
        resp = flask.Response(json.dumps(payload), status=200, mimetype="application/json")
    else:
        resp = flask.Response(block_page(verdict.label or "", verdict.category or ""),
                              status=200, mimetype="text/html")
    resp.headers["X-Safeguard"] = f"block:{verdict.category}"
    return resp


def _image_url_candidates(raw: str) -> list[str]:
    """The URL an /image_proxy request points at, in every form it may take.

    SearXNG passes the image URL as a plain (percent-encoded) ``url`` parameter.
    A base64 form is also accepted, but only when the value is not already a
    URL: lenient base64 decoding of a plain URL silently yields garbage with no
    host, which would wave every thumbnail through.
    """
    raw = (raw or "").strip()
    if not raw:
        return []
    if raw.startswith("//"):
        return ["https:" + raw]
    if "://" in raw:
        return [raw]
    out = [raw]
    try:
        decoded = base64.b64decode(raw + "=" * (-len(raw) % 4), altchars=b"-_", validate=True)
        text = decoded.decode("utf-8")
    except (binascii.Error, ValueError):
        return out
    if text.startswith("//"):
        text = "https:" + text
    if "://" in text:
        out.append(text)
    return out


# ------------------------------------------------------------------ routes --
# Both endpoints answer only to this machine.  The counters are per category
# ("crisis_served", "query_block.self_harm"), which is private information
# about the child even without the queries themselves.
@app.route("/healthz")
def healthz():
    if not _is_local(flask.request):
        flask.abort(404)
    bl = get_blocklist()
    bl.reload_if_changed()
    ok = len(bl) > 0
    resp = flask.jsonify(
        ok=ok,
        lexicon_version=get_classifier().version,
        blocked_hosts=len(bl),
        upstream=UPSTREAM,
    )
    resp.status_code = 200 if ok else 503
    return resp


@app.route("/metricsz")
def metricsz():
    if not _is_local(flask.request):
        flask.abort(404)
    with _metrics_lock:
        return flask.jsonify(dict(_metrics))


@app.route("/preferences", methods=["POST"])
def preferences_post():
    """Preferences are pinned server-side; writes are refused outright."""
    _bump("preferences_write_denied")
    return flask.redirect("/preferences", code=303)


@app.route("/", defaults={"path": ""}, methods=["GET", "POST", "HEAD"])
@app.route("/<path:path>", methods=["GET", "POST", "HEAD"])
def proxy(path: str):
    req = flask.request
    if not _safe_path(path):
        _bump("bad_path")
        return flask.Response("Bad request.", status=400, mimetype="text/plain")
    lowered = "/" + path.lower()
    is_search = lowered.startswith("/search") or lowered in ("/", "/autocompleter")

    if is_search:
        queries = _queries_of(req)
        scopes = _scopes_for(req, queries)
        for q in queries:
            blocked = _guard_query(q, scopes)
            if blocked is not None:
                return blocked

    # L5: never proxy a thumbnail from a blocked host.
    if lowered.startswith("/image_proxy"):
        bl = get_blocklist()
        for raw in req.args.getlist("url"):
            if any(bl.blocks_url(c) for c in _image_url_candidates(raw)):
                _bump("image_proxy_blocked")
                return flask.Response(b"", status=403)

    # Search requests always carry the forced safesearch value, even when the
    # client sent no query string at all.
    query = urlencode(_forced_args(req)) if (req.args or is_search) else ""
    # Re-encode the path: it was decoded once by Flask and must not be decoded
    # a second time, into something else, by the upstream.
    url = "/" + quote(path, safe="/") + (("?" + query) if query else "")

    headers = {
        k: v for k, v in req.headers.items()
        if k.lower() not in ("host", "cookie", "content-length", "accept-encoding", "connection")
    }
    headers["Accept-Encoding"] = "identity"

    body = None
    if req.method == "POST":
        if req.form:
            body = urlencode(_forced_form(req))
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        else:
            body = req.get_data()

    try:
        upstream = _client.request(req.method, url, headers=headers, content=body)
    except httpx.HTTPError as exc:
        log.warning("upstream error: %s", exc)
        return flask.Response("Search is temporarily unavailable.", status=502, mimetype="text/plain")

    out = flask.Response(upstream.content, status=upstream.status_code)
    for k, v in upstream.headers.items():
        if k.lower() not in _HOP_BY_HOP:
            out.headers[k] = v
    out.headers["X-Safeguard"] = "pass"
    out.headers["X-Robots-Tag"] = "noindex, nofollow"
    return out


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    get_classifier()
    hosts = len(get_blocklist())
    log.info("blocklist: %d hosts", hosts)
    if not hosts and os.environ.get("SAFEGUARD_ALLOW_EMPTY_BLOCKLIST") != "1":
        # A missing data file used to load as an empty list without a word.
        raise SystemExit(
            "safeguard: the compiled blocklist is empty or missing -- run "
            "bin/refresh_blocklists.py and check SAFEGUARD_DATA "
            "(set SAFEGUARD_ALLOW_EMPTY_BLOCKLIST=1 to start anyway)"
        )
    from waitress import serve  # noqa: PLC0415

    serve(app, host=os.environ.get("SAFEGUARD_BIND", "0.0.0.0"), port=int(os.environ.get("SAFEGUARD_PORT", "8889")),
          threads=int(os.environ.get("SAFEGUARD_THREADS", "16")), ident="the child",
          # waitress strips X-Forwarded-* from untrusted peers by default, which
          # would hide a same-host reverse proxy from _is_local()
          clear_untrusted_proxy_headers=False)


if __name__ == "__main__":
    main()
