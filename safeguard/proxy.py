# SPDX-License-Identifier: AGPL-3.0-or-later
"""Layer 1 + Layer 2 guard in front of the SearXNG "safe" instance.

Sits on the public port; SearXNG itself is moved to loopback.  Every request is
rewritten so the client cannot lower safe search, and every search query is
classified before it is allowed anywhere near an upstream engine.
"""

from __future__ import annotations

import base64
import binascii
import json
import logging
import os
import threading
from collections import Counter
from urllib.parse import urlencode

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


def _wants_json() -> bool:
    return (flask.request.values.get("format") or "").lower() == "json"


def _query_of(req: flask.Request) -> str:
    return (req.values.get("q") or "").strip()


# --------------------------------------------------------------------- L1 --
def _forced_args(req: flask.Request) -> list[tuple[str, str]]:
    """Query string with every client-supplied safe-search knob overwritten."""
    dropped = {"safesearch", "preferences", "disabled_engines", "enabled_engines",
               "disabled_plugins", "enabled_plugins", "categories"}
    args = [(k, v) for k, v in req.args.items(multi=True) if k.lower() not in dropped]
    args.append(("safesearch", FORCED_SAFESEARCH))
    # keep an explicit category only when it is one we still allow
    cats = [c for c in req.args.getlist("categories") if c in ALLOWED_CATEGORIES]
    for c in cats:
        args.append(("categories", c))
    return args


ALLOWED_CATEGORIES = {"general", "science", "it", "news", "map", "images"}


def _forced_form(req: flask.Request) -> list[tuple[str, str]]:
    dropped = {"safesearch", "categories"}
    form = [(k, v) for k, v in req.form.items(multi=True) if k.lower() not in dropped]
    form.append(("safesearch", FORCED_SAFESEARCH))
    for c in req.form.getlist("categories"):
        if c in ALLOWED_CATEGORIES:
            form.append(("categories", c))
    return form


# --------------------------------------------------------------------- L2 --
def _scopes_for(req: flask.Request) -> tuple[str, ...]:
    """Image searches get the stricter lexicon as well as the general one."""
    values = [v.lower() for v in req.values.getlist("categories")]
    values += [v.lower() for v in req.values.getlist("category_images")]
    if any("image" in v for v in values) or req.values.get("category_images"):
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


# ------------------------------------------------------------------ routes --
@app.route("/healthz")
def healthz():
    bl = get_blocklist()
    bl.reload_if_changed()
    return flask.jsonify(
        ok=True,
        lexicon_version=get_classifier().version,
        blocked_hosts=len(bl),
        upstream=UPSTREAM,
    )


@app.route("/metricsz")
def metricsz():
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
    lowered = "/" + path.lower()

    if lowered.startswith("/search") or lowered in ("/", "/autocompleter"):
        blocked = _guard_query(_query_of(req), _scopes_for(req))
        if blocked is not None:
            return blocked

    # L5: never proxy a thumbnail from a blocked host.
    if lowered.startswith("/image_proxy"):
        raw = req.args.get("url", "")
        try:
            decoded = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)).decode("utf-8", "replace")
        except (binascii.Error, ValueError):
            decoded = raw
        hit = get_blocklist().blocks_url(decoded)
        if hit:
            _bump("image_proxy_blocked")
            return flask.Response(b"", status=403)

    query = urlencode(_forced_args(req), doseq=True) if req.args else ""
    url = "/" + path + (("?" + query) if query else "")

    headers = {
        k: v for k, v in req.headers.items()
        if k.lower() not in ("host", "cookie", "content-length", "accept-encoding", "connection")
    }
    headers["Accept-Encoding"] = "identity"

    body = None
    if req.method == "POST":
        if req.form:
            body = urlencode(_forced_form(req), doseq=True)
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
    log.info("blocklist: %d hosts", len(get_blocklist()))
    from waitress import serve  # noqa: PLC0415

    serve(app, host="0.0.0.0", port=int(os.environ.get("SAFEGUARD_PORT", "8889")),
          threads=int(os.environ.get("SAFEGUARD_THREADS", "16")), ident="the child")


if __name__ == "__main__":
    main()
