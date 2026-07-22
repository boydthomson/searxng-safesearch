#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Acceptance harness for the safe-search instance.

Two modes, because 100k *live* queries would take ~30 hours and get the
instance banned by every upstream engine:

  offline (default, CI gate)
      Drives the real guard WSGI app in-process with a stub upstream, so every
      one of the 100k terms exercises Layer 1 + Layer 2 for real, and replays a
      fixture result set through Layer 3 + Layer 4.  Seconds, deterministic.

  live (nightly)
      Real HTTP against the running instance for a random sample (default
      2000 terms), which is what catches upstream drift.

Thresholds: Tier-1 leaks must be 0, Tier-2 >= 99.9%, crisis coverage 100%,
benign control >= 98%.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import re
import sys
import time
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from safeguard.blocklist import get_blocklist          # noqa: E402
from safeguard.classifier import get_classifier        # noqa: E402
from safeguard.pages import BLOCK_MARKER, CRISIS_MARKER  # noqa: E402

DEFAULT_CORPUS = os.path.join(HERE, "corpus.jsonl")
FIXTURES = os.path.join(HERE, "result_fixtures.jsonl")

TIER2_MIN = 0.999
BENIGN_MIN = 0.98


# --------------------------------------------------------------- offline --
class StubUpstream:
    """Stands in for SearXNG: records what the guard forwarded, returns a SERP."""

    def __init__(self) -> None:
        self.last_url = ""

    def request(self, method, url, headers=None, content=None):  # noqa: ANN001, ARG002
        import httpx
        self.last_url = url
        body = json.dumps({"query": "", "number_of_results": 1, "results": [
            {"url": "https://en.wikipedia.org/wiki/Test", "title": "Test", "content": "A test result."}
        ]}).encode()
        return httpx.Response(200, content=body, headers={"content-type": "application/json"},
                              request=httpx.Request(method, "http://stub" + url))


def offline_runner():
    from safeguard import proxy
    stub = StubUpstream()
    proxy._client = stub  # noqa: SLF001
    client = proxy.app.test_client()

    def run(term: str) -> dict:
        resp = client.get("/search", query_string={"q": term, "safesearch": "0", "format": "json"})
        guard = resp.headers.get("X-Safeguard", "")
        body = resp.get_data(as_text=True)
        forwarded = stub.last_url if guard == "pass" else ""
        return {
            "guard": guard,
            "status": resp.status_code,
            "forwarded": forwarded,
            "results": _results_of(body),
            "crisis": guard.startswith("crisis") or CRISIS_MARKER in body,
            "blocked": guard.startswith("block") or BLOCK_MARKER in body,
        }

    return run, client


def _results_of(body: str) -> list[dict]:
    try:
        return json.loads(body).get("results", []) or []
    except (json.JSONDecodeError, AttributeError):
        return []


# ------------------------------------------------------------------ live --
def live_runner(base_url: str, delay: float, jitter: float = 0.0, seed: int = 0):
    import httpx
    client = httpx.Client(base_url=base_url, timeout=45.0)
    rng = random.Random(seed or 1)

    def run(term: str) -> dict:
        try:
            resp = client.get("/search", params={"q": term, "safesearch": "0", "format": "json"})
        except httpx.HTTPError as exc:
            return {"guard": "error", "status": 0, "error": str(exc), "results": [],
                    "crisis": False, "blocked": False, "forwarded": ""}
        guard = resp.headers.get("X-Safeguard", "")
        body = resp.text
        if delay and guard == "pass":
            # Only space out the requests that actually reached the engines.
            # Measured on this instance: 40 queries at 3 s spacing produced 4
            # CAPTCHA + 4 access-denied events, while a single isolated query
            # produced none -- so the errors are rate-induced, not a baseline
            # of the IP.  A CAPTCHA costs 15 days of engine suspension
            # (`suspended_times.cf_SearxEngineCaptcha`), which would land in
            # the daytime when the site is actually used.  Jitter keeps the
            # spacing from looking machine-regular.
            time.sleep(delay * (1.0 + rng.uniform(-jitter, jitter)) if jitter else delay)
        return {
            "guard": guard,
            "status": resp.status_code,
            "forwarded": "",
            "results": _results_of(body),
            "crisis": guard.startswith("crisis") or CRISIS_MARKER in body,
            "blocked": guard.startswith("block") or BLOCK_MARKER in body,
        }

    return run, client


# ------------------------------------------------------------- scoring ----
def harmful_results(results: list[dict]) -> list[dict]:
    """Layer 3/4 scoring of whatever came back: domain check then content check."""
    bl = get_blocklist()
    clf = get_classifier()
    bad = []
    for r in results:
        url = r.get("url") or ""
        hit = bl.blocks_url(url)
        if hit:
            bad.append({"url": url, "reason": f"blocklist:{hit}"})
            continue
        v = clf.classify_result(url=url, title=r.get("title") or "", content=r.get("content") or "")
        if v.hit:
            bad.append({"url": url, "reason": f"classifier:{v.category}:{v.reason}"})
    return bad


def score(row: dict, out: dict, strict_block: bool = False) -> tuple[bool, str]:
    """``strict_block`` (offline) demands a real block decision.

    Live mode cannot demand that -- a Tier-2 query that upstream answers with
    nothing harmful is a legitimate "safe-redirected" pass -- but offline the
    stub upstream always answers, so anything short of a block is a miss.
    """
    expect = row["expect"]

    if expect == "crisis":
        if not out["crisis"]:
            return False, "crisis term did not receive the interstitial"
        if out["results"]:
            return False, "crisis term returned search results"
        return True, ""

    if expect == "block":
        if out["blocked"] and not out["results"]:
            return True, ""
        if strict_block:
            return False, "query was not blocked (forwarded to upstream engines)"
        leaked = harmful_results(out["results"])
        if leaked:
            return False, f"leaked {len(leaked)} harmful result(s): {leaked[0]['url']} ({leaked[0]['reason']})"
        if out["results"]:
            # Not blocked at L2 but nothing harmful survived L3/L4.  Tier 1 is
            # still a failure -- those queries must never reach an engine.
            if row["tier"] == 1:
                return False, "tier-1 query was forwarded to upstream engines instead of blocked"
            return True, ""
        return True, ""

    # expect == "allow"
    if out["crisis"] or out["blocked"]:
        return False, "benign term was blocked (overblocking)"
    if out["guard"] == "error":
        return False, f"request error: {out.get('error')}"
    return True, ""


def check_no_escalation(client, live: bool) -> list[str]:
    """Layer 1: the client must not be able to lower safe search."""
    problems: list[str] = []
    probes = [
        {"q": "kittens", "safesearch": "0"},
        {"q": "kittens", "safesearch": "1"},
        {"q": "kittens", "safesearch": "0", "format": "json"},
    ]
    for params in probes:
        if live:
            resp = client.get("/search", params=params)
            body = resp.text
        else:
            resp = client.get("/search", query_string=params)
            body = resp.get_data(as_text=True)
        if "safesearch=0" in body or "safesearch=1" in body:
            problems.append(f"response echoes a lowered safesearch for {params}")
    if not live:
        from safeguard import proxy
        forwarded = proxy._client.last_url  # noqa: SLF001
        if "safesearch=2" not in forwarded:
            problems.append(f"forwarded URL did not force safesearch=2: {forwarded}")
        if "safesearch=0" in forwarded or "safesearch=1" in forwarded:
            problems.append(f"forwarded URL retained the client value: {forwarded}")
    return problems


def check_assets(client, live: bool) -> list[str]:
    """The guard must proxy static assets, not answer them itself.

    Flask registers its own /static/<path> route by default, which is more
    specific than the catch-all proxy route and silently shadows it.  Every
    stylesheet and icon then 404s and the theme renders unstyled.  Cheap to
    regress, invisible in a search-only test suite, so it is checked here.
    """
    problems: list[str] = []
    probe = "/static/themes/simple/sxng-ltr.min.css"

    if not live:
        resp = client.get(probe)
        if resp.status_code == 404:
            problems.append(f"guard 404s {probe} (Flask static route is shadowing the proxy)")
        elif resp.headers.get("X-Safeguard") != "pass":
            problems.append(f"{probe} was not forwarded upstream")
        return problems

    index = client.get("/")
    refs = sorted(set(re.findall(r'(?:href|src)="(/static/[^"]+|/manifest\.json)"', index.text)))
    if not refs:
        problems.append("index page referenced no static assets at all")
    for ref in refs[:12]:
        resp = client.get(ref)
        ctype = resp.headers.get("content-type", "")
        if resp.status_code != 200:
            problems.append(f"{ref} -> HTTP {resp.status_code}")
        elif ctype.startswith("text/html"):
            problems.append(f"{ref} served as {ctype} (an error page, not the asset)")
    return problems


IMAGE_BENIGN = ["puppies", "volcano eruption", "monarch butterfly"]
IMAGE_STRICT = ["bikini", "hot girls", "shirtless men"]


def check_images(client, live: bool) -> list[str]:
    """The image tab is the highest-risk surface, so it is checked explicitly.

    Three ways it has already broken in practice: locking `categories` in
    SearXNG preferences silently pins the tab to general (image search returns
    web results); the guard's category whitelist can drop `images`; and
    image_proxy can end up off, which would hotlink thumbnails straight from
    the source CDN, exposing the child's IP and bypassing the blocklist.
    """
    problems: list[str] = []

    for term in IMAGE_STRICT:
        if live:
            resp = client.get("/search", params={"q": term, "categories": "images"})
            guard = resp.headers.get("X-Safeguard", "")
        else:
            resp = client.get("/search", query_string={"q": term, "categories": "images"})
            guard = resp.headers.get("X-Safeguard", "")
        if not guard.startswith("block"):
            problems.append(f"image search for {term!r} was not blocked (guard={guard!r})")

    if not live:
        return problems

    for term in IMAGE_BENIGN:
        resp = client.get("/search", params={"q": term, "categories": "images", "format": "json"})
        try:
            results = resp.json().get("results", [])
        except ValueError:
            problems.append(f"image search for {term!r} returned unparseable JSON")
            continue
        images = [r for r in results if r.get("img_src")]
        if not images:
            problems.append(
                f"image search for {term!r} returned {len(results)} results but none are images "
                "(image engines not selected -- check preferences.lock and the category whitelist)"
            )

    page = client.get("/search", params={"q": IMAGE_BENIGN[0], "categories": "images"}).text
    direct = len(re.findall(r'(?:src|data-src)="https?://', page))
    if direct:
        problems.append(f"{direct} thumbnails are hotlinked instead of proxied (image_proxy off?)")
    return problems


def check_fixtures() -> list[str]:
    """Layer 3/4 replay: known-bad results must all be dropped."""
    if not os.path.exists(FIXTURES):
        return []
    failures = []
    with open(FIXTURES, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            fx = json.loads(line)
            leaked = harmful_results([fx])
            if fx.get("expect", "drop") == "drop" and not leaked:
                failures.append(f"fixture NOT dropped: {fx.get('url')}")
            if fx.get("expect") == "keep" and leaked:
                failures.append(f"fixture wrongly dropped: {fx.get('url')} ({leaked[0]['reason']})")
    return failures


# ---------------------------------------------------------------- main ----
def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", default=DEFAULT_CORPUS)
    ap.add_argument("--mode", choices=["offline", "live"], default="offline")
    ap.add_argument("--base-url", default="http://127.0.0.1:8889")
    ap.add_argument("--sample", type=int, default=0, help="0 = whole corpus")
    ap.add_argument("--benign-sample", type=int, default=0,
                    help="live: cap on benign terms, the only ones that reach upstream engines "
                         "(0 = same as the per-category share)")
    ap.add_argument("--delay", type=float, default=0.0,
                    help="seconds to pause AFTER a request that actually hit upstream")
    ap.add_argument("--jitter", type=float, default=0.0,
                    help="+/- this fraction of --delay, so the spacing is not machine-regular")
    ap.add_argument("--report", default="")
    ap.add_argument("--failures", default="", help="JSONL file receiving EVERY failure")
    ap.add_argument("--previous", default="", help="prior report JSON, for the regression diff")
    ap.add_argument("--seed", type=int, default=20260721)
    args = ap.parse_args()

    if args.mode == "live" and not args.sample:
        args.sample = 2000

    rows = []
    with open(args.corpus, "r", encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                rows.append(json.loads(line))
    if args.sample and args.sample < len(rows):
        rng = random.Random(args.seed)
        # keep every category represented
        by_cat: dict[str, list[dict]] = defaultdict(list)
        for r in rows:
            by_cat[r["category"]].append(r)
        per = max(1, args.sample // len(by_cat))
        picked = []
        for cat, cat_rows in by_cat.items():
            # Blocked terms are short-circuited by the guard and never reach an
            # engine, so they are effectively free and worth sampling widely.
            # Benign terms are the entire upstream cost -- budget them apart.
            n = args.benign_sample if (cat == "benign" and args.benign_sample) else per
            picked.extend(rng.sample(cat_rows, min(n, len(cat_rows))))
        rows = picked

    if args.mode == "offline":
        run, client = offline_runner()
    else:
        run, client = live_runner(args.base_url, args.delay, args.jitter, args.seed)

    print(f"mode={args.mode} terms={len(rows)} blocklist={len(get_blocklist())} "
          f"lexicon=v{get_classifier().version}", flush=True)

    escalation = check_no_escalation(client, args.mode == "live")
    asset_problems = check_assets(client, args.mode == "live")
    image_problems = check_images(client, args.mode == "live")
    fixture_failures = check_fixtures()

    stats: dict[str, dict[str, int]] = defaultdict(lambda: {"n": 0, "pass": 0})
    failures: list[dict] = []
    crisis_total = crisis_ok = 0
    started = time.time()

    for i, row in enumerate(rows, 1):
        out = run(row["term"])
        ok, why = score(row, out, strict_block=args.mode == "offline")
        s = stats[row["category"]]
        s["n"] += 1
        s["pass"] += int(ok)
        if row["expect"] == "crisis":
            crisis_total += 1
            crisis_ok += int(out["crisis"] and not out["results"])
        if not ok:
            failures.append({
                "term": row["term"], "category": row["category"], "tier": row["tier"],
                "mutation": row["mutation"], "reason": why,
                "guard": out["guard"],
                "leaked": [r.get("url") for r in out["results"]][:5],
            })
        if i % 10000 == 0:
            print(f"  {i}/{len(rows)} ({time.time() - started:.0f}s)", flush=True)

    tier1 = [f for f in failures if f["tier"] == 1]
    tier2_n = sum(s["n"] for c, s in stats.items() if _tier_of(rows, c) == 2)
    tier2_pass = sum(s["pass"] for c, s in stats.items() if _tier_of(rows, c) == 2)
    benign = stats.get("benign", {"n": 0, "pass": 0})

    tier2_rate = tier2_pass / tier2_n if tier2_n else 1.0
    benign_rate = benign["pass"] / benign["n"] if benign["n"] else 1.0
    crisis_rate = crisis_ok / crisis_total if crisis_total else 1.0

    green = (
        not tier1 and not escalation and not fixture_failures and not asset_problems and not image_problems
        and tier2_rate >= TIER2_MIN and benign_rate >= BENIGN_MIN and crisis_rate >= 1.0
    )

    report = {
        "mode": args.mode,
        "terms": len(rows),
        "duration_s": round(time.time() - started, 1),
        "lexicon_version": get_classifier().version,
        "blocked_hosts": len(get_blocklist()),
        "tier1_leaks": len(tier1),
        "tier2_pass_rate": round(tier2_rate, 5),
        "crisis_coverage": round(crisis_rate, 5),
        "benign_pass_rate": round(benign_rate, 5),
        "escalation_problems": escalation,
        "asset_problems": asset_problems,
        "image_problems": image_problems,
        "fixture_failures": fixture_failures,
        "by_category": {c: {"n": s["n"], "pass": s["pass"],
                            "rate": round(s["pass"] / s["n"], 5) if s["n"] else 1.0}
                        for c, s in sorted(stats.items())},
        "failures": failures[:2000],
        "failures_file": args.failures or "",
        "failure_count": len(failures),
        "green": green,
    }

    print("\n=== per category ===")
    for cat, s in sorted(report["by_category"].items()):
        flag = "" if s["rate"] >= 0.999 else "   <-- "
        print(f"  {cat:18s} {s['pass']:7d}/{s['n']:<7d} {s['rate'] * 100:7.3f}%{flag}")

    print("\n=== gate ===")
    print(f"  tier-1 leaks       {len(tier1)}            (must be 0)")
    print(f"  tier-2 pass rate   {tier2_rate * 100:.4f}%   (must be >= 99.9%)")
    print(f"  crisis coverage    {crisis_rate * 100:.4f}%   (must be 100%)")
    print(f"  benign pass rate   {benign_rate * 100:.4f}%   (must be >= 98%)")
    print(f"  no-escalation      {'OK' if not escalation else escalation}")
    print(f"  L3/L4 fixtures     {'OK' if not fixture_failures else fixture_failures[:5]}")
    print(f"  static assets      {'OK' if not asset_problems else asset_problems[:5]}")
    print(f"  image search       {'OK' if not image_problems else image_problems[:5]}")

    if failures:
        print(f"\n=== first 15 of {len(failures)} failures ===")
        for f in failures[:15]:
            print(f"  [{f['category']}/{f['mutation']}] {f['term']!r}\n      {f['reason']}")

    if args.previous and os.path.exists(args.previous):
        with open(args.previous, "r", encoding="utf-8") as fh:
            prev = json.load(fh)
        prev_terms = {f["term"] for f in prev.get("failures", [])}
        now_terms = {f["term"] for f in failures}
        new = sorted(now_terms - prev_terms)[:25]
        fixed = len(prev_terms - now_terms)
        print(f"\n=== diff vs previous run ===\n  new failures: {len(now_terms - prev_terms)}"
              f"   fixed: {fixed}")
        for t in new:
            print(f"    + {t!r}")
        report["regressions"] = sorted(now_terms - prev_terms)[:500]

    if args.failures:
        os.makedirs(os.path.dirname(args.failures) or ".", exist_ok=True)
        with open(args.failures, "w", encoding="utf-8") as fh:
            for f in failures:
                fh.write(json.dumps(f, ensure_ascii=False) + "\n")
        print(f"\nall {len(failures)} failures: {args.failures}")

    if args.report:
        os.makedirs(os.path.dirname(args.report) or ".", exist_ok=True)
        with open(args.report, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2, ensure_ascii=False)
        print(f"\nreport: {args.report}")

    print("\nRESULT: " + ("GREEN" if green else "RED"))
    return 0 if green else 1


def _tier_of(rows: list[dict], category: str) -> int:
    for r in rows:
        if r["category"] == category:
            return r["tier"]
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
