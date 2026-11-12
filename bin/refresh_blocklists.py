#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Pull the upstream host lists, dedupe, and emit the compiled blocklist.

Outputs:
  data/blocked-hosts.txt      -- the full set, consumed by safeguard.blocklist
  data/sources.lock           -- source -> (sha256, count) for reproducibility
  /etc/searxng/blocked-hosts.yml -- small curated regex list for the SearXNG
                                    ``hostnames`` plugin (independent Layer 3)

Run with --offline to recompile from the curated seed only (no network).

Exit status:
  0  list written, every source accounted for (fresh or cached)
  1  refused to write: the result is implausibly small (see --force)
  3  list written, but at least one source had neither a usable response nor
     a cached copy, so its hosts are missing
"""

from __future__ import annotations

import argparse
import hashlib
import os
import sys
import tempfile

import httpx

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
DATA = os.path.join(ROOT, "data")
SEED = os.path.join(DATA, "curated-seed.txt")
ALLOWED = os.path.join(DATA, "allowed-hosts.txt")
OUT = os.path.join(DATA, "blocked-hosts.txt")
LOCK = os.path.join(DATA, "sources.lock")
CACHE = os.path.join(DATA, "cache")
HOSTNAMES_YML = os.environ.get("SAFEGUARD_HOSTNAMES_YML", "/etc/searxng/blocked-hosts.yml")

SOURCES = [
    # category, url
    ("adult", "https://raw.githubusercontent.com/blocklistproject/Lists/master/porn.txt"),
    ("adult", "https://raw.githubusercontent.com/Sinfonietta/hostfiles/master/pornography-hosts"),
    ("gambling", "https://raw.githubusercontent.com/blocklistproject/Lists/master/gambling.txt"),
    ("gambling", "https://raw.githubusercontent.com/Sinfonietta/hostfiles/master/gambling-hosts"),
    ("piracy", "https://raw.githubusercontent.com/blocklistproject/Lists/master/piracy.txt"),
    ("malware", "https://raw.githubusercontent.com/blocklistproject/Lists/master/malware.txt"),
    ("scam", "https://raw.githubusercontent.com/blocklistproject/Lists/master/scam.txt"),
    ("phishing", "https://raw.githubusercontent.com/blocklistproject/Lists/master/phishing.txt"),
    ("drugs", "https://raw.githubusercontent.com/blocklistproject/Lists/master/drugs.txt"),
]

# Never let an upstream list take these down, whatever it says.
HARD_ALLOW = {
    "wikipedia.org", "wikimedia.org", "google.com", "duckduckgo.com",
    "canada.ca", "gc.ca", "kidshelpphone.ca", "khanacademy.org",
    "nasa.gov", "archive.org", "stackoverflow.com", "github.com",
    "mozilla.org", "bbc.co.uk", "cbc.ca", "britannica.com",
}


def parse_hosts(text: str) -> set[str]:
    hosts: set[str] = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line[0] in "#!":
            continue
        parts = line.split()
        host = parts[1] if len(parts) > 1 and parts[0][0].isdigit() else parts[0]
        host = host.split("#")[0].strip().rstrip(".").lower()
        if not host or "/" in host or ":" in host:
            continue
        if host in ("localhost", "localhost.localdomain", "broadcasthost", "0.0.0.0"):
            continue
        if "." not in host:
            continue
        hosts.add(host)
    return hosts


def read_local(path: str) -> set[str]:
    if not os.path.exists(path):
        return set()
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return parse_hosts(fh.read())


# Refuse to write a list that lost more than this share of the previous one.
MIN_KEEP = 0.8


def previous_count(path: str) -> int:
    """Entry count of the compiled list currently on disk (0 if there is none)."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for _ in range(8):
                line = fh.readline()
                if line.startswith("# entries:"):
                    return int(line.split(":", 1)[1].strip())
                if not line.startswith("#"):
                    break
    except (OSError, ValueError):
        pass
    return 0


def atomic_write(path: str, text: str) -> None:
    d = os.path.dirname(path) or "."
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".tmp-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.chmod(tmp, 0o644)   # mkstemp gives 0600; SearXNG runs as its own user
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--offline", action="store_true", help="skip network sources")
    ap.add_argument("--timeout", type=float, default=60.0)
    ap.add_argument("--force", action="store_true",
                    help="write even if the list shrank sharply against the previous one")
    args = ap.parse_args()

    os.makedirs(CACHE, exist_ok=True)
    seed = read_local(SEED)
    allowed = read_local(ALLOWED) | HARD_ALLOW
    blocked = set(seed)
    lock_lines = [f"seed\tlocal\t{len(seed)}"]
    missing = 0   # sources with no usable response and no cache

    def cached_hosts(body_path: str) -> set[str] | None:
        if not os.path.exists(body_path):
            return None
        with open(body_path, "r", encoding="utf-8", errors="replace") as fh:
            return parse_hosts(fh.read())

    if not args.offline:
        with httpx.Client(timeout=args.timeout, follow_redirects=True,
                          headers={"User-Agent": "searxng-safesearch-blocklist/1.0"}) as client:
            for category, url in SOURCES:
                slug = hashlib.sha256(url.encode()).hexdigest()[:16]
                body_path = os.path.join(CACHE, slug + ".txt")
                etag_path = os.path.join(CACHE, slug + ".etag")

                headers = {}
                if os.path.exists(body_path) and os.path.exists(etag_path):
                    with open(etag_path, "r", encoding="utf-8") as fh:
                        etag = fh.read().strip()
                    if etag:
                        headers["If-None-Match"] = etag

                try:
                    resp = client.get(url, headers=headers)
                    if resp.status_code == 304:
                        # These lists total ~110 MB; re-downloading them nightly
                        # when nothing changed is pure waste.
                        with open(body_path, "r", encoding="utf-8", errors="replace") as fh:
                            text = fh.read()
                        hosts = parse_hosts(text)
                        blocked |= hosts
                        lock_lines.append(f"{category}\t{url}\t{len(hosts)}\tcached")
                        print(f"CACHED{category:>10s} {len(hosts):7d}  {url}")
                        continue
                    resp.raise_for_status()
                except Exception as exc:  # noqa: BLE001
                    print(f"WARN  {category} {url}: {exc}", file=sys.stderr)
                    hosts = cached_hosts(body_path)
                    if hosts is not None:
                        blocked |= hosts
                        lock_lines.append(f"{category}\t{url}\tFAILED(using cache, {len(hosts)})")
                        print(f"WARN  {category}: using cached copy ({len(hosts)} hosts)", file=sys.stderr)
                    else:
                        missing += 1
                        lock_lines.append(f"{category}\t{url}\tFAILED")
                    continue
                hosts = parse_hosts(resp.text)
                # A 200 with a truncated or empty body must not replace a good
                # copy: fall back to the cache instead of dropping the source.
                previous = cached_hosts(body_path)
                floor = max(50, len(previous) // 2) if previous else 50
                if len(hosts) < floor:
                    print(f"WARN  {category} {url}: only {len(hosts)} hosts "
                          f"(expected at least {floor}), not trusting it", file=sys.stderr)
                    if previous:
                        blocked |= previous
                        lock_lines.append(
                            f"{category}\t{url}\tSUSPECT({len(hosts)}, using cache, {len(previous)})")
                        print(f"WARN  {category}: using cached copy ({len(previous)} hosts)", file=sys.stderr)
                    else:
                        missing += 1
                        lock_lines.append(f"{category}\t{url}\tSUSPECT({len(hosts)})")
                    continue
                digest = hashlib.sha256(resp.content).hexdigest()[:16]
                atomic_write(body_path, resp.text)
                atomic_write(etag_path, resp.headers.get("etag", ""))
                blocked |= hosts
                lock_lines.append(f"{category}\t{url}\t{len(hosts)}\t{digest}")
                print(f"OK    {category:9s} {len(hosts):7d}  {url}")

    # allowlist wins, including parent-domain entries
    def is_allowed(host: str) -> bool:
        labels = host.split(".")
        return any(".".join(labels[i:]) in allowed for i in range(len(labels) - 1))

    blocked = {h for h in blocked if not is_allowed(h)}

    if len(blocked) < len(seed):
        print("ERROR: compiled list smaller than the seed, refusing to write", file=sys.stderr)
        return 1

    # The seed is ~230 hosts and the full list is millions, so "not smaller
    # than the seed" guards nothing.  Compare against what is deployed now.
    before = previous_count(OUT)
    if before and len(blocked) < before * MIN_KEEP and not args.force:
        print(f"ERROR: compiled list would shrink from {before} to {len(blocked)} hosts "
              f"(below {MIN_KEEP:.0%}); refusing to write.  Re-run with --force if this is intended.",
              file=sys.stderr)
        return 1

    header = (
        "# Compiled child-safety blocklist for the safe-search instance.\n"
        "# GENERATED by bin/refresh_blocklists.py -- do not edit by hand.\n"
        "# Edit data/curated-seed.txt (add) or data/allowed-hosts.txt (remove).\n"
        f"# entries: {len(blocked)}\n"
    )
    atomic_write(OUT, header + "\n".join(sorted(blocked)) + "\n")
    atomic_write(LOCK, "\n".join(lock_lines) + "\n")
    print(f"\nwrote {OUT}: {len(blocked)} hosts")

    # Curated regex fragment for the SearXNG hostnames plugin (Layer 3).
    # Deliberately small -- the big set is enforced by the child_safety plugin.
    curated = sorted(seed - {h for h in seed if is_allowed(h)})
    yml = ["# GENERATED by bin/refresh_blocklists.py -- SearXNG 'hostnames' plugin list.",
           "# Independent second opinion; the full set lives in data/blocked-hosts.txt.",
           ""]
    for host in curated:
        escaped = host.replace(".", r"\.")
        yml.append(f"- '^(.*\\.)?{escaped}$'")
    try:
        atomic_write(HOSTNAMES_YML, "\n".join(yml) + "\n")
        print(f"wrote {HOSTNAMES_YML}: {len(curated)} patterns")
    except OSError as exc:
        print(f"WARN  could not write {HOSTNAMES_YML}: {exc}", file=sys.stderr)
    if missing:
        print(f"WARN  {missing} source(s) had no usable response and no cache; "
              "their hosts are not in the list", file=sys.stderr)
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
