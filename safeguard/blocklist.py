# SPDX-License-Identifier: AGPL-3.0-or-later
"""Compiled hostname blocklist (Layer 3/4).

The compiled list runs to millions of hosts, so it is held as a sorted array of
64-bit hashes and looked up by bisect over the host and each of its parent
suffixes -- never a regex sweep, and never a set of strings.
``searx.plugins.hostnames`` keeps only a small curated regex list as an
independent second opinion.
"""

from __future__ import annotations

import hashlib
import os
import threading
import typing as t
from array import array
from bisect import bisect_left

from .classifier import host_of

__all__ = ["Blocklist", "get_blocklist", "host_of"]

DATA_DIR = os.environ.get("SAFEGUARD_DATA", "/opt/safesearch-guard/data")
BLOCKED_FILE = os.path.join(DATA_DIR, "blocked-hosts.txt")
ALLOWED_FILE = os.path.join(DATA_DIR, "allowed-hosts.txt")

# TLDs that are adult/abuse-only in practice.
BAD_TLDS = (".xxx", ".adult", ".porn", ".sex", ".sexy", ".cam", ".tube", ".onion")


def _h(host: str) -> int:
    """64-bit digest of a hostname.

    The compiled list runs to millions of entries; holding them as Python
    strings costs ~500 MB per process, while a sorted array of 64-bit hashes
    costs ~35 MB and answers in a bisect.  Collision odds across 4M entries in
    a 64-bit space are ~1e-6, and a collision can only over-block one host.
    """
    return int.from_bytes(hashlib.blake2b(host.encode("utf-8"), digest_size=8).digest(), "big")


def _iter_hosts(path: str) -> t.Iterator[str]:
    if not os.path.exists(path):
        return
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line or line[0] in "#!":
                continue
            parts = line.split()
            host = parts[1] if len(parts) > 1 and parts[0][0].isdigit() else parts[0]
            host = host.strip().rstrip(".").lower()
            if not host or "/" in host or " " in host:
                continue
            if host in ("localhost", "localhost.localdomain", "broadcasthost"):
                continue
            yield host


def _read_hosts(path: str) -> set[str]:
    hosts: set[str] = set()
    if not os.path.exists(path):
        return hosts
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line or line[0] in "#!":
                continue
            # accept "0.0.0.0 evil.com", "127.0.0.1 evil.com" and bare "evil.com"
            parts = line.split()
            host = parts[1] if len(parts) > 1 and parts[0][0].isdigit() else parts[0]
            host = host.strip().rstrip(".").lower()
            if not host or host in ("localhost", "localhost.localdomain", "broadcasthost"):
                continue
            if "/" in host or " " in host:
                continue
            hosts.add(host)
    return hosts


class Blocklist:
    def __init__(self, blocked_file: str = BLOCKED_FILE, allowed_file: str = ALLOWED_FILE) -> None:
        self.blocked_file = blocked_file
        self.allowed_file = allowed_file
        self._lock = threading.Lock()
        self.blocked: array = array("Q")
        self.allowed: set[str] = set()
        self._mtime: float = -1.0
        self.load()

    def load(self) -> None:
        with self._lock:
            allowed = _read_hosts(self.allowed_file)
            # streamed, so the 4M-entry file never exists as strings all at once
            hashes = array("Q")
            for host in _iter_hosts(self.blocked_file):
                if host not in allowed:
                    hashes.append(_h(host))
            seen = sorted(set(hashes))
            self.blocked = array("Q", seen)
            self.allowed = allowed
            try:
                self._mtime = os.path.getmtime(self.blocked_file)
            except OSError:
                self._mtime = -1.0

    def reload_if_changed(self) -> bool:
        try:
            mtime = os.path.getmtime(self.blocked_file)
        except OSError:
            return False
        if mtime != self._mtime:
            self.load()
            return True
        return False

    def __len__(self) -> int:
        return len(self.blocked)

    def _suffixes(self, host: str) -> t.Iterator[str]:
        labels = host.split(".")
        for i in range(len(labels) - 1):
            yield ".".join(labels[i:])

    def _contains(self, host: str) -> bool:
        needle = _h(host)
        blocked = self.blocked
        i = bisect_left(blocked, needle)
        return i < len(blocked) and blocked[i] == needle

    def blocks_host(self, host: str) -> str | None:
        """Return the matching blocklist entry, or ``None``."""
        host = (host or "").strip().rstrip(".").lower()
        if not host:
            return None
        if host in self.allowed:
            return None
        for suffix in self._suffixes(host):
            if suffix in self.allowed:
                return None
            if self._contains(suffix):
                return suffix
        for tld in BAD_TLDS:
            if host.endswith(tld):
                return f"tld:{tld}"
        return None

    def blocks_url(self, url: str) -> str | None:
        return self.blocks_host(host_of(url))


_INSTANCE: Blocklist | None = None


def get_blocklist() -> Blocklist:
    global _INSTANCE  # noqa: PLW0603
    if _INSTANCE is None:
        _INSTANCE = Blocklist()
    return _INSTANCE
