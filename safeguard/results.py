# SPDX-License-Identifier: AGPL-3.0-or-later
"""Layer 4 decision for one engine result.

One function, shared by ``searx.plugins.child_safety`` (which drops results in
the live instance) and ``harness.run_harness`` (which replays fixtures), so the
thing that is tested is the thing that runs.
"""

from __future__ import annotations

import typing as t

from .blocklist import get_blocklist
from .classifier import get_classifier

__all__ = ["URL_FIELDS", "result_verdict"]

# Every field of a SearXNG result that makes the browser, or the image proxy,
# fetch something.  A clean page URL with a thumbnail from a blocked host is
# still a picture from a blocked host.
URL_FIELDS = ("url", "img_src", "thumbnail_src", "thumbnail", "iframe_src", "audio_src", "magnetlink")


def result_verdict(result: t.Mapping[str, t.Any]) -> str | None:
    """Return why ``result`` must be dropped, or ``None`` to keep it."""
    bl = get_blocklist()
    for name in URL_FIELDS:
        value = result.get(name)
        if not value or not isinstance(value, str):
            continue
        if value.startswith("//"):
            value = "https:" + value
        hit = bl.blocks_url(value)
        if hit:
            return f"blocklist:{name}:{hit}"

    v = get_classifier().classify_result(
        url=str(result.get("url") or ""),
        title=str(result.get("title") or ""),
        content=str(result.get("content") or ""),
    )
    if v.hit:
        return f"classifier:{v.category}:{v.reason}"
    return None
