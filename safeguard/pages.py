# SPDX-License-Identifier: AGPL-3.0-or-later
"""Interstitial and block pages served by Layer 2.

Self-contained (inline CSS, no outbound links other than the crisis services)
so they render even if the themed static assets are unavailable.
"""

from __future__ import annotations

import html
import os

__all__ = ["crisis_page", "block_page", "BRAND", "CRISIS_MARKER", "BLOCK_MARKER"]

# Display name of the instance.  Set SAFEGUARD_BRAND to match whatever you put
# in SearXNG's `general.instance_name`.
BRAND = os.environ.get("SAFEGUARD_BRAND", "Safe Search")

CRISIS_MARKER = "safeguard-crisis-interstitial"
BLOCK_MARKER = "safeguard-blocked"

_CSS = """
*{box-sizing:border-box}
body{margin:0;min-height:100vh;font:16px/1.6 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
     color:#20242c;background:linear-gradient(160deg,#f6f2ea 0%,#e7eef3 100%);
     display:flex;align-items:center;justify-content:center;padding:24px}
.card{max-width:640px;width:100%;background:#fff;border-radius:22px;padding:40px 36px;
      box-shadow:0 18px 50px rgba(30,40,60,.14)}
h1{margin:0 0 6px;font-size:26px;line-height:1.25}
.lede{margin:0 0 22px;font-size:17px;color:#3c4352}
p{margin:0 0 14px}
.mark{font-size:13px;letter-spacing:.14em;text-transform:uppercase;color:#8a8f9a;margin:0 0 18px}
.help{background:#f3f7fb;border:1px solid #dde6ef;border-radius:16px;padding:20px 22px;margin:22px 0}
.help h2{margin:0 0 12px;font-size:15px;letter-spacing:.06em;text-transform:uppercase;color:#516074}
.res{margin:0 0 14px}
.res:last-child{margin-bottom:0}
.res b{display:block;font-size:17px}
.res span{color:#4a5464}
.num{font-size:22px;font-weight:700;color:#12507d;letter-spacing:.5px}
a.btn{display:inline-block;margin-top:6px;background:#12507d;color:#fff;text-decoration:none;
      padding:13px 24px;border-radius:999px;font-weight:600}
a.btn.sec{background:#e8edf3;color:#22303f;margin-left:10px}
.foot{margin:26px 0 0;font-size:14px;color:#6a7280}
.foot a{color:#12507d}
@media (prefers-color-scheme:dark){
  body{color:#e8ecf2;background:linear-gradient(160deg,#1b1f27 0%,#141a22 100%)}
  .card{background:#222833;box-shadow:0 18px 50px rgba(0,0,0,.45)}
  .help{background:#1c222c;border-color:#333d4b}
  .help h2{color:#9fb0c4}.res span{color:#b3bcc9}.num{color:#7fc0f0}
  a.btn{background:#2b6ea8}a.btn.sec{background:#333c49;color:#e8ecf2}
  .foot{color:#98a2b0}.foot a{color:#7fc0f0}
}
"""


def _shell(title: str, marker: str, body: str) -> str:
    return (
        "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
        "<meta name=\"robots\" content=\"noindex,nofollow\">"
        f"<title>{html.escape(title)}</title><style>{_CSS}</style></head>"
        f"<body data-safeguard=\"{marker}\"><!-- {marker} -->"
        f"<main class=\"card\">{body}</main></body></html>"
    )


def crisis_page(kind: str = "self_harm") -> str:
    """Full-page crisis interstitial -- served *instead of* search results."""
    if kind == "eating_disorder":
        h1 = "You deserve support with this"
        lede = (
            "It sounds like you might be having a hard time with food, eating, or how you "
            "feel about your body. You are not alone, and you have not done anything wrong."
        )
    else:
        h1 = "You matter, and help is here"
        lede = (
            "It sounds like you might be going through something really painful right now. "
            "You are not alone, and you do not have to handle this by yourself."
        )

    extra = ""
    if kind == "eating_disorder":
        extra = (
            "<div class=\"res\"><b>NEDIC &mdash; National Eating Disorder Information Centre</b>"
            "<span class=\"num\">1-866-633-4220</span>"
            "<span>Free, confidential support and referrals across Canada.</span></div>"
        )

    body = f"""
<p class="mark">A safe place to pause</p>
<h1>{h1}</h1>
<p class="lede">{lede}</p>
<p>The best next step is talking to someone who can help &mdash; a parent, a caregiver,
a teacher, a school counsellor, or one of the free services below. They are open right
now, they are free, and you do not need a reason "good enough" to call.</p>

<div class="help">
  <h2>Talk to someone now &mdash; Canada</h2>
  <div class="res">
    <b>Kids Help Phone</b>
    <span class="num">1-800-668-6868</span>
    <span>Call any time, or text <b>CONNECT</b> to <b>686868</b>. Free and confidential, 24/7.</span>
  </div>
  <div class="res">
    <b>9-8-8 Suicide Crisis Helpline</b>
    <span class="num">988</span>
    <span>Call or text <b>988</b>, any time, in English or French.</span>
  </div>
  {extra}
  <div class="res">
    <b>If someone is in immediate danger</b>
    <span class="num">911</span>
  </div>
</div>

<a class="btn" href="tel:18006686868">Call Kids Help Phone</a>
<a class="btn sec" href="/">Back to search</a>

<p class="foot">{html.escape(BRAND)} does not show results for this kind of search.
That is on purpose &mdash; you deserve a person, not a web page.</p>
"""
    return _shell("Help is available", CRISIS_MARKER, body)


def block_page(label: str = "", category: str = "") -> str:
    """Hard block page for Tier-1/Tier-2 queries that are not a crisis."""
    reason = f" ({html.escape(label)})" if label else ""
    body = f"""
<p class="mark">Blocked by {html.escape(BRAND)}</p>
<h1>That search isn&rsquo;t available here</h1>
<p class="lede">This search matched something {html.escape(BRAND)} doesn&rsquo;t show{reason}.
No results were requested from any search engine.</p>
<p>If you were looking for this for school, a project, or because you are worried about
something, ask a parent, caregiver, or teacher &mdash; they can help you find a safe
source for it.</p>
<div class="help">
  <div class="res">
    <b>Need to talk to someone?</b>
    <span>Kids Help Phone &mdash; call <b>1-800-668-6868</b> or text <b>CONNECT</b> to <b>686868</b>, free, 24/7.</span>
  </div>
</div>
<a class="btn" href="/">Try a different search</a>
<p class="foot">Category: <code>{html.escape(category or "restricted")}</code></p>
"""
    return _shell("Search blocked", BLOCK_MARKER, body)
