# the safe-search instance — child-safety filter

A defence-in-depth child-safety filter layered on top of a self-hosted
[SearXNG](https://github.com/searxng/searxng) instance.

SearXNG's own `safesearch=2` only asks upstream engines to censor themselves and
drops what *they* flag as adult. It does nothing for self-harm, weapons, drugs,
gore, gambling, piracy, extremism or dark-web queries, and several adult engines
ignore the flag outright. Everything below is layered on top of it.

```
client ─▶ :8889 safesearch-guard ────────────▶ :8899 searxng-safe ─▶ engines
          L1 force safesearch=2, strip         L3 hostnames plugin
             cookies/preferences/categories    L4 child_safety plugin
          L2 query classifier                  L5 images guarded, video off,
             ├─ crisis interstitial               thumbnails proxied
             └─ hard block page
```

## Layout

| Path | What it is |
|---|---|
| `safeguard/normalize.py` | Unicode folding, homoglyphs, zero-width strip, de-leet, repeat collapse, spaced-letter joining. Emits *variants*, never one lossy canonical form. |
| `safeguard/spellfix.py` | SymSpell-style distance-1 correction toward the harmful vocabulary, plus per-token de-leeting. Refuses ambiguous corrections. |
| `safeguard/fuzzyphrase.py` | Order-free, typo-tolerant phrase matching — the mechanism that survives a single garbled character. |
| `safeguard/classifier.py` | Category lexicons; the one classifier shared by L2, L4 and the harness. |
| `safeguard/blocklist.py` | 4.1M-host blocklist as a sorted array of 64-bit hashes (~65 MB resident, bisect lookup). |
| `safeguard/pages.py` | Crisis interstitial and block page. |
| `safeguard/proxy.py` | The L1/L2 guard (waitress + Flask), `systemd: safesearch-guard`. |
| `searx/plugins/child_safety.py` | L4 result post-filter, installed into the SearXNG tree. |
| `harness/` | Corpus generator, seed lexicon, acceptance runner, L3/L4 fixtures. |
| `bin/` | Blocklist refresh, lexicon builders, CI gate, nightly job. |
| `data/` | `curated-seed.txt` (hand-maintained), `allowed-hosts.txt`, generated `blocked-hosts.txt`, `sources.lock`. |

Generated files — never edit by hand:
`data/blocked-hosts.txt`, `/etc/searxng/blocked-hosts.yml`,
`safeguard/lexicons/fuzzy_vocab.txt`, `safeguard/lexicons/phrases.yml`,
`harness/corpus.jsonl`.

## Everyday tasks

```bash
cd /opt/safesearch-guard
PY=/usr/local/searxng/searx-pyenv/bin/python

bash bin/ci_gate.sh                 # rebuild everything + full 110k harness
$PY bin/refresh_blocklists.py       # pull upstream lists, recompile
$PY harness/run_harness.py --mode live --sample 1500   # hit the real instance
curl -s localhost:8889/healthz      # blocklist size, lexicon version
curl -s localhost:8889/metricsz     # block counts by category (no queries logged)
```

**To block something new**: add the domain to `data/curated-seed.txt`, or the
phrase to `harness/seeds.yml` under the right category, then run `bin/ci_gate.sh`.
**To unblock a false positive**: add the host to `data/allowed-hosts.txt`, or a
veto regex under that category's `safe:` in `safeguard/lexicons/categories.yml`.

## Acceptance status

Offline gate, corpus `sha256:0a42467…`, 110,494 terms (101,942 adversarial +
8,552 benign controls):

| Gate | Required | Actual |
|---|---|---|
| Tier-1 leaks | 0 | **0** |
| Tier-2 pass rate | ≥ 99.9% | **100.000%** |
| Crisis interstitial coverage | 100% | **100.000%** |
| Benign control pass rate | ≥ 98% | **100.000%** |
| Client cannot lower safe search | pass | pass |
| L3/L4 fixture replay | pass | pass |
| Static assets proxied (not 404'd) | pass | pass |
| Image tab guarded + thumbnails proxied | pass | pass |

Live gate, 450-term stratified sample against the running instance: same, all
categories 100%.

## Two things to know before trusting the number

**The harness has two modes, and only one of them is honest about scale.**
100,000 *live* queries would take roughly 30 hours and would get the instance
banned by every upstream engine. So `--mode offline` (the CI gate) drives the
real guard WSGI app in-process against a stub upstream: all 110k terms exercise
Layers 1–2 for real and replay fixtures through Layers 3–4, in ~80 seconds and
deterministically. `--mode live` then samples a few thousand terms against the
running instance nightly, which is what catches upstream engines drifting.

**The phrase lexicon and the harness corpus share a source.**
`bin/build_phrases.py` and `bin/build_vocab.py` compile from the same
`harness/seeds.yml` that the corpus expands. That is deliberate — the seed list
*is* the threat model — but it means the green number measures **evasion
robustness against a known threat list**, not discovery of threats nobody wrote
down. What covers the unknown tail is the other layers: the 4.1M-host blocklist,
the L4 post-filter scoring URL/title/snippet of every result, and the nightly
live run. Adding a genuinely new threat means adding a seed.

## Image search

Images are **on**; video is not. The brief allows images "routed only through
engines that hard-enforce safe search", which is what this is:

- only `google images`, `bing images`, `qwant images`, `brave.images` and
  `wikicommons.images` are routed to the tab;
- the guard applies an extra `images_strict` lexicon (`scope: images` in
  `categories.yml`) *on top of* the general one, so terms that are merely
  awkward as text are refused as pictures — `bikini`, `hot girls`,
  `shirtless men` block on the image tab but still work in web search;
- `image_proxy` is on, so every thumbnail is fetched by the server and passes
  the guard's blocklist check. Verified: 284 thumbnails on a results page, all
  proxied, zero hotlinked — the child's browser never contacts an image CDN;
- the L4 plugin scores `img_src` / `thumbnail_src`, not just the result URL.

The lightbox is overridden (`theme/`) to put a **Visit page** button on the
source site rather than burying that link in a metadata table under an
"Open image" action. `theme/README.md` also documents why the stock lightbox
silently collapses into a thumbnail-sized box when the theme animates results,
and what to check before adding analytics to a search engine.

Measured on 15 deliberately borderline queries (`beach`, `party`, `yoga`,
`gymnastics`, `cheerleader`, `art model`, `sleepover`, …): **2,003 image
results, 0 flagged** by the blocklist or the classifier.

Read that honestly: it means nothing *this system recognises* got through. It
is not a claim that all 2,003 pictures are appropriate — nobody looked at them.
Most of the work there is being done by the upstream engines' own SafeSearch,
and image search remains the surface most likely to produce a bad surprise. If
you want it off again, drop `images:` from `categories_as_tabs` and remove the
image engines from `keep_only` in `settings-safe.yml`.

Video stays off: autoplay, weaker safe-search enforcement upstream, and no
thumbnail-equivalent chokepoint to filter at.

## Deliberate over-blocks

Each of these blocks a query a child could plausibly mean innocently. For a
10-year-old's search engine the bias runs toward blocking, and the block page
points them at an adult.

- `how ice is made`, `how to make ice` — "ice" is meth slang. `ice cream`,
  `ice cubes`, `ice rink` etc. are vetoed.
- `leaks` on its own — overwhelmingly leaked nudes in this context. Plumbing,
  data and news senses are vetoed.
- `torture methods` — blocked even in a medieval-history framing.
- on the image tab only: swimwear/underwear, "hot/sexy <person>", body-part
  photo queries, gore. Vetoed for science, anatomy, animals, costumes and
  swimming lessons.
- `kms` on its own — self-harm slang. `20 km`, `kms to miles` are vetoed.

## Known gaps

- Layer 4 scores results with lexicons and the blocklist, not an ML NSFW
  classifier. The brief suggested adding a lightweight toxicity/NSFW model for
  novel domains; that is the obvious next increment.
- Multilingual coverage is thin: the corpus adds FR/ES intent prefixes, but the
  category lexicons themselves are English. A French-language porn query with no
  English tokens relies entirely on the hostname blocklist.
- The upstream blocklists are third-party. `data/sources.lock` records the sha256
  and entry count of each fetch, and the refresh refuses to shrink the compiled
  list below the curated seed, but a poisoned upstream could still over-block.
  `data/allowed-hosts.txt` is the escape hatch.

## Operations

- `systemd`: `safesearch-guard.service` (public :8889) and `searxng-safe.service`
  (loopback :8899). The guard hot-reloads the compiled blocklist; SearXNG reads
  its curated regex list at start-up and needs a restart.
- `cron.d/safesearch-guard`: 03:17 nightly. Tuned to be cheap on everything
  external:
  - **offline gate every night** — 110k terms, ~80 s of local CPU, no network.
  - **blocklists refresh Sundays only**, with conditional GET. An unchanged week
    transfers nothing instead of ~110 MB. `data/cache/` holds the last copy
    (110 MB) and is also the fallback if an upstream list is unreachable.
  - **services restart only if `/etc/searxng/blocked-hosts.yml` actually
    changed**, not on a schedule.
  - **live sample ~900 terms, of which only 40 reach an engine.** Blocked terms
    are short-circuited by the guard and never touch the network, so they are
    free; the benign terms are the entire upstream cost and are capped and
    spaced 3 s apart (`--delay` fires only after a request that actually hit
    upstream). Whole run ≈ 3 minutes.
  - Knobs: `LIVE_SAMPLE`, `LIVE_BENIGN`, `LIVE_DELAY`, `FORCE_REFRESH=1`.
- Why the thrift: SearXNG suspends an engine for 24 h on a Cloudflare access
  denial and **15 days** on a captcha (`suspended_times` in the upstream
  defaults). A nightly burst of automated searches is exactly the pattern that
  trips those, and the damage would land during the day when the site is used.
  Several engines already sit at low reliability here.
- `logrotate.d/safesearch-guard`: weekly, 8 kept, compressed.
- Logging is category counts only. Raw queries are never written to disk.
- The `:8888` "Private Search" instance shares the source tree but not the
  settings, and is unaffected: `child_safety` is enabled only in
  `settings-safe.yml`.

> **Two traps, both hit during commissioning.**
>
> `flask.Flask(__name__)` registers its own `/static/<path>` route, which is
> more specific than the proxy catch-all and silently shadows it — every
> stylesheet and icon 404s and the theme renders unstyled with full-size SVG
> icons. The guard passes `static_folder=None`; the harness asserts it.
>
> A caching reverse proxy in front (Nginx Proxy Manager and friends cache
> css/js/images by default) will happily cache a **404**. After any fix that
> touches static assets, purge its cache — otherwise the fix looks like it
> did not work.
>
> Do **not** add `categories` to `preferences.lock`. It pins the tab to the
> default and silently makes image search return web results, with no error
> anywhere. The guard whitelists categories itself
> (`proxy.ALLOWED_CATEGORIES`), so the lock buys nothing. The harness now fails
> if the image tab stops returning images.
>
> `enabled_plugins:` is dead configuration in SearXNG 2026.x — it is silently
> ignored. The live key is `plugins:` with fully-qualified class names. The
> instance had been carrying an `enabled_plugins:` block that did nothing.
