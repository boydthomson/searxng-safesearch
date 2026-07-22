# Theme overrides

Drop-in overrides for SearXNG's `simple` theme, pointed at by
`ui.templates_path` / `ui.static_path` so the stock tree stays untouched.

| File | Purpose |
|---|---|
| `result_templates/images.html` | Image lightbox with a **Visit page** action |
| `image-viewer.css` | Append to `sxng-ltr.min.css`; fixes the collapsed lightbox |

## Why the lightbox collapses (and how it looked)

Stock SearXNG positions the image detail panel with
`position: fixed; inset: 13rem 0 0 60rem`. If **any** ancestor has a computed
`transform` other than `none`, that ancestor becomes the containing block for
fixed descendants and the panel shrinks into its grid cell — it renders as a
small dark box with a chevron, which looks like a broken theme.

A results fade-in is enough to trigger it:

```css
#urls .result { animation: fade .32s ease both }   /* transform in keyframes */
```

With `animation-fill-mode: both` the computed transform settles on
`matrix(1, 0, 0, 1, 0, 0)` — an *identity* matrix, but still not `none`. Hence:

```css
#urls .result-images { animation: none !important; transform: none !important }
```

## Two gotchas that cost real time

**SearXNG caches static file contents in memory at start-up.** Editing a file
under `static_path` changes nothing until the service restarts — the old bytes
keep being served, even on a direct request that bypasses every proxy. Compare
`wc -c` on disk against `curl … | wc -c` if a change seems to vanish.

**A caching reverse proxy in front will cache a 404.** If assets were briefly
broken, purge its cache after fixing, or the fix looks like it failed.

## If you add analytics, check what it sends

On a search engine the query lives in the URL, so a tracker that reports the
location can ship every search to your analytics backend. Swetrix's script, for
example, includes a `qs` field carrying the whole of `location.search` in every
payload — independently of its `search` page-view option. Self-host the script
and neutralise it:

```sh
sed -i 's/qs:p()/qs:void 0/g' swetrix.js
```

Then verify with an intercepting browser that the payload contains only the
path (`"pg": "/search"`) and no query. Do not take the option names on trust.
