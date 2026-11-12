# SPDX-License-Identifier: AGPL-3.0-or-later
"""Layer 4: drop engine results that the child-safety filter rejects.

Install by copying (or symlinking) this file into the SearXNG tree as
``searx/plugins/child_safety.py`` and enabling it in ``settings-safe.yml``:

.. code:: yaml

   plugins:
     searx.plugins.child_safety.SXNGPlugin:
       active: true

The decision itself lives in ``safeguard.results`` so that the guard, this
plugin and the acceptance harness share one implementation.  The plugin finds
the ``safeguard`` package through ``SAFEGUARD_ROOT`` (default
``/opt/safesearch-guard``).

Every result is checked against the compiled multi-million-host blocklist
(page URL, image, thumbnail and iframe sources) and then scored by the
category lexicons on URL, title and snippet.  Suggestions and corrections are
classified as queries, so the instance never proposes a search the guard would
refuse.

If the filter cannot be loaded the plugin raises instead of deactivating
itself: an instance that silently runs without Layer 4 is worse than one that
does not start.
"""

from __future__ import annotations

import os
import sys
import typing as t

from searx.plugins import Plugin, PluginInfo

if t.TYPE_CHECKING:
    import flask
    from searx.extended_types import SXNG_Request
    from searx.plugins import PluginCfg
    from searx.result_types import Result
    from searx.search import SearchWithPlugins

SAFEGUARD_ROOT = os.environ.get("SAFEGUARD_ROOT", "/opt/safesearch-guard")


def _load():
    if SAFEGUARD_ROOT not in sys.path:
        sys.path.insert(0, SAFEGUARD_ROOT)
    from safeguard.blocklist import get_blocklist  # pylint: disable=import-outside-toplevel
    from safeguard.classifier import get_classifier  # pylint: disable=import-outside-toplevel
    from safeguard.results import URL_FIELDS, result_verdict  # pylint: disable=import-outside-toplevel

    return get_blocklist, get_classifier, URL_FIELDS, result_verdict


def _as_mapping(result: t.Any, fields: t.Iterable[str]) -> dict[str, t.Any]:
    """Flatten a typed or legacy (dict-like) result to the fields we score."""
    out: dict[str, t.Any] = {}
    for name in fields:
        value = getattr(result, name, None)
        if value is None and isinstance(result, dict):
            value = result.get(name)
        if value:
            out[name] = value
    return out


class SXNGPlugin(Plugin):
    """Remove results from blocked hosts or with blocked content."""

    id = "child_safety"

    def __init__(self, plg_cfg: "PluginCfg") -> None:
        super().__init__(plg_cfg)
        self.info = PluginInfo(
            id=self.id,
            name="Child safety",
            description="Removes results from blocked hosts and results with unsafe content",
            preference_section="general",
        )
        self._verdict: t.Callable[[t.Mapping[str, t.Any]], str | None] | None = None
        self._classifier: t.Any = None
        self._fields: tuple[str, ...] = ()

    def init(self, app: "flask.Flask") -> bool:  # pylint: disable=unused-argument
        try:
            get_blocklist, get_classifier, url_fields, result_verdict = _load()
            self._classifier = get_classifier()
            hosts = len(get_blocklist())
        except Exception as exc:
            raise RuntimeError(
                f"child_safety: cannot load the safeguard package from {SAFEGUARD_ROOT} "
                "(set SAFEGUARD_ROOT): refusing to start without Layer 4"
            ) from exc
        if not hosts and os.environ.get("SAFEGUARD_ALLOW_EMPTY_BLOCKLIST") != "1":
            raise RuntimeError(
                "child_safety: the compiled blocklist is empty or missing -- run "
                "bin/refresh_blocklists.py and check SAFEGUARD_DATA"
            )
        self._verdict = result_verdict
        self._fields = tuple(url_fields) + ("title", "content")
        self.log.info("child_safety active: %d blocked hosts, lexicon v%s", hosts, self._classifier.version)
        return True

    def on_result(self, request: "SXNG_Request", search: "SearchWithPlugins", result: "Result") -> bool:
        if self._verdict is None:
            return False  # not initialised: fail closed
        reason = self._verdict(_as_mapping(result, self._fields))
        if reason:
            # category and field only -- never the query, never the URL
            self.log.debug("dropped a result: %s", reason.split(":", 2)[:2])
            return False
        return True

    def post_search(self, request: "SXNG_Request", search: "SearchWithPlugins") -> None:
        """Do not offer a suggestion or correction the guard would block."""
        if self._classifier is None:
            return None
        container = getattr(search, "result_container", None)
        for name in ("suggestions", "corrections"):
            items = getattr(container, name, None)
            if not isinstance(items, set):
                continue
            for text in list(items):
                if isinstance(text, str) and self._classifier.classify_query(text, scopes=("all", "images")).hit:
                    items.discard(text)
        return None
