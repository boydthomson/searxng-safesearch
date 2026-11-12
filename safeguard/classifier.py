# SPDX-License-Identifier: AGPL-3.0-or-later
"""Shared query/result classifier for the safe-search instance.

Used by three consumers so they can never drift apart:

* ``safeguard.proxy``            -- Layer 2, classifies the incoming query
* ``searx.plugins.child_safety`` -- Layer 4, classifies each engine result
* ``harness.run_harness``        -- the 100k acceptance test
"""

from __future__ import annotations

import os
import re
import typing as t
from dataclasses import dataclass, field
from functools import lru_cache

import yaml

from .normalize import variants, normalize
from .fuzzyphrase import FuzzyPhraseIndex
from .spellfix import correct_text, smart_deleet

__all__ = ["Category", "Verdict", "Classifier", "get_classifier"]

_HERE = os.path.dirname(os.path.abspath(__file__))
LEXICON_PATH = os.environ.get("SAFEGUARD_LEXICONS", os.path.join(_HERE, "lexicons", "categories.yml"))
PHRASES_PATH = os.environ.get("SAFEGUARD_PHRASES", os.path.join(_HERE, "lexicons", "phrases.yml"))


@dataclass
class Category:
    id: str
    tier: int
    action: str  # "crisis" | "block"
    label: str
    safe: list[re.Pattern[str]] = field(default_factory=list)
    any: list[re.Pattern[str]] = field(default_factory=list)
    combo: list[tuple[list[re.Pattern[str]], list[re.Pattern[str]]]] = field(default_factory=list)
    squeeze: list[str] = field(default_factory=list)
    fuzzy: list[str] = field(default_factory=list)
    scope: str = "all"
    """"all" everywhere, or a surface name ("images") to apply only there."""


@dataclass
class Verdict:
    hit: bool
    category: str | None = None
    tier: int | None = None
    action: str | None = None
    label: str | None = None
    reason: str = ""

    def __bool__(self) -> bool:
        return self.hit


NO_HIT = Verdict(hit=False)

# Domains whose results are never dropped by the lexicon pass (they can still be
# dropped by an explicit blocklist entry).  Keeps the benign control set green.
DEFAULT_ALLOW_SUFFIXES = (
    # wikimedia.org is deliberately absent: Commons hosts explicit anatomical
    # and nude media, so its results are scored like any other site's.
    "wikipedia.org", "wikidata.org", "wiktionary.org",
    "britannica.com", "nationalgeographic.com", "natgeokids.com",
    "khanacademy.org", "nasa.gov", "noaa.gov", "si.edu", "ushmm.org",
    "canada.ca", "gc.ca", "who.int", "cdc.gov", "nih.gov", "nhs.uk",
    "kidshelpphone.ca", "talksuicide.ca", "988.ca", "camh.ca",
    "nedic.ca", "nationaleatingdisorders.org", "heretohelp.bc.ca",
    "bbc.co.uk", "cbc.ca", "dictionary.com", "merriam-webster.com",
    "stackoverflow.com", "developer.mozilla.org", "archive.org",
    "ducksters.com", "kids.nationalgeographic.com", "coolmath4kids.com",
    "scholastic.com", "pbskids.org", "britishcouncil.org",
)


# What a ``safe`` match is replaced with.  Not a word character, so ``\b``
# still falls on either side of it, and not a letter any lexicon uses.
_MASK = " | "
_MASK_WS_RE = re.compile(r"\s+")


def _compile(patterns: t.Iterable[str]) -> list[re.Pattern[str]]:
    return [re.compile(p) for p in patterns]


class Classifier:
    def __init__(self, path: str = LEXICON_PATH) -> None:
        with open(path, "r", encoding="utf-8") as fh:
            doc = yaml.safe_load(fh)
        self.version = doc.get("version", 0)
        self.categories: list[Category] = []
        for raw in doc["categories"]:
            self.categories.append(
                Category(
                    id=raw["id"],
                    tier=int(raw["tier"]),
                    action=raw.get("action", "block"),
                    label=raw.get("label", raw["id"]),
                    safe=_compile(raw.get("safe") or []),
                    any=_compile(raw.get("any") or []),
                    combo=[
                        (_compile(c.get("verbs") or []), _compile(c.get("nouns") or []))
                        for c in (raw.get("combo") or [])
                    ],
                    squeeze=[str(s).lower() for s in (raw.get("squeeze") or [])],
                    fuzzy=[str(s).lower().strip() for s in (raw.get("fuzzy") or [])],
                    scope=str(raw.get("scope", "all")),
                )
            )
        # crisis categories first, then tier, so the most protective wins ties
        self.categories.sort(key=lambda c: (c.action != "crisis", c.tier))
        self.by_id = {c.id: c for c in self.categories}

        self.phrases = FuzzyPhraseIndex()
        for cat in self.categories:
            for phrase in cat.fuzzy:
                self.phrases.add(cat.id, phrase)
        if os.path.exists(PHRASES_PATH):
            with open(PHRASES_PATH, "r", encoding="utf-8") as fh:
                for cat_id, phrases in (yaml.safe_load(fh) or {}).items():
                    if cat_id not in self.by_id:
                        continue
                    for phrase in phrases or []:
                        self.phrases.add(cat_id, str(phrase).lower())

    # ------------------------------------------------------------------ core
    @staticmethod
    def _masked(cat: Category, forms: list[str]) -> list[str] | None:
        """``forms`` with every ``safe`` match cut out, or ``None`` if none matched.

        A ``safe`` pattern excuses the words it matches and nothing else.  It
        used to veto the whole category for the whole query, so tacking a safe
        phrase onto anything ("... sex education", "... suicide squad",
        "... minecraft") switched the category off, crisis page included.  Now
        the safe span is removed and whatever is left is classified as usual:
        "sex education" leaves nothing and passes, "porn sex education" leaves
        "porn" and is blocked.
        """
        out: list[str] = []
        for f in forms:
            hit = False
            for rx in cat.safe:
                f, n = rx.subn(_MASK, f)
                hit = hit or bool(n)
            if not hit:
                # ``forms`` are spellings of one query.  Where the safe phrase
                # is recognisable only after normalisation ("sex chromsomes",
                # "w_e_e_d_s"), the raw spelling still holds the excused words
                # unmasked; judging it would undo the excuse.  The rest of the
                # query is present in the masked spellings too.
                continue
            f = _MASK_WS_RE.sub(" ", f).strip()
            if f not in out:
                out.append(f)
        return out or None

    def _match(self, cat: Category, forms: list[str], squeezed: str) -> str | None:
        for rx in cat.any:
            for f in forms:
                if rx.search(f):
                    return f"any:{rx.pattern}"
        for verbs, nouns in cat.combo:
            if any(v.search(f) for v in verbs for f in forms) and any(
                n.search(f) for n in nouns for f in forms
            ):
                return "combo"
        for tok in cat.squeeze:
            if tok in squeezed:
                return f"squeeze:{tok}"
        return None

    def classify_text(
        self,
        text: str,
        only: t.Container[str] | None = None,
        scopes: t.Container[str] = ("all",),
    ) -> Verdict:
        if not text or not text.strip():
            return NO_HIT
        forms, squeezed = variants(text)
        extra = " "
        for f in list(forms):
            for fixed in (smart_deleet(f), correct_text(f)):
                if fixed and fixed not in forms:
                    forms.append(fixed)
                    extra += fixed.replace(" ", "") + " "
        for f in list(forms):
            fixed = correct_text(f)
            if fixed and fixed not in forms:
                forms.append(fixed)
                extra += fixed.replace(" ", "") + " "
        squeezed += extra

        # Categories with a ``safe`` match are judged on what is left of the
        # query once the safe spans are removed (see ``_masked``).
        masked: dict[str, list[str]] = {}
        for cat in self.categories:
            if only is not None and cat.id not in only:
                continue
            if cat.scope not in scopes:
                continue
            rest = self._masked(cat, forms)
            if rest is None:
                reason = self._match(cat, forms, squeezed)
            else:
                masked[cat.id] = rest
                # the mask is kept in the squeezed form so that the words on
                # either side of a removed span cannot fuse into a new token
                reason = self._match(cat, rest, " ".join(f.replace(" ", "") for f in rest))
            if reason:
                return Verdict(True, cat.id, cat.tier, cat.action, cat.label, reason)

        # Typo-tolerant second pass over the phrase lexicons.
        tokens: set[str] = set()
        for f in forms:
            tokens.update(f.split())
        wanted = {c.id for c in self.categories
                  if c.id not in masked and c.scope in scopes
                  and (only is None or c.id in only)}
        hit = self.phrases.match(tokens, owners=wanted)
        if not hit:
            for cat in self.categories:
                if cat.id not in masked:
                    continue
                rest_tokens: set[str] = set()
                for f in masked[cat.id]:
                    rest_tokens.update(tok for tok in f.split() if tok != _MASK.strip())
                hit = self.phrases.match(rest_tokens, owners={cat.id})
                if hit:
                    break
        if hit:
            cat = self.by_id[hit[0]]
            return Verdict(True, cat.id, cat.tier, cat.action, cat.label, f"fuzzy:{hit[1]}")
        return NO_HIT

    # ----------------------------------------------------------- public API
    def classify_query(self, query: str, scopes: t.Container[str] = ("all",)) -> Verdict:
        """Layer 2: what to do with an incoming search query.

        ``scopes`` widens the lexicon for higher-risk surfaces: an image search
        also evaluates the ``images`` categories, because a thumbnail grid puts
        a single miss straight in front of the child with no snippet to soften
        it, and terms that are merely awkward in text results are not
        acceptable as pictures.
        """
        return self.classify_text(query, scopes=scopes)

    def classify_result(
        self,
        url: str = "",
        title: str = "",
        content: str = "",
        allow_suffixes: t.Sequence[str] = DEFAULT_ALLOW_SUFFIXES,
    ) -> Verdict:
        """Layer 4: should this engine result be dropped?

        ``crisis`` categories are *not* applied to results -- a page about
        suicide prevention must not be flagged just for containing the word.
        Only ``block`` categories drop a result.
        """
        host = host_of(url)
        if host and any(host == s or host.endswith("." + s) for s in allow_suffixes):
            return NO_HIT
        blockable = {c.id for c in self.categories if c.action == "block"}
        # URL path text is a strong signal; join with spaces so words separate.
        url_text = re.sub(r"[^a-zA-Z0-9]+", " ", url)
        for field_name, text in (("url", url_text), ("title", title), ("content", content)):
            v = self.classify_text(text, only=blockable)
            if v.hit:
                v.reason = f"{field_name}/{v.reason}"
                return v
        return NO_HIT


def host_of(url: str) -> str:
    m = re.match(r"^[a-z][a-z0-9+.\-]*://([^/?#]+)", url or "", re.I)
    if not m:
        return ""
    host = m.group(1).rsplit("@", 1)[-1]
    host = host.split(":")[0].strip().rstrip(".").lower()
    return host


@lru_cache(maxsize=1)
def get_classifier(path: str = LEXICON_PATH) -> Classifier:
    return Classifier(path)


# Convenience re-export for callers that only need normalisation.
normalize_query = normalize
