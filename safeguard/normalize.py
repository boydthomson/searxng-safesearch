# SPDX-License-Identifier: AGPL-3.0-or-later
"""Text normalisation used to defeat evasion before classification.

Produces a *set* of variants rather than a single canonical string: de-leeting
and repeat-collapsing are lossy and would mangle benign queries, so each
transform is offered as an additional candidate instead of being applied
destructively.
"""

from __future__ import annotations

import re
import unicodedata

__all__ = ["normalize", "variants", "squeeze"]

# Cyrillic / Greek / fullwidth look-alikes -> Latin.
_HOMOGLYPHS = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c",
    "у": "y", "х": "x", "і": "i", "ѕ": "s", "һ": "h",
    "А": "a", "Е": "e", "О": "o", "Р": "p", "С": "c",
    "У": "y", "Х": "x", "І": "i", "Ѕ": "s", "К": "k",
    "М": "m", "В": "b", "Н": "h", "Т": "t",
    "α": "a", "ε": "e", "ι": "i", "ο": "o", "ρ": "p",
    "υ": "u", "χ": "x", "Ο": "o", "Β": "b", "Η": "h",
    "Ι": "i", "Κ": "k", "Μ": "m", "Ν": "n", "Ρ": "p",
    "Τ": "t", "Χ": "x",
    "ӏ": "l", "ı": "i", "ł": "l", "ø": "o", "đ": "d",
    "к": "k", "м": "m", "в": "b", "н": "h", "т": "t",
    "г": "r", "п": "n", "д": "d", "и": "u", "л": "n",
    "з": "3", "б": "b", "ч": "4", "я": "r", "ф": "f",
    "ј": "j", "ԁ": "d", "ɡ": "g", "ѵ": "v", "ԝ": "w",
    "ѡ": "w", "ո": "n", "օ": "o", "ս": "u", "ɑ": "a",
}

# Zero-width / bidi / soft-hyphen noise.
_INVISIBLE = dict.fromkeys(
    [0x200B, 0x200C, 0x200D, 0x200E, 0x200F, 0x2060, 0xFEFF, 0x00AD,
     0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069]
)

_LEET_I = str.maketrans({
    "0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b",
    "@": "a", "$": "s", "!": "i", "+": "t", "|": "l",
})
# "1" stands in for both i and l ("my5e1f" -> myself, "8134ch" -> bleach),
# so both readings are offered as candidates.
_LEET_L = str.maketrans({
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b",
    "@": "a", "$": "s", "!": "i", "+": "t", "|": "l",
})

_PUNCT_RE = re.compile(r"[^a-z0-9@$!+|]+")
_WS_RE = re.compile(r"\s+")
# runs of single letters split by separators:  "p o r n", "p.o.r.n", "s-e-x"
_SPACED_LETTERS_RE = re.compile(r"\b(?:[a-z0-9][ .\-_*']+){1,}[a-z0-9]\b")
_SEPS = {ord(c): None for c in " .-_*'"}
_TRIPLE_RE = re.compile(r"(.)\1{2,}")
_DOUBLE_RE = re.compile(r"(.)\1+")


def _fold(text: str) -> str:
    """Lowercase, strip accents/invisibles, map homoglyphs."""
    text = text.translate(_INVISIBLE)
    text = "".join(_HOMOGLYPHS.get(ch, ch) for ch in text)
    text = unicodedata.normalize("NFKD", text)
    text = "".join(ch for ch in text if not unicodedata.combining(ch))
    return text.casefold()


def normalize(text: str) -> str:
    """Canonical form: folded, punctuation -> single spaces."""
    text = _fold(text)
    text = _PUNCT_RE.sub(" ", text)
    return _WS_RE.sub(" ", text).strip()


def _join_spaced_letters(text: str, keep_last: bool = False, keep_first: bool = False) -> str:
    """Collapse runs of separated single letters: "p.o.r.n" -> "porn".

    ``keep_last`` leaves the final letter of the run as its own word, because a
    run often swallows a following article: "m a k e a noose" is "make a
    noose", not "makea noose".  ``keep_first`` does the same at the front, for
    a preceding one: "a h a m s t e r" is "a hamster".  All readings are
    generated.
    """

    def repl(m: re.Match[str]) -> str:
        letters = m.group(0).translate(_SEPS)
        if len(letters) > 2:
            if keep_last:
                return letters[:-1] + " " + letters[-1]
            if keep_first:
                return letters[0] + " " + letters[1:]
        return letters

    return _SPACED_LETTERS_RE.sub(repl, text)


def squeeze(text: str) -> str:
    """All separators removed -- only ever matched against unambiguous tokens."""
    return re.sub(r"[^a-z0-9]+", "", _fold(text))


def variants(text: str) -> tuple[list[str], str]:
    """Return ``(spaced_variants, squeezed)`` for a raw query or snippet.

    ``spaced_variants`` keeps word boundaries so regexes with ``\\b`` stay
    meaningful; ``squeezed`` is the boundary-free form.
    """
    base = normalize(text)
    out = [base]

    def add(s: str) -> None:
        s = _WS_RE.sub(" ", s).strip()
        if s and s not in out:
            out.append(s)

    add(_join_spaced_letters(base))
    add(_join_spaced_letters(base, keep_last=True))
    add(_join_spaced_letters(base, keep_first=True))
    for v in list(out):
        add(v.translate(_LEET_I))
        add(v.translate(_LEET_L))
    for v in list(out):
        add(_TRIPLE_RE.sub(r"\1", v))        # aaammo -> ammo
        add(_TRIPLE_RE.sub(r"\1\1", v))      # boooobs -> boobs, killll -> kill
        add(_DOUBLE_RE.sub(r"\1", v))        # pornn -> porn (also asses -> ases)
    # strip residual leet chars that survived translate (digits inside words)
    for v in list(out):
        add(_PUNCT_RE.sub(" ", v))

    squeezed = set()
    for v in out:
        squeezed.add(v.replace(" ", ""))
    squeezed.add(squeeze(text))
    return out, " ".join(sorted(squeezed))
