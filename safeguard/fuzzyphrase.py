# SPDX-License-Identifier: AGPL-3.0-or-later
"""Order-free, typo-tolerant phrase matching.

Regexes are brittle against a single garbled character: ``torture methods``
survives ``torture methodss`` but not ``torture methds``, and writing a regex
per misspelling does not scale.  A phrase here is a bag of tokens; it matches
when *every* token is present somewhere in the query within Damerau distance 1.

"ketamine buy", "buy ketamine" and "ketamin buy cheap" all match the phrase
``ketamine buy``.  Tokens of three characters or fewer must match exactly,
because distance-1 on a short token matches almost anything.
"""

from __future__ import annotations

import typing as t
from collections import defaultdict

from .spellfix import _damerau  # noqa: PLC2701 - shared distance implementation

__all__ = ["FuzzyPhraseIndex"]

# Tokens shorter than this must match exactly.  Three is safe *because* every
# token of a phrase has to line up: "wed"->"weed" and "iss"->"isis" resolve,
# while a lone short word can never trigger a phrase on its own.
EXACT_BELOW = 3

# A one-token phrase may match fuzzily only if it is at least this long and is
# not an ordinary English word.
FUZZY_SINGLE_MIN = 4


def _is_english(token: str) -> bool:
    from .spellfix import get_index  # noqa: PLC0415 - avoids an import cycle
    return token in get_index().dictionary


def _deletions(word: str) -> set[str]:
    return {word[:i] + word[i + 1:] for i in range(len(word))}


class FuzzyPhraseIndex:
    """Matches many phrases against a token set in one pass."""

    def __init__(self) -> None:
        self._phrases: list[tuple[str, str, frozenset[str]]] = []   # (owner, text, tokens)
        self._by_token: dict[str, set[int]] = defaultdict(set)
        self._lookup: dict[str, set[str]] = defaultdict(set)        # deletion -> phrase tokens
        self._vocab: set[str] = set()

    def add(self, owner: str, phrase: str) -> None:
        tokens = frozenset(phrase.split())
        if not tokens:
            return
        idx = len(self._phrases)
        self._phrases.append((owner, phrase, tokens))
        for tok in tokens:
            self._by_token[tok].add(idx)
            self._vocab.add(tok)
            self._lookup[tok].add(tok)
            if len(tok) >= EXACT_BELOW:
                for d in _deletions(tok):
                    self._lookup[d].add(tok)

    def __len__(self) -> int:
        return len(self._phrases)

    def _resolve(self, tokens: t.Iterable[str]) -> set[str]:
        """Map query tokens onto the phrase vocabulary, tolerating one edit."""
        found: set[str] = set()
        for tok in tokens:
            if tok in self._vocab:
                # An exact hit on one phrase's token must not stop us: the same
                # token can also be a typo of a different phrase's token.
                found.add(tok)
            if len(tok) < EXACT_BELOW:
                continue
            candidates: set[str] = set(self._lookup.get(tok, ()))
            for d in _deletions(tok):
                candidates |= self._lookup.get(d, set())
            tok_is_word = _is_english(tok)
            for cand in candidates:
                if len(cand) < EXACT_BELOW or _damerau(tok, cand, 1) > 1:
                    continue
                # Shortening one ordinary word into another is guesswork --
                # "best"->"bet" is how a books query lands in gambling.  A
                # typo that *drops* a character is far more likely than a user
                # who meant the shorter word, so only that direction is kept:
                # "bay"->"baby", "sear"->"swear" and "lie"->"life" survive.
                if tok_is_word and _is_english(cand) and len(cand) < len(tok):
                    continue
                found.add(cand)
        return found

    def match(self, tokens: t.Iterable[str], owners: t.Container[str] | None = None) -> tuple[str, str] | None:
        """Return ``(owner, phrase)`` of the first fully-covered phrase.

        A short single-token phrase must match *exactly*: distance-1 on "porn"
        also covers "corn", "born" and "pork", which is only tolerable when
        several tokens have to line up at once.  Long non-dictionary tokens
        ("soap2day", "stripchat") are distinctive enough to match fuzzily.
        """
        raw = set(tokens)
        resolved = self._resolve(raw)
        if not resolved:
            return None
        counts: dict[int, int] = defaultdict(int)
        for tok in resolved:
            for idx in self._by_token.get(tok, ()):
                counts[idx] += 1
        for idx, hits in counts.items():
            owner, phrase, phrase_tokens = self._phrases[idx]
            if hits != len(phrase_tokens):
                continue
            if owners is not None and owner not in owners:
                continue
            if len(phrase_tokens) == 1 and not (phrase_tokens & raw):
                token = next(iter(phrase_tokens))
                if len(token) < FUZZY_SINGLE_MIN:
                    continue
                # The query word it was matched from must itself be a non-word.
                # That is what stops "corn"/"born"/"pork" reaching "porn" and
                # "hamster" reaching "xhamster", while "ponr", "nueds" and
                # "henti" still resolve.
                if not any(
                    not _is_english(t)
                    # "a h a m s t e r" normalises to "ahamster", one edit from
                    # "xhamster".  An article glued onto a real word is a
                    # joining artefact, not evasion.  Narrow on purpose:
                    # "thinso" also ends in a real word ("thins") and must
                    # still resolve to "thinspo".
                    and not (t[:1] in ("a", "i") and _is_english(t[1:]))
                    and _damerau(t, token, 1) <= 1
                    for t in raw
                ):
                    continue
            return owner, phrase
        return None
