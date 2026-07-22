# SPDX-License-Identifier: AGPL-3.0-or-later
"""Edit-distance-1 correction toward the harmful-term vocabulary.

``pormhub``, ``pron``, ``kiill myself`` and friends have to resolve to the term
they are imitating before the lexicons ever see them.  A SymSpell-style
deletion index gives distance-1 matching (substitution, insertion, deletion,
transposition) in constant time per token.

A token that is itself a real English word is never corrected, so ``sax``,
``sox``, ``pond`` and ``bill`` stay put.
"""

from __future__ import annotations

import os
import typing as t
from functools import lru_cache

__all__ = ["correct_text", "smart_deleet", "get_index"]

_HERE = os.path.dirname(os.path.abspath(__file__))
VOCAB_PATH = os.environ.get("SAFEGUARD_FUZZY_VOCAB", os.path.join(_HERE, "lexicons", "fuzzy_vocab.txt"))
DICT_PATH = os.environ.get("SAFEGUARD_WORDLIST", "/usr/share/dict/words")

MIN_LEN = 3
_ALPHA = "abcdefghijklmnopqrstuvwxyz"

# "1" reads as either i or l, so a token-by-token choice is needed: "cr1m3
# sc3n3 ph0tos r3a1" is crime/scene/photos/real, which no single whole-string
# substitution produces.
_LEET_ALT = {"1": ("i", "l"), "0": ("o",), "3": ("e",), "4": ("a",), "5": ("s",),
             "7": ("t",), "8": ("b",), "@": ("a",), "$": ("s",), "!": ("i",),
             "+": ("t",), "|": ("l", "i")}


def _deletions(word: str) -> set[str]:
    return {word[:i] + word[i + 1:] for i in range(len(word))}


def _damerau(a: str, b: str, limit: int = 2) -> int:
    """Damerau-Levenshtein distance, giving up once it exceeds ``limit``."""
    if abs(len(a) - len(b)) > limit:
        return limit + 1
    prev2: list[int] = []
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            if i > 1 and j > 1 and ca == b[j - 2] and a[i - 2] == cb:
                cur[j] = min(cur[j], prev2[j - 2] + 1)
        if min(cur) > limit:
            return limit + 1
        prev2, prev = prev, cur
    return prev[len(b)]


def _prefix_len(a: str, b: str) -> int:
    n = 0
    for ca, cb in zip(a, b):
        if ca != cb:
            break
        n += 1
    return n


class SpellFix:
    def __init__(self, vocab_path: str = VOCAB_PATH, dict_path: str = DICT_PATH) -> None:
        self.vocab: set[str] = set()
        if os.path.exists(vocab_path):
            with open(vocab_path, "r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.split("#")[0].strip().lower()
                    if len(line) >= MIN_LEN and line.isalpha():
                        self.vocab.add(line)

        self.index: dict[str, set[str]] = {}
        for word in self.vocab:
            self.index.setdefault(word, set()).add(word)
            for d in _deletions(word):
                self.index.setdefault(d, set()).add(word)

        # Real words are never "corrected" into a harmful term.
        self.english: set[str] = set()
        if os.path.exists(dict_path):
            with open(dict_path, "r", encoding="utf-8", errors="ignore") as fh:
                for line in fh:
                    w = line.strip().lower()
                    if w.isalpha() and len(w) >= MIN_LEN:
                        self.english.add(w)
        # `english` drives correction (a vocab word is never "corrected"), while
        # `dictionary` answers "is this an ordinary word?" and must keep terms
        # like "bet" and "hamster" that also appear in the harmful vocabulary.
        self.dictionary: set[str] = set(self.english)
        self.english -= self.vocab
        self._cache: dict[str, str] = {}

    def is_word(self, token: str) -> bool:
        return token in self.vocab or token in self.english

    def deleet_token(self, token: str) -> str:
        """Pick the de-leeted reading of one token that yields a real word."""
        if len(token) == 1:
            # a lone leet glyph is a word: "500 calorie 4 day" -> "a day"
            return _LEET_ALT.get(token, (token,))[0]
        if token.isdigit() or not any(c in _LEET_ALT for c in token):
            return token
        if self.is_word(token):
            return token
        candidates = [""]
        for ch in token:
            alts = _LEET_ALT.get(ch, (ch,))
            if len(candidates) * len(alts) > 64:      # runaway guard
                alts = alts[:1]
            candidates = [c + a for c in candidates for a in alts]
        for cand in candidates:
            if self.is_word(cand):
                return cand
        for cand in candidates:
            fixed = self.correct_token(cand)
            if fixed != cand:
                return fixed
        return candidates[0]

    def smart_deleet(self, text: str) -> str:
        out = [self.deleet_token(tok) for tok in text.split()]
        return " ".join(out)

    def correct_token(self, token: str) -> str:
        cached = self._cache.get(token)
        if cached is not None:
            return cached
        result = self._correct_token(token)
        if len(self._cache) < 500_000:
            self._cache[token] = result
        return result

    def _neighbours(self, token: str) -> t.Iterator[str]:
        for i in range(len(token)):
            yield token[:i] + token[i + 1:]
            for c in _ALPHA:
                yield token[:i] + c + token[i + 1:]
        for i in range(len(token) + 1):
            for c in _ALPHA:
                yield token[:i] + c + token[i:]
        for i in range(len(token) - 1):
            yield token[:i] + token[i + 1] + token[i] + token[i + 2:]

    def _has_english_neighbour(self, token: str) -> bool:
        return any(n in self.english for n in self._neighbours(token))

    def _correct_token(self, token: str) -> str:
        if len(token) < MIN_LEN or not token.isalpha():
            return token
        if token in self.vocab or token in self.english:
            return token
        candidates = set(self.index.get(token, ()))
        for d in _deletions(token):
            candidates |= self.index.get(d, set())
        scored = []
        for c in candidates:
            dist = _damerau(token, c)
            if dist <= 1:
                scored.append((dist, -_prefix_len(token, c), -len(c), c))
        if not scored:
            return token
        # An ordinary word one edit away means the intent is ambiguous:
        # "rie" is as close to "ride" as to "die", so leave it alone and let
        # the phrase matcher decide with more context.
        if self._has_english_neighbour(token):
            return token
        # true edit distance first, then shared prefix, then the longer (more
        # specific) term -- ties biased toward blocking, which is the safe side
        return min(scored)[3]

    def correct_text(self, text: str) -> str:
        changed = False
        out = []
        for token in text.split():
            fixed = self.correct_token(token)
            changed = changed or fixed != token
            out.append(fixed)
        return " ".join(out) if changed else text


@lru_cache(maxsize=1)
def get_index(vocab_path: str = VOCAB_PATH, dict_path: str = DICT_PATH) -> SpellFix:
    return SpellFix(vocab_path, dict_path)


def correct_text(text: str) -> str:
    return get_index().correct_text(text)


def smart_deleet(text: str) -> str:
    return get_index().smart_deleet(text)
