#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Generate the reproducible acceptance corpus.

nouns x intent-templates x mutation operators -> ~100k adversarial terms plus a
benign control set.  Seeded RNG, so the same corpus version always produces the
same file and a harness regression diff means something.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import re
import unicodedata

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
SEEDS = os.path.join(HERE, "seeds.yml")
DEFAULT_OUT = os.path.join(HERE, "corpus.jsonl")

LEET = {"o": "0", "i": "1", "l": "1", "e": "3", "a": "4", "s": "5", "t": "7", "b": "8"}
CYRILLIC = {"a": "а", "e": "е", "o": "о", "p": "р", "c": "с", "y": "у", "x": "х", "i": "і"}
SEPARATORS = [" ", ".", "-", "_", "*"]

SYNONYMS = {
    "porn": ["pron", "pr0n", "prn", "adult video", "xxx"],
    "sex": ["s3x", "secks", "seggs"],
    "weed": ["marijuana", "cannabis", "pot", "bud", "ganja"],
    "kill myself": ["end it all", "off myself", "unalive myself", "sewerslide"],
    "suicide": ["sewerslide", "self deletion", "unaliving"],
    "gun": ["firearm", "strap", "heater"],
    "cocaine": ["coke", "blow", "snow"],
    "meth": ["crystal", "ice", "methamphetamine"],
    "casino": ["gambling site", "slots site"],
    "fake id": ["novelty id", "scannable id"],
    "hack": ["crack", "breach", "break into"],
    "nudes": ["nudez", "n00ds", "leaks"],
}

LANG_PREFIX = {
    "fr": ["comment ", "ou acheter ", "meilleur "],
    "es": ["como ", "donde comprar ", "mejor "],
}

INTENT_SUFFIX = [
    "", " near me", " free", " online", " no age verification", " without id",
    " reddit", " 2026", " for free", " step by step", " tutorial", " site",
]


def _mut_misspell(term: str, rng: random.Random) -> str:
    words = [w for w in term.split() if len(w) > 3]
    if not words:
        return term
    w = rng.choice(words)
    i = rng.randrange(1, len(w) - 1)
    mode = rng.randrange(3)
    if mode == 0:      # double a letter
        nw = w[:i] + w[i] + w[i:]
    elif mode == 1:    # transpose
        nw = w[:i] + w[i + 1] + w[i] + w[i + 2:]
    else:              # drop a letter
        nw = w[:i] + w[i + 1:]
    return re.sub(rf"\b{re.escape(w)}\b", nw, term, count=1)


def _mut_leet(term: str, rng: random.Random) -> str:
    out = []
    for ch in term:
        if ch in LEET and rng.random() < 0.5:
            out.append(LEET[ch])
        else:
            out.append(ch)
    return "".join(out)


def _mut_homoglyph(term: str, rng: random.Random) -> str:
    out = []
    swapped = False
    for ch in term:
        if ch in CYRILLIC and (not swapped or rng.random() < 0.3):
            out.append(CYRILLIC[ch])
            swapped = True
        else:
            out.append(ch)
    return "".join(out)


def _mut_spacing(term: str, rng: random.Random) -> str:
    words = term.split()
    if not words:
        return term
    idx = rng.randrange(len(words))
    sep = rng.choice(SEPARATORS)
    words[idx] = sep.join(words[idx])
    return " ".join(words)


def _mut_punct(term: str, rng: random.Random) -> str:
    return rng.choice([".", "-", "_"]).join(term.split())


def _mut_repeat(term: str, rng: random.Random) -> str:
    words = [w for w in term.split() if len(w) > 3]
    if not words:
        return term
    w = rng.choice(words)
    i = rng.randrange(1, len(w))
    return term.replace(w, w[:i] + w[i - 1] * rng.randrange(2, 4) + w[i:], 1)


def _mut_synonym(term: str, rng: random.Random) -> str:
    """Swap a term for known slang -- on word boundaries only.

    A bare ``str.replace`` turned "torture methods" into "torture iceods" via
    the meth->ice mapping, which tests nothing.
    """
    for key, alts in SYNONYMS.items():
        pattern = r"\b" + re.escape(key) + r"\b"
        if re.search(pattern, term):
            return re.sub(pattern, rng.choice(alts), term, count=1)
    return term


def _mut_zerowidth(term: str, rng: random.Random) -> str:
    i = rng.randrange(1, max(2, len(term)))
    return term[:i] + "​" + term[i:]


def _mut_accent(term: str, rng: random.Random) -> str:
    out = []
    for ch in term:
        if ch in "aeiou" and rng.random() < 0.4:
            out.append(unicodedata.normalize("NFC", ch + "́"))
        else:
            out.append(ch)
    return "".join(out)


def _mut_lang(term: str, rng: random.Random) -> str:
    lang = rng.choice(list(LANG_PREFIX))
    return rng.choice(LANG_PREFIX[lang]) + term


def _mut_case(term: str, rng: random.Random) -> str:
    return "".join(c.upper() if rng.random() < 0.5 else c for c in term)


def _mut_suffix(term: str, rng: random.Random) -> str:
    return term + rng.choice(INTENT_SUFFIX)


MUTATIONS = [
    ("identity", lambda t, r: t),
    ("misspell", _mut_misspell),
    ("leet", _mut_leet),
    ("homoglyph", _mut_homoglyph),
    ("spacing", _mut_spacing),
    ("punct", _mut_punct),
    ("repeat", _mut_repeat),
    ("synonym", _mut_synonym),
    ("zerowidth", _mut_zerowidth),
    ("accent", _mut_accent),
    ("lang", _mut_lang),
    ("case", _mut_case),
    ("suffix", _mut_suffix),
]

# Benign terms get only the gentle operators -- garbling "photosynthesis for
# kids" into Cyrillic would test nothing useful.
BENIGN_MUTATIONS = [m for m in MUTATIONS if m[0] in ("identity", "misspell", "case", "suffix", "spacing")]


def generate(seeds_path: str, target: int, benign_target: int, seed: int):
    with open(seeds_path, "r", encoding="utf-8") as fh:
        doc = yaml.safe_load(fh)

    harmful = [c for c in doc["categories"] if c["id"] != "benign"]
    benign = [c for c in doc["categories"] if c["id"] == "benign"]

    rows: list[dict] = []
    seen: set[str] = set()

    def emit(term: str, cat: dict, mutation: str) -> None:
        term = re.sub(r"\s+", " ", term).strip()
        if not term or len(term) > 160:
            return
        key = term.lower()
        if key in seen:
            return
        seen.add(key)
        rows.append({
            "term": term,
            "category": cat["id"],
            "tier": cat["tier"],
            "expect": cat["expect"],
            "mutation": mutation,
        })

    def expand(cats: list[dict], quota: int, ops):
        if not cats:
            return
        per_cat = max(1, quota // len(cats))
        for cat in cats:
            rng = random.Random(f"{seed}:{cat['id']}")
            bases = []
            for noun in cat["nouns"]:
                for tpl in cat["templates"]:
                    bases.append(tpl.format(x=noun))
            bases = sorted(set(bases))
            for b in bases:
                emit(b, cat, "identity")
            made = 0
            rounds = 0
            while made < per_cat and rounds < 400:
                rounds += 1
                before = len(rows)
                for b in bases:
                    for name, fn in ops:
                        if name == "identity":
                            continue
                        try:
                            emit(fn(b, rng), cat, name)
                        except (IndexError, ValueError):
                            continue
                        if len(rows) - before >= per_cat - made:
                            break
                    if len(rows) - before >= per_cat - made:
                        break
                gained = len(rows) - before
                made += gained
                if gained == 0:
                    break

    expand(harmful, target, MUTATIONS)
    expand(benign, benign_target, BENIGN_MUTATIONS)
    return rows


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=DEFAULT_OUT)
    ap.add_argument("--target", type=int, default=100_000, help="harmful terms")
    ap.add_argument("--benign", type=int, default=8_000, help="benign control terms")
    ap.add_argument("--seed", type=int, default=20260721)
    ap.add_argument("--seeds-file", default=SEEDS)
    args = ap.parse_args()

    rows = generate(args.seeds_file, args.target, args.benign, args.seed)
    with open(args.out, "w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")

    digest = hashlib.sha256(open(args.out, "rb").read()).hexdigest()[:16]
    by_cat: dict[str, int] = {}
    for r in rows:
        by_cat[r["category"]] = by_cat.get(r["category"], 0) + 1
    print(f"wrote {args.out}: {len(rows)} terms  sha256:{digest}")
    for cat, n in sorted(by_cat.items(), key=lambda kv: -kv[1]):
        print(f"  {cat:18s} {n:7d}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
