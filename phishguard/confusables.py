"""Unicode confusable folding for homograph / IDN phishing."""

from __future__ import annotations

import unicodedata

# Common lookalikes folded to ASCII. Incomplete by design: we also flag mixed scripts.
CONFUSABLE_MAP: dict[str, str] = {
    # Cyrillic
    "а": "a",
    "е": "e",
    "о": "o",
    "р": "p",
    "с": "c",
    "у": "y",
    "х": "x",
    "і": "i",
    "ј": "j",
    "ѕ": "s",
    "ԁ": "d",
    "ԛ": "q",
    "ԝ": "w",
    "һ": "h",
    "ѵ": "v",
    "ѡ": "w",
    "ᴦ": "r",
    "ᴨ": "n",
    "ᴩ": "p",
    "ᴛ": "t",
    "ᴜ": "u",
    "ᴠ": "v",
    "ᴡ": "w",
    "ᴢ": "z",
    "А": "a",
    "В": "b",
    "Е": "e",
    "К": "k",
    "М": "m",
    "Н": "h",
    "О": "o",
    "Р": "p",
    "С": "c",
    "Т": "t",
    "Х": "x",
    "Ь": "b",
    # Greek
    "α": "a",
    "ο": "o",
    "ν": "v",
    "ρ": "p",
    "τ": "t",
    "υ": "u",
    "ι": "i",
    "κ": "k",
    "η": "n",
    "ω": "w",
    "χ": "x",
    "γ": "y",
    "μ": "u",
    "Α": "a",
    "Β": "b",
    "Ε": "e",
    "Ζ": "z",
    "Η": "h",
    "Ι": "i",
    "Κ": "k",
    "Μ": "m",
    "Ν": "n",
    "Ο": "o",
    "Ρ": "p",
    "Τ": "t",
    "Υ": "y",
    "Χ": "x",
    # Latin lookalikes / fullwidth
    "а": "a",
    "е": "e",
    "ⅰ": "i",
    "ⅼ": "l",
    "ⅼ": "l",
    "ℓ": "l",
    "Ⅰ": "i",
    "０": "0",
    "１": "1",
    "３": "3",
    "４": "4",
    "５": "5",
    "６": "6",
    "７": "7",
    "８": "8",
    "９": "9",
    "а": "a",
    "＠": "@",
    "．": ".",
    "‐": "-",
    "‑": "-",
    "‒": "-",
    "–": "-",
    "—": "-",
    "−": "-",
    "ı": "i",
    "ı": "i",
    "ɒ": "a",
    "ɛ": "e",
    "ɡ": "g",
    "ɪ": "i",
    "ɴ": "n",
    "ʀ": "r",
    "ʏ": "y",
    "ʙ": "b",
    "ʜ": "h",
    "ʟ": "l",
    "ᴀ": "a",
    "ᴄ": "c",
    "ᴅ": "d",
    "ᴇ": "e",
    "ᴊ": "j",
    "ᴋ": "k",
    "ᴍ": "m",
    "ᴏ": "o",
    "ᴘ": "p",
    "ᴙ": "r",
    "ᴢ": "z",
    "𝟎": "0",
    "𝟏": "1",
    "𝟓": "5",
    "８": "8",
    "𝟎": "0",
    "Ο": "o",
    "ο": "o",
    "О": "o",
    "о": "o",
    "ℓ": "l",
    "Ꮟ": "b",
    "Ꭵ": "i",
    "Ꮒ": "h",
    "Ꮞ": "e",
    "Ꮢ": "r",
    "Ꮪ": "s",
    "Ꮤ": "w",
    "Ꮥ": "s",
    "Ꮧ": "b",
    "Ꮩ": "v",
    "Ꭺ": "a",
    "Ᏼ": "b",
    "Ꮯ": "c",
    "Ꭰ": "d",
    "Ꭼ": "e",
    "Ꮋ": "h",
    "Ꭻ": "j",
    "Ꮶ": "k",
    "Ꮮ": "l",
    "Ꮇ": "m",
    "Ꮑ": "n",
    "Ꮎ": "o",
    "Ꮲ": "p",
    "Ꮕ": "q",
    "Ꭱ": "r",
    "Ꮪ": "s",
    "Ꭲ": "t",
    "Ꮜ": "u",
    "Ꮩ": "v",
    "Ꮃ": "w",
    "Ꮖ": "x",
    "Ꮍ": "y",
    "Ꮓ": "z",
}


def fold_confusables(text: str) -> str:
    text = unicodedata.normalize("NFKC", text)
    return "".join(CONFUSABLE_MAP.get(ch, ch) for ch in text).lower()


def scripts_in(text: str) -> set[str]:
    scripts: set[str] = set()
    for ch in text:
        if not ch.isalpha():
            continue
        try:
            name = unicodedata.name(ch)
        except ValueError:
            continue
        scripts.add(name.split()[0])
    return scripts


def has_mixed_scripts(text: str) -> bool:
    scripts = scripts_in(text)
    latinish = {"LATIN", "COMMON", "INHERITED"}
    interesting = {s for s in scripts if s not in latinish}
    if "LATIN" in scripts and interesting:
        return True
    return len(interesting) > 1


def has_invisible(text: str) -> bool:
    for ch in text:
        if unicodedata.category(ch) in {"Cf", "Cc"} and ch not in {"\n", "\t"}:
            return True
        if ch in {"\u200b", "\u200c", "\u200d", "\ufeff", "\u2060", "\u202e", "\u202d"}:
            return True
    return False
