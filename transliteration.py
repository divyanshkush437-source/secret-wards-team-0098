"""Library-backed Devanagari transliteration with stable Hindi matching spelling.

indic-transliteration owns the script alphabet. The adapter retains word-final
schwa handling and the previous Roman spelling so existing linkage keys stay stable.
"""
from functools import lru_cache
import unicodedata
from indic_transliteration import sanscript

_SCHEME = sanscript.SCHEMES[sanscript.DEVANAGARI]
_VOWELS = set(_SCHEME['vowels'].values())
_MATRAS = set(_SCHEME['vowel_marks'].values())
_CONSONANTS = {unicodedata.normalize('NFC', c) for group in ('consonants', 'extra_consonants')
               for c in _SCHEME[group].values()}
_NUKTA_BASE = {c[0]: c for c in _CONSONANTS if len(c) == 2 and c[1] == '़'}
_VIRAMA, _NUKTA, _ANUSVARA, _CHANDRABINDU, _VISARGA = '्', '़', 'ं', 'ँ', 'ः'
# ITRANS does not render these Hindi candra vowels consistently in the pinned release.
_CANDRA = {'ॅ': 'e', 'ॉ': 'o', 'ऍ': 'e', 'ऑ': 'o'}


def _matching_roman(value):
    # Roman scheme adaptation, not a second Devanagari alphabet.
    for source, target in (('.Dh', 'rh'), ('.D', 'r'), ('RRi', 'ri'), ('RRI', 'rii'),
                           ('LLi', 'li'), ('LLI', 'lii'), ('~N', 'n'), ('~n', 'n'),
                           ('.N', 'n'), ('Ch', 'chh'), ('Sh', 'sh')):
        value = value.replace(source, target)
    return value.translate(str.maketrans({'A': 'aa', 'I': 'ee', 'U': 'oo', 'K': 'kh',
        'G': 'g', 'M': 'n', 'H': 'h', 'L': 'l', 'T': 't', 'D': 'd', 'N': 'n', 'Y': 'y', 'R': 'r'}))


@lru_cache(maxsize=256)
def _letter(char, consonant=False):
    if char in _CANDRA:
        return _CANDRA[char]
    if char in _MATRAS:
        roman = sanscript.transliterate('क' + char, sanscript.DEVANAGARI, sanscript.ITRANS)[1:]
    else:
        roman = sanscript.transliterate(char + (_VIRAMA if consonant else ''),
                                       sanscript.DEVANAGARI, sanscript.ITRANS)
    return _matching_roman(roman)


def transliterate(text):
    """Convert script using the library; preserve Latin, punctuation and offsets' order."""
    text = unicodedata.normalize('NFC', text)
    out, i, n = [], 0, len(text)
    while i < n:
        char = text[i]
        if char in _CONSONANTS or char in _NUKTA_BASE:
            if i + 1 < n and text[i + 1] == _NUKTA and char in _NUKTA_BASE:
                char = _NUKTA_BASE[char]
                i += 1
            out.append(_letter(char, True))
            nxt = text[i + 1] if i + 1 < n else ''
            if nxt == _VIRAMA:
                i += 2
                continue
            if nxt in _MATRAS:
                out.append(_letter(nxt))
                i += 2
                continue
            word_end = not (nxt and ('ऀ' <= nxt <= 'ॿ') and nxt not in (_ANUSVARA, _CHANDRABINDU, _VISARGA))
            conjunct = i >= 1 and text[i - 1] == _VIRAMA
            if not word_end or conjunct or nxt in (_ANUSVARA, _CHANDRABINDU):
                out.append('a')
            i += 1
            continue
        if char in _VOWELS or char in _MATRAS:
            out.append(_letter(char))
        elif char in (_ANUSVARA, _CHANDRABINDU):
            out.append('n')
        elif char == _VISARGA:
            out.append('h')
        elif '०' <= char <= '९':
            out.append(str(unicodedata.decimal(char)))
        elif char not in (_VIRAMA, _NUKTA, '‌', '‍'):
            out.append(char)
        i += 1
    return ''.join(out)
