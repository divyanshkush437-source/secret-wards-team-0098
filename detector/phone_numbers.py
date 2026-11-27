"""Offline phone recognition and E.164 identity keys using libphonenumber metadata."""
import phonenumbers


def _usable(number):
    # Local-only 6–8 digit candidates collide with PINs, dates and lab counts.
    # Indian identity keys require the complete ten-digit national number.
    if number.country_code == 91 and len(phonenumbers.national_significant_number(number)) != 10:
        return False
    return phonenumbers.is_possible_number(number)


def normalize_phone(text):
    try:
        number = phonenumbers.parse(text, 'IN')
    except phonenumbers.NumberParseException:
        return None
    if not _usable(number):
        return None
    # Extensions belong to the displayed contact, not the underlying phone identity.
    return phonenumbers.format_number(number, phonenumbers.PhoneNumberFormat.E164)


def phone_spans(text):
    # POSSIBLE deliberately retains fictional but correctly-sized test numbers.
    for match in phonenumbers.PhoneNumberMatcher(text, 'IN', leniency=phonenumbers.Leniency.POSSIBLE):
        if not _usable(match.number):
            continue
        start, end = match.start, match.end
        # The permissive matcher otherwise accepts substrings of IDs / words.
        if start and (text[start - 1].isalnum() or text[start - 1] == '_'):
            continue
        if end < len(text) and (text[end].isalnum() or text[end] == '_'):
            continue
        yield start, end, phonenumbers.format_number(match.number, phonenumbers.PhoneNumberFormat.E164)
