"""Behavioral regression tests for the required offline libraries."""
import unittest
from detector import detect_text
from detector.phone_numbers import normalize_phone
from team_processor import Processor
from transliteration import transliterate


class PhoneLibraryTests(unittest.TestCase):
    def test_grouping_prefix_unicode_and_extension(self):
        forms = ['+91 98765 43210', '098-765-43210', '(987) 654 3210',
                 '91 98765 43210', '०९८७६५४३२१०', '+91 98765 43210 ext. 123']
        for value in forms:
            with self.subTest(value=value):
                spans = [s for s in detect_text('Phone: ' + value).spans if s.entity_type == 'PHONE']
                self.assertEqual([(s.text, s.normalized) for s in spans], [(value, '+919876543210')])
                self.assertEqual(normalize_phone(value), '+919876543210')

    def test_international_numbers(self):
        for value, expected in [('+44 20 8366 1177', '+442083661177'),
                                ('+1 (650) 253-0000', '+16502530000')]:
            with self.subTest(value=value):
                phones = [s for s in detect_text('Phone: ' + value).spans if s.entity_type == 'PHONE']
                self.assertEqual([s.normalized for s in phones], [expected])

    def test_clinical_counts_dates_pins_and_ids_are_not_phones(self):
        for value in ['100000', 'PIN: 226001', 'Date: 2026-05-15', 'Dose 1-0-1',
                      'x9876543210z', 'Specimen 9876543210']:
            with self.subTest(value=value):
                self.assertFalse(any(s.entity_type == 'PHONE' for s in detect_text(value).spans))


class TransliterationLibraryTests(unittest.TestCase):
    def test_existing_matching_spelling_is_preserved(self):
        for value, expected in [('राम', 'raam'), ('आदित्य', 'aaditya'),
                                ('ज़ैनब', 'zainab'), ('फ़ातिमा', 'faatimaa'),
                                ('रोगी १२३', 'rogee 123')]:
            with self.subTest(value=value):
                self.assertEqual(transliterate(value), expected)

    def test_new_phone_format_and_hindi_name_link_to_same_patient(self):
        p = Processor(b'synthetic-library-test')
        rows = [dict(Name='Ananya Batra', Phone='+91 98765 43210'),
                dict(Name='अनन्या बत्रा', Phone='(987) 654 3210')]
        for i, row in enumerate(rows):
            p.observe('f', 'row:' + str(i), row)
        p.finish()
        ids = [p.clean('f', 'row:' + str(i), row)[1] for i, row in enumerate(rows)]
        self.assertIsNotNone(ids[0])
        self.assertEqual(ids[0], ids[1])


if __name__ == '__main__':
    unittest.main()
