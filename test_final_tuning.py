"""Synthetic metadata regression cases; no benchmark identities in rules."""
import unittest
from team_processor import Processor

class MetadataPrivacyTests(unittest.TestCase):
    def test_explicit_patient_in_clinical_display(self):
        for name in ('Zorven', 'Avnira', 'अनन्या'):
            with self.subTest(name=name):
                data = {'display': 'Ward 7 bed of ' + name}
                p = Processor(b'synthetic-test')
                p.observe('f', 'doc', data)
                p.finish()
                out, _ = p.clean('f', 'doc', data)
                self.assertNotIn(name, out['display'])
                self.assertIn('Ward 7 bed of', out['display'])

    def test_clinical_display_protects_doctor_and_measurements(self):
        for value in ('Dr. Zorven Talrek', 'BP 120/80', "Parkinson disease", 'Hemoglobin'):
            with self.subTest(value=value):
                data = {'display': value}
                p = Processor(b'synthetic-test')
                p.observe('f', 'doc', data)
                p.finish()
                out, _ = p.clean('f', 'doc', data)
                self.assertEqual(out['display'], value)
