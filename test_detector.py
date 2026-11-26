"""Synthetic fixtures only. Runs with unittest OR pytest, no runtime downloads."""
import contextlib
import io
import json
import logging
from pathlib import Path
import socket
import tempfile
import unittest
from unittest.mock import patch
from detector import detect_text, detect_record, detect_key_or_filename

class DetectorTests(unittest.TestCase):
    def check_entity(self, text, kind, value, hint=''):
        result = detect_text(text,hint)
        self.assertTrue(any(s.entity_type == kind and s.text == value for s in result.spans), 'Expected entity missing')
        for s in result.spans:
            self.assertEqual(s.text,text[s.start:s.end])
        return result
    def test_english(self): self.check_entity('Patient: Mohammad Arif; BP 150/90','PERSON','Mohammad Arif')
    def test_bare_name(self): self.check_entity('Mohammad Arif','PERSON','Mohammad Arif')
    def test_initials(self): self.check_entity('Md. Arif','PERSON','Md. Arif')
    def test_multiple_initials(self): self.check_entity('R. K. Sharma','PERSON','R. K. Sharma')
    def test_reverse(self): self.check_entity('Sharma, Rajesh','PERSON','Sharma, Rajesh')
    def test_hindi(self): self.check_entity('मोहम्मद आरिफ','PERSON','मोहम्मद आरिफ')
    def test_hinglish(self): self.check_entity('Arif sahab ka BP 150/90 hai','PERSON','Arif')
    def test_honorific(self): self.check_entity('Meera ji ko 3 din se bukhar hai','PERSON','Meera')
    def test_hindi_honorific(self): self.check_entity('श्री निखिल कुमार जी','PERSON','निखिल कुमार')
    def test_relative(self): self.check_entity('S/o Nikhil Patil','RELATIVE','Nikhil Patil')
    def test_hindi_relative(self): self.check_entity('पिता: विनय जोशी','RELATIVE','विनय जोशी')
    def test_care_of(self): self.check_entity('C/O Ramesh Kumar','RELATIVE','Ramesh Kumar')
    def test_care_of_single(self): self.check_entity('C/O Ramesh','RELATIVE','Ramesh')
    def test_complaint(self): self.assertFalse(detect_text('C/O fever and vomiting').spans)
    def test_complaint_titlecase(self): self.assertFalse(detect_text('C/O Chest Pain').spans)
    def test_doctor(self): self.assertFalse(detect_text('Dr. Ramesh; Dr Sharma; Consultant: Dr. Verma; डॉ. वर्मा').spans)
    def test_doctor_and_relative(self):
        result = self.check_entity('Dr. Ramesh; S/o Ramesh','RELATIVE','Ramesh')
        self.assertEqual(len(result.spans),1)
        self.assertEqual(result.spans[0].start,16)
    def test_eponyms(self): self.assertFalse(detect_text("Parkinson's disease; Alzheimer's; Hodgkin's lymphoma; Bell's palsy; Graves' disease; Crohn's; Cushing's; Addison's; Down syndrome; Kawasaki; Hansen's; Pott's spine; Guillain-Barre").spans)
    def test_medications(self): self.assertFalse(detect_text('Ramipril 5 mg; Dolo 650 BD x 5 days; Tab Augmentin 625; Inj Ceftriaxone 1g IV').spans)
    def test_dosage(self): self.assertFalse(detect_text('1-0-1 0-1-0 1-1-1').spans)
    def test_vitals(self): self.assertFalse(detect_text('BP 150/90; SpO2 98%; PR 88/min; Temp 101.4 F').spans)
    def test_labs(self): self.assertFalse(detect_text('Hb 11.2 g/dL; Creatinine 1.1 mg/dL; Platelets 85000/cumm; Platelets 100000/cumm').spans)
    def test_phone(self): self.check_entity('+91 98765 43210','PHONE','+91 98765 43210')
    def test_phone_dash(self): self.check_entity('98765-43210','PHONE','98765-43210')
    def test_phone_dot(self): self.check_entity('98765.43210','PHONE','98765.43210')
    def test_phone_zero(self): self.check_entity('09876543210','PHONE','09876543210')
    def test_landline(self): self.check_entity('(0522) 2345678','PHONE','(0522) 2345678')
    def test_landline_delhi(self): self.check_entity('011-23456789','PHONE','011-23456789')
    def test_aadhaar(self): self.check_entity('Aadhaar: 2345 6789 1234','ID_AADHAAR','2345 6789 1234')
    def test_abha(self):
        r=self.check_entity('ABHA: 12-3456-7890-1234','ID_ABHA','12-3456-7890-1234')
        self.assertEqual(len(r.spans),1)
    def test_pan(self): self.check_entity('ABCDE1234F','ID_PAN','ABCDE1234F')
    def test_uhid(self): self.check_entity('UHID: HOS-12345','ID_UHID','HOS-12345')
    def test_insurance(self): self.check_entity('Insurance ID: INS-321','ID_UHID','INS-321')
    def test_email(self): self.check_entity('test.person@example.invalid','EMAIL','test.person@example.invalid')
    def test_pin(self): self.check_entity('PIN: 226001','PINCODE','226001')
    def test_bare_count(self): self.assertFalse(detect_text('100000').spans)
    def test_address(self):
        r = self.check_entity('Address: Gali 7, Lucknow 226001','PINCODE','226001')
        self.assertIn('gali 7, lucknow',r.locations)
    def test_numeric_date(self):
        r=self.check_entity('Visit 12/03/2024','DATE','12/03/2024')
        self.assertEqual(r.dates,['2024-03-12'])
    def test_iso_date(self): self.check_entity('2024-03-12','DATE','2024-03-12')
    def test_text_date(self): self.check_entity('12 Mar 2024','DATE','12 Mar 2024')
    def test_dob(self):
        r=self.check_entity('DOB: 12-03-98','DOB','12-03-98')
        self.assertEqual(r.dob,'1998-03-12')
    def test_invalid_date(self): self.assertFalse(detect_text('31/02/2024').spans)
    def test_leap_date(self): self.check_entity('29/02/2024','DATE','29/02/2024')
    def test_age(self): self.check_entity('47 yrs','AGE','47')
    def test_age_label(self): self.check_entity('Age: 47','AGE','47')
    def test_hindi_age(self): self.check_entity('आयु 47 वर्ष','AGE','47')
    def test_compact_age_gender(self):
        r=self.check_entity('47/F','AGE','47')
        self.assertEqual(r.gender,'F')
    def test_compact_no_slash(self):
        r=self.check_entity('47M','AGE','47')
        self.assertEqual(r.gender,'M')
    def test_gender(self): self.assertEqual(detect_text('महिला').gender,'F')
    def test_shifted_columns(self):
        r=detect_record({'diagnosis_misc':'Mohammad Arif','notes':'9876543210'})
        self.assertTrue(r['diagnosis_misc'].patient_names)
        self.assertTrue(r['notes'].phones)
    def test_field_hint_not_override(self): self.assertFalse(detect_text('Dolo 650','patient_name').spans)
    def test_filename(self):
        text='mohammad_arif_discharge.txt'
        spans=detect_key_or_filename(text)
        self.assertTrue(any(s.text=='mohammad_arif' for s in spans))
        self.assertTrue(all(s.text==text[s.start:s.end] for s in spans))
    def test_key_phone(self): self.assertTrue(any(s.entity_type=='PHONE' for s in detect_key_or_filename('phone_9876543210')))
    def test_normal_header(self): self.assertFalse(detect_key_or_filename('patient_name'))
    def test_determinism_overlap(self):
        text='Patient: Nikhil Patil; S/o Vinay Patil; 12-3456-7890-1234; 47/F'
        a,b=detect_text(text),detect_text(text)
        self.assertEqual(a,b)
        self.assertTrue(all(x.end<=y.start for x,y in zip(a.spans,a.spans[1:])))
    def test_nested(self):
        r=detect_record({'resourceType':'Patient','name':[{'given':['Nikhil'],'family':'Patil'}]})
        self.assertTrue(r['/name/0/given/0'].patient_names)
    def test_null(self): self.assertFalse(detect_record({'name':None})['name'].spans)
    def test_bad_type(self):
        with self.assertRaisesRegex(TypeError,'string inputs'): detect_text(['SECRET'])
    def test_cycle(self):
        data={}; data['loop']=data
        with self.assertRaisesRegex(ValueError,'Cyclic'): detect_record(data)
    def test_offline(self):
        with patch.object(socket,'socket',side_effect=AssertionError('Network forbidden')):
            self.assertTrue(detect_text('Patient: Nikhil Patil').spans)
    def test_no_logs(self):
        text='Patient: CanaryPrivatePerson UniqueSentinel; 9876543210'
        stream=io.StringIO(); handler=logging.StreamHandler(stream)
        logging.getLogger().addHandler(handler)
        try:
            with contextlib.redirect_stdout(stream), contextlib.redirect_stderr(stream):
                r=detect_text(text)
                representations=repr(r)+repr(r.spans)
            self.assertEqual(stream.getvalue(),'')
            self.assertNotIn('CanaryPrivatePerson',representations)
            self.assertNotIn('9876543210',representations)
        finally: logging.getLogger().removeHandler(handler)
    def test_policy(self):
        policy=json.loads(Path('config/policy.yaml').read_text())
        policy['enabled_ids']['PAN']=False
        with tempfile.TemporaryDirectory() as directory:
            target=Path(directory)/'policy.yaml'; target.write_text(json.dumps(policy))
            self.assertFalse(detect_text('ABCDE1234F',policy_path=str(target)).spans)
    def test_policy_failure_private(self):
        with self.assertRaisesRegex(ValueError,'^Invalid detector policy$'): detect_text('secret',policy_path='/missing/SecretName.yaml')
    def test_input_limit(self):
        with self.assertRaisesRegex(ValueError,'configured limit'): detect_text('a'*1000001)

    def test_metadata_doctor(self): self.assertFalse(detect_key_or_filename('Dr_Ramesh.txt'))
    def test_fhir_birthdate(self): self.assertEqual(detect_record({'birthDate':'1998-03-12'})['birthDate'].dob,'1998-03-12')
    def test_gender_not_inside_identifier(self): self.assertFalse(detect_text('CODE1234F').spans)
    def test_age_space_gender(self): self.assertEqual(detect_text('47 / F').gender,'F')
    def test_hindi_demographics(self):
        r=detect_text('महिला रोगी; आयु 47 वर्ष')
        self.assertEqual(r.gender,'F')
        self.assertEqual(r.age,47)
        self.assertFalse(r.patient_names)
    def test_date_separation(self):
        r=detect_text('DOB: 12/03/1998; admitted 14/04/2024')
        self.assertEqual(r.dob,'1998-03-12')
        self.assertEqual(r.dates,['2024-04-14'])
    def test_unknown_name_not_dictionary(self): self.check_entity('Patient: Zorven Talrek','PERSON','Zorven Talrek')
    def test_lowercase_labeled(self): self.check_entity('Patient: zorven talrek','PERSON','zorven talrek')
    def test_duration_not_age(self): self.assertFalse(detect_text('diabetes for 5 years; cough x 3 days').spans)
    def test_empty(self): self.assertFalse(detect_text('').spans)
    def test_flat_offsets(self): self.assertEqual(detect_record({'age':47})['age'].spans[0].text,'47')
    def test_json_pointer_escape(self):
        r=detect_record({'a/b':{'~name':'9876543210'}})
        self.assertIn('/a~1b/~0name',r)
    def test_field_hint_id(self): self.check_entity('HOS-12345','ID_UHID','HOS-12345','mrn')
    def test_no_false_phone_substring(self): self.assertFalse(detect_text('x9876543210z').spans)
    def test_invalid_age(self): self.assertFalse(detect_text('Age: 999').spans)
    def test_devanagari_phone(self): self.check_entity('९८७६५४३२१०','PHONE','९८७६५४३२१०')

if __name__=='__main__':
    unittest.main(verbosity=2)
