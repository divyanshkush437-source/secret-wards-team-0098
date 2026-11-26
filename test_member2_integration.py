"""Synthetic regression fixtures; no practice names or truth in runtime code."""
import base64
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from detector import detect_text
from main import run
from member2_processor import Processor

class MemberTwoIntegrationTests(unittest.TestCase):
    def processor(self,*records):
        p=Processor(b'synthetic-test-key')
        for data in records:p.observe('internal','doc',data)
        p.finish()
        return p

    def test_historical_duration(self): self.assertFalse(detect_text('H/O TB 9 yrs back').age)
    def test_possessive_patient(self): self.assertEqual(detect_text("Zorven's attendant").patient_names,['zorven'])
    def test_unseen_hinglish(self): self.assertEqual(detect_text('Zorven ka BP 120/80').patient_names,['zorven'])
    def test_hindi_complaint(self): self.assertFalse(detect_text('C/O दस्त और उल्टी').spans)
    def test_history_codes(self):
        for text in ('K/C/O: I10','K/C/O A01.0','K/C/O: E03.9'):
            self.assertFalse(detect_text(text).spans)
    def test_name_does_not_consume_code_prefix(self):
        self.assertFalse(detect_text('C/O: I10').relative_names)
    def test_transliterated_address_labels(self):
        for key in ('Gaon','Pata'):
            self.assertTrue(detect_text('Synthetic Nagar',key).locations)
    def test_legacy_labels(self):
        for label,value,kind in [('FirstName','Zorven','PERSON'),('LastName','Talrek','PERSON'),('PatientID','HOS-987654','ID_UHID'),('Zip','226001','PINCODE'),('Street','House 12','LOCATION')]:
            self.assertTrue(any(s.entity_type==kind for s in detect_text(value,label).spans))
    def test_month_first(self): self.assertEqual(detect_text('04/20/1979','DOB (MM/DD/YYYY)').dob,'1979-04-20')
    def test_month_first_ambiguous(self): self.assertEqual(detect_text('04/03/1979','DOB (MM/DD/YYYY)').dob,'1979-04-03')
    def test_masked_identifier(self): self.assertEqual(detect_text('XXXX XXXX 1234').spans[0].entity_type,'ID_AADHAAR')
    def test_compact_identifier(self): self.assertEqual(detect_text('HOS2026-123456').spans[0].entity_type,'ID_UHID')
    def test_insurance_field(self): self.assertEqual(detect_text('POL/33/87654321','policy_no').spans[0].entity_type,'ID_UHID')
    def test_structured_id_without_label(self): self.assertTrue(detect_text('HOS/26/123456').ids)
    def test_hinglish_extra_honorific(self): self.assertEqual(detect_text('Zorven behenji ka BP 120/80').patient_names,['zorven'])
    def test_complaints(self):
        for value in ['C/O loose stools x 9 days','K/C/O hypothyroidism','C/O generalised weakness x 9 weeks']:
            self.assertFalse(detect_text(value).spans)
    def test_no_linkage_claims(self):
        p=self.processor({'patient_name':'Zorven Talrek'})
        out,patient=p.clean('internal','doc',{'patient_name':'Zorven Talrek','dob':'1990-03-12','age':47})
        self.assertIsNone(patient)
        self.assertEqual(out['dob'],'1990-03-12')
        self.assertEqual(out['age'],47)
        self.assertNotIn('Zorven',out['patient_name'])
    def test_learned_name_protect_doctor(self):
        p=self.processor({'patient_name':'Zorven Talrek'})
        out,_=p.clean('internal','doc','Zorven Talrek; Dr. Zorven Talrek (MS Surgery)')
        self.assertEqual(out,'[PERSON]; Dr. Zorven Talrek (MS Surgery)')
    def test_clinical_dictionary_from_input(self):
        p=self.processor({'diagnosis':'Essential Hypertension','drug':'Dolo 650'})
        text='Essential Hypertension; Dolo 650 BD x 5 days; BP 150/90'
        self.assertEqual(p.clean('internal','doc',text)[0],text)
    def test_numeric_identifier_type(self):
        data={'aadhar_no':234567891234,'platelets':100000}
        p=self.processor(data); out,_=p.clean('internal','doc',data)
        self.assertIs(type(out['aadhar_no']),int)
        self.assertEqual(out['aadhar_no'],0)
        self.assertEqual(out['platelets'],100000)
    def test_attachment_cleaned_in_memory(self):
        data={'attachment':{'contentType':'text/plain','data':base64.b64encode(b'Patient: Zorven Talrek; Dolo 650').decode()}}
        p=self.processor(data); out,_=p.clean('internal','doc',data)
        decoded=base64.b64decode(out['attachment']['data']).decode()
        self.assertNotIn('Zorven',decoded);self.assertIn('Dolo 650',decoded)
    def test_bad_attachment_stops(self):
        p=self.processor()
        with self.assertRaisesRegex(ValueError,'^Unsupported encoded attachment$'):
            p.clean('internal','doc',{'contentType':'text/plain','data':'!!private!!'})
    def test_source_path_removed(self):
        p=self.processor();out,_=p.clean('internal','doc',{'source_path':'D:/private/123456/export.json'})
        self.assertEqual(out['source_path'],'[SOURCE_PATH]')
    def test_keys_stable_across_rows(self):
        first={'notes_Zorven_Talrek':'Dolo 650'}; second={'notes_Zorven_Talrek':'BP 150/90'}
        p=self.processor({'patient_name':'Zorven Talrek'},first,second)
        a,_=p.clean('internal','row:0',first);b,_=p.clean('internal','row:1',second)
        self.assertEqual(list(a),list(b));self.assertNotIn('Zorven',next(iter(a)))
    def test_fhir_role_and_references(self):
        data={'resourceType':'Bundle','entry':[
            {'fullUrl':'urn:uuid:abc','resource':{'resourceType':'Patient','id':'abc','name':[{'given':['Zorven'],'family':'Talrek'}]}},
            {'resource':{'resourceType':'Practitioner','name':[{'given':['Zorven'],'family':'Talrek'}]}},
            {'resource':{'resourceType':'Observation','subject':{'reference':'urn:uuid:abc','display':'Zorven Talrek'},'valueQuantity':{'value':11.2,'unit':'g/dL'}}}]}
        p=self.processor(data);out,_=p.clean('internal','doc',data)
        self.assertNotIn('Zorven',json.dumps(out['entry'][0]))
        self.assertEqual(out['entry'][1],data['entry'][1])
        self.assertEqual(out['entry'][2]['resource']['subject']['reference'],'urn:uuid:abc')
        self.assertEqual(out['entry'][2]['resource']['valueQuantity'],data['entry'][2]['resource']['valueQuantity'])
    def test_silent(self):
        stream=io.StringIO()
        with contextlib.redirect_stdout(stream),contextlib.redirect_stderr(stream):
            p=self.processor({'patient_name':'CanarySynthetic UniqueTest'})
            p.clean('internal','doc',{'patient_name':'CanarySynthetic UniqueTest'})
        self.assertEqual(stream.getvalue(),'')
    def test_two_pass_file_roundtrip(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)/'input';root.mkdir()
            (root/'rows.csv').write_text('patient_name,notes\nZorven Talrek,Dolo 650\n',encoding='utf-8')
            (root/'visit.json').write_text(json.dumps({'visits':[{'patient_name':'Zorven Talrek','notes':'BP 150/90'}]}))
            for n in (1,2):
                run(root,Path(folder)/str(n),Processor(b'synthetic'),b'synthetic')
            a=Path(folder)/'1';b=Path(folder)/'2'
            for f in (a/'sanitized').rglob('*'):
                if f.is_file():
                    self.assertEqual(f.read_bytes(),(b/f.relative_to(a)).read_bytes())
                    self.assertNotIn(b'Zorven',f.read_bytes())
            self.assertEqual((a/'records.jsonl').read_bytes(),(b/'records.jsonl').read_bytes())
    def test_offline_pipeline(self):
        with patch('socket.socket',side_effect=AssertionError('Network forbidden')):
            p=self.processor({'name':'Zorven Talrek'})
            self.assertNotIn('Zorven',p.clean('internal','doc',{'name':'Zorven Talrek'})[0]['name'])

if __name__=='__main__': unittest.main()
