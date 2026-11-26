"""Boundary tests for Member 3; all fixtures are synthetic."""
import base64
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import builtins
import main as runner
from detector import detect_record, detect_text
from io_handler import parse
from main import run
from member2_processor import Processor

class ReadinessTests(unittest.TestCase):
    def test_iso_timestamp_date(self):
        text='2026-03-12T09:30:00+05:30'
        r=detect_text(text,'effectiveDateTime')
        self.assertEqual(r.dates,['2026-03-12'])
        self.assertEqual(r.spans[0].text,'2026-03-12')
    def test_iso_timestamp_invalid(self):
        self.assertFalse(detect_text('2026-02-30T09:30:00Z').dates)
    def test_record_practitioner_names_preserved(self):
        r=detect_record({'resourceType':'Practitioner','name':[{'given':['Zorven'],'family':'Talrek'}]})
        self.assertFalse(any(x.patient_names for x in r.values()))
    def test_record_patient_names_detected(self):
        r=detect_record({'resourceType':'Patient','name':[{'given':['Zorven'],'family':'Talrek'}]})
        self.assertTrue(r['/name/0/given/0'].patient_names)
    def test_nested_guardian_role(self):
        r=detect_record({'guardian':{'name':'Zorven Talrek'}})
        self.assertTrue(r['/guardian/name'].relative_names)
        self.assertFalse(r['/guardian/name'].patient_names)
    def test_adapter_keeps_date_convention(self):
        p=Processor(b'test')
        leaves=list(p._leaves({'DOB (MM/DD/YYYY)':'04/20/1979'}))
        self.assertEqual(detect_text(leaves[0][1],leaves[0][2]).dob,'1979-04-20')
    def test_attachment_type_rejected(self):
        p=Processor(b'test')
        data={'contentType':'application/octet-stream','data':base64.b64encode(b'arbitrary binary-looking payload').decode()}
        with self.assertRaisesRegex(ValueError,'Unsupported encoded attachment'):
            p.clean('file','doc',data)
    def test_member3_import_error_is_private(self):
        original=builtins.__import__
        def broken(name,*args,**kwargs):
            if name=='team_processor': raise ValueError('PRIVATE_SENTINEL_IMPORT')
            return original(name,*args,**kwargs)
        stream=io.StringIO()
        with patch('sys.argv',['main.py','--input','unused','--output','unused']),patch.dict('os.environ',{'RAKSHA_SECRET':'test'}),patch('builtins.__import__',side_effect=broken),contextlib.redirect_stderr(stream):
            with self.assertRaises(SystemExit) as error: runner.main()
        self.assertEqual(error.exception.code,1)
        self.assertNotIn('PRIVATE_SENTINEL',stream.getvalue())
    def test_nonfinite_json_rejected(self):
        for value in ('NaN','Infinity','-Infinity','1e999'):
            with self.assertRaises(ValueError):parse(('{"value":'+value+'}').encode(),'.json')
    def test_patient_id_must_be_embedded(self):
        class Unembedded:
            def observe(self,*args):pass
            def finish(self):pass
            def clean(self,file_id,loc,data):return data,'PSN-ABC123'
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)/'input';root.mkdir();(root/'note.txt').write_text('Dolo 650')
            out=Path(folder)/'output'
            with self.assertRaisesRegex(ValueError,'patient identifier'):
                run(root,out,Unembedded(),b'test')
            self.assertFalse((out/'report.json').exists())
    def test_json_quarantine_keeps_good_files(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)/'input';root.mkdir()
            (root/'bad.json').write_text('{"value":NaN}')
            (root/'good.txt').write_text('Dolo 650')
            report=run(root,Path(folder)/'out',Processor(b'test'),b'test')
            self.assertEqual(report['counts']['files_quarantined'],1)
            self.assertEqual(report['counts']['files_sanitized'],1)
    def test_timestamp_preserves_time_offsets(self):
        text='DOB: 1998-03-12T09:30:00Z'
        r=detect_text(text)
        self.assertEqual(r.dob,'1998-03-12')
        self.assertEqual(text[r.spans[0].end:],'T09:30:00Z')
    def test_invalid_timestamp_time(self):
        self.assertFalse(detect_text('2026-03-12T99:30:00Z').dates)
    def test_record_fhir_identifier(self):
        r=detect_record({'resourceType':'Patient','identifier':[{'value':'HOS-123456'}]})
        self.assertTrue(r['/identifier/0/value'].ids)
    def test_member3_cli_dispatch(self):
        import types
        class Stub:
            def __init__(self,secret):pass
        module=types.ModuleType('team_processor');module.Processor=Stub
        stream=io.StringIO()
        summary={'counts':{'files_sanitized':1,'files_quarantined':0,'records_processed':1}}
        with patch.dict('sys.modules',{'team_processor':module}),patch('sys.argv',['main.py','--input','unused','--output','unused']),patch.dict('os.environ',{'RAKSHA_SECRET':'test'}),patch('main.run',return_value=summary) as fake,contextlib.redirect_stdout(stream):
            runner.main()
        self.assertIsInstance(fake.call_args[0][2],Stub)
    def test_patient_id_prefix_is_not_embedding(self):
        class WrongID:
            def observe(self,*args):pass
            def finish(self):pass
            def clean(self,*args):return 'Patient: PSN-ABC1234','PSN-ABC123'
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)/'input';root.mkdir();(root/'note.txt').write_text('Dolo 650')
            with self.assertRaisesRegex(ValueError,'patient identifier'):
                run(root,Path(folder)/'out',WrongID(),b'test')
    def test_linkage_contract_end_to_end(self):
        class Linked:
            def __init__(self):self.observed=[];self.finished=False;self.entities={}
            def observe(self,file_id,loc,data):self.observed.append((file_id,loc))
            def finish(self):self.finished=True
            def clean(self,file_id,loc,data):
                assert self.finished and (file_id,loc) in self.observed
                if loc is None:return data,None
                if isinstance(data,str):return 'Patient: PSN-ABC123\n'+data,'PSN-ABC123'
                return dict(data,patient_ref='PSN-ABC123'),'PSN-ABC123'
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)/'input';root.mkdir()
            (root/'rows.csv').write_text('medicine\nDolo 650\n')
            (root/'note.txt').write_text('BP 120/80')
            (root/'group.json').write_text('{"export":"synthetic","visits":[{"medicine":"Dolo 650"}]}')
            out=Path(folder)/'output';processor=Linked()
            report=run(root,out,processor,b'test')
            self.assertEqual(report['counts']['records_linked'],3)
            rows=[json.loads(line) for line in (out/'records.jsonl').read_text().splitlines()]
            self.assertEqual({r['loc'] for r in rows},{'doc','row:0','/visits/0'})
            self.assertTrue(all(r['patient']=='PSN-ABC123' for r in rows))
    def test_failure_cleans_staging(self):
        class Broken:
            def observe(self,*args):pass
            def finish(self):pass
            def clean(self,*args):raise ValueError('Synthetic private diagnostic')
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)/'input';root.mkdir();(root/'note.txt').write_text('Dolo 650')
            out=Path(folder)/'output'
            with self.assertRaises(ValueError):run(root,out,Broken(),b'test')
            self.assertEqual(list(out.iterdir()),[])

if __name__=='__main__':unittest.main()
