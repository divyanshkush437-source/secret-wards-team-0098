"""Member 1 adapter for detector-only integration runs.

This intentionally returns patient=None and keeps DATE/DOB/AGE/GENDER unchanged.
It is not the final Member 3 privacy/linkage processor. All evidence stays in RAM.
"""
from collections import Counter
import base64
import binascii
import hashlib
import hmac
import re
from detector import detect_text, detect_key_or_filename
from detector.context_rules import name_candidates, overlaps, resolve
from detector.engine import _policy
from detector.field_hints import canonical_hint, contextual_hint
from detector.schema import EntitySpan
from detector.medical_whitelist import protected_ranges

DIRECT = {'PERSON','RELATIVE','PHONE','EMAIL','ID_AADHAAR','ID_ABHA','ID_PAN','ID_UHID'}

class Processor:
    def __init__(self, secret):
        if not isinstance(secret,bytes) or not secret:
            raise ValueError('A nonempty byte secret is required')
        self.secret = secret
        self.entities = Counter()
        self.generalized = 0
        self.names = set()
        self.name_pattern = None
        self.clinical_values = set()
        self.clinical_pattern = None
        self.district_values = set()

    def _hint(self,key,path,inherited='',role=''):
        return contextual_hint(key,path,inherited,role,preserve_district=True)

    def _leaves(self,data,path=(),hint='',depth=0):
        if depth > 64: raise ValueError('Record nesting exceeds configured limit')
        if isinstance(data,dict):
            role=data.get('resourceType','')
            for key,value in data.items():
                if not isinstance(key,str): raise TypeError('Record keys must be strings')
                child_hint=self._hint(key,path,hint,role)
                yield from self._leaves(value,path+(key,),child_hint,depth+1)
        elif isinstance(data,list):
            for index,value in enumerate(data): yield from self._leaves(value,path+(str(index),),hint,depth+1)
        elif isinstance(data,(str,int,float)) and not isinstance(data,bool):
            yield path,str(data),hint

    def observe(self,file_id,loc,data):
        for _,text,hint in self._leaves(data):
            if hint in {'__clinical__','__district__'} and text.strip(): self.clinical_values.add(text.strip())
            if hint=='__district__' and text.strip(): self.district_values.add(text.strip())
            for span in detect_text(text,hint).spans:
                if span.entity_type in {'PERSON','RELATIVE'} and span.confidence >= .85 and len(span.text.strip()) >= 3:
                    self.names.add(span.text.strip())

    def finish(self):
        if self.clinical_values:
            self.clinical_pattern=re.compile(r'(?<!\w)(?:'+'|'.join(re.escape(v) for v in sorted(self.clinical_values,key=lambda x:(-len(x),x)))+r')(?!\w)',re.I)
        if self.names:
            # Names discovered from input context only; never from truth or gazetteers.
            terms=sorted(self.names,key=lambda s:(-len(s),s))
            self.name_pattern=re.compile(r'(?<![^\W_])(?:'+'|'.join(re.escape(t).replace(r'\ ','[ _-]+') for t in terms)+r')(?![^\W_])',re.I)

    def _spans(self,text,hint):
        found=detect_text(text,hint).spans
        protected=([m.span() for m in self.clinical_pattern.finditer(text)] if self.clinical_pattern else [])+protected_ranges(text)
        found=[s for s in found if s.entity_type not in {'PERSON','RELATIVE'} or (hint in {'patient name','name','relative','given','family'} and s.confidence>=.85) or not any(overlaps((s.start,s.end),r) for r in protected)]
        _,doctors=name_candidates(text,_policy(None),hint)
        if self.name_pattern and hint not in {'__clinical__','__district__'}:
            for match in self.name_pattern.finditer(text):
                if not any(overlaps(match.span(),d) for d in doctors+protected):
                    found.append(EntitySpan(match.start(),match.end(),'PERSON',match[0],match[0].casefold(),'PSEUDONYMIZE',.92))
        return resolve(found)

    def _text(self,text,hint):
        result=text
        for span in reversed(self._spans(text,hint)):
            if span.entity_type in DIRECT or span.entity_type in {'LOCATION','PINCODE'}:
                self.entities[span.entity_type]+=1
                replacement='['+span.entity_type+']'
                if span.entity_type=='LOCATION':
                    retained=[v for v in sorted(self.district_values) if re.search(r'(?<!\w)'+re.escape(v)+r'(?!\w)',span.text,re.I)]
                    if retained: replacement+=' '+', '.join(retained)
                result=result[:span.start]+replacement+result[span.end:]
        return result

    def _key(self,key):
        # Schema labels are not personal names. Strong identifiers and learned
        # names still get scanned in every key; unknown contextual metadata too.
        known=canonical_hint(key)!=key or key in {'name','given','family','age','gender','address','phone','email'}
        spans=self._spans(key,'__clinical__')
        if not known: spans+=detect_key_or_filename(key)
        if self.name_pattern and self.name_pattern.search(key):
            return self._key_token(key)
        if any(s.entity_type in DIRECT and (s.entity_type!='PERSON' or s.confidence>=.85) for s in spans):
            return self._key_token(key)
        return key

    def _key_token(self,key):
        self.entities['METADATA']+=1
        return 'field_'+hmac.new(self.secret,key.encode(),hashlib.sha256).hexdigest()[:24]

    def _value(self,data,path=(),hint='',depth=0):
        if depth>64: raise ValueError('Record nesting exceeds configured limit')
        if isinstance(data,str):
            if path and path[-1].casefold() in {'source_path','sourcepath','filepath','file_path'}:
                self.entities['METADATA']+=1
                return '[SOURCE_PATH]'
            return self._text(data,hint)
        if isinstance(data,(int,float)) and not isinstance(data,bool):
            # Preserve JSON number types; null is not an acceptable type-preserving replacement.
            if any(s.entity_type in DIRECT for s in self._spans(str(data),hint)):
                self.entities['NUMERIC_ID']+=1
                return 0 if isinstance(data,int) else 0.0
            return data
        if isinstance(data,list): return [self._value(v,path+(str(i),),hint,depth+1) for i,v in enumerate(data)]
        if isinstance(data,dict):
            result={}; role=data.get('resourceType','')
            for key,value in data.items():
                safe=self._key(key)
                if safe in result: raise ValueError('Transformed key collision')
                child_hint=self._hint(key,path,hint,role)
                if key=='data' and isinstance(value,str) and ('contentType' in data or 'attachment' in path or data.get('encoding')=='base64'):
                    try:
                        mime=str(data.get('contentType','')).split(';',1)[0].strip().casefold()
                        if mime!='text/plain' or len(value)>1400000: raise ValueError
                        decoded=base64.b64decode(value,validate=True).decode('utf-8')
                        if len(decoded)>1000000: raise ValueError
                        cleaned=self._text(decoded,'')
                        result[safe]=base64.b64encode(cleaned.encode()).decode('ascii')
                    except (ValueError,UnicodeError,binascii.Error):
                        raise ValueError('Unsupported encoded attachment') from None
                    self.entities['ATTACHMENT']+=1
                    continue
                result[safe]=self._value(value,path+(key,),child_hint,depth+1)
            return result
        return data

    def clean(self,file_id,loc,data):
        return self._value(data),None
