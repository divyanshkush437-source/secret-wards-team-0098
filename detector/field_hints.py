"""Canonicalize field labels without trusting them to exclude content scans."""
import re

def canonical_hint(label):
    compact = re.sub(r'[^\w\u0900-\u097f]', '', label.casefold()).replace('_','')
    groups = {
        'patient name': {'patientname','fullname','firstname','lastname','givenname','surname','नाम','मरीजकानाम','रोगीकानाम'},
        'relative': {'guardian','guardianname','fathername','mothername','relativename','attendant','spouse','पितापति','अभिभावक'},
        'uhid': {'patientid','patientref','hospitaluhid','uhid','mrn','registrationno','regno','ipdno','opdno','admissionid','insuranceid','policyno','policynumber','pmjayid'},
        'address': {'address','pata','gaon','gram','gali','makan','street','city','village','villagemohalla','mohalla','tehsil','taluka','district','house','houseno','पता','ग्राम','गांव','मोहल्ला','तहसील','जिला'},
        'pincode': {'pin','pincode','zip','zipcode','postalcode','पिन'},
        'dob': {'birthdate','dateofbirth','dob','जन्मतिथि'},
        'age': {'age','ageyears','ageyrs','उम्र','आयु'},
        'gender': {'sex','gender','लिंग'},
    }
    for hint, aliases in groups.items():
        if compact in aliases: return hint
    if compact.startswith('dob'): return 'dob'
    return label
