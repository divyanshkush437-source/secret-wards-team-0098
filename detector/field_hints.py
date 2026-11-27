"""Canonicalize field labels without trusting them to exclude content scans."""
import re

def canonical_hint(label):
    compact = re.sub(r'[^\w\u0900-\u097f]', '', label.casefold()).replace('_','')
    groups = {
        'patient name': {'patientname','fullname','firstname','lastname','givenname','surname','नाम','मरीजकानाम','रोगीकानाम'},
        'relative': {'guardian','guardianname','fathername','mothername','fatherhusband','fathermother','parentguardian','nextofkin','relativename','attendant','spouse','पितापति','अभिभावक'},
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

CLINICAL_FIELDS = set('drug medicine medication diagnosis procedure complaints history test unit strength frequency duration range code display title hospital department lab panel system resourcetype status type language profile contenttype'.split())
NAME_PARTS = {'name','text','family','given','prefix','suffix','hi','en','hindi','english','latin','deva'}

def contextual_hint(key, path=(), inherited='', role='', preserve_district=False):
    """Shared traversal context for detection and cleaning, not an exclusion filter.

    Keep explicit date conventions until detect_text has parsed them. Propagate
    person roles only through name containers; never turn every patient field into
    a name. Numeric and strongly formatted identifiers remain scanned everywhere.
    """
    if re.search(r'(?i)MM[/-]DD',key): return key
    if key == 'name' and role in {'Practitioner','Organization','Location','Medication'}:
        return '__clinical__'
    if key == 'name' and role == 'Patient': return 'patient name'
    if key == 'name' and role == 'RelatedPerson': return 'relative'
    if key in NAME_PARTS and inherited in {'relative','__clinical__','patient name'}:
        return inherited
    if key in NAME_PARTS and inherited == 'name': return 'patient name'
    if key == 'display' and any(x in path for x in ('subject','patient')): return 'patient name'
    if key == 'value' and 'identifier' in path: return 'uhid'
    if key == 'name' and any(x in path for x in ('panels','results','medication')): return '__clinical__'
    if key.casefold() in CLINICAL_FIELDS: return '__clinical__'
    if preserve_district and key.casefold() in {'district','जिला'}: return '__district__'
    if 'address' in path and key in {'line','text','city','state','postalCode'}:
        return 'pincode' if key == 'postalCode' else 'address'
    return canonical_hint(key)
