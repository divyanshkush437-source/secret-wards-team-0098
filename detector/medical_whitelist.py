"""Editable seed vocabulary, not a complete clinical terminology database."""
import re
SYMPTOMS = set('fever vomiting cough chest pain breathlessness headache nausea weakness dizziness abdominal burning bleeding fatigue swelling rash cold diabetes hypertension asthma dengue malaria typhoid bukhar dard khansi बुखार दर्द खांसी उल्टी सांस कमजोरी'.split())
DRUGS = set('ramipril dolo paracetamol acetaminophen augmentin amoxicillin ceftriaxone azithromycin metformin insulin amlodipine atenolol losartan telmisartan atorvastatin aspirin clopidogrel pantoprazole omeprazole cetirizine levocetirizine montelukast salbutamol budesonide diclofenac ibuprofen tramadol ondansetron domperidone ors crocin calpol combiflam ecosprin glycomet lasix furosemide thyroxine levothyroxine prednisolone dexamethasone doxycycline ciprofloxacin metronidazole'.split())
EPONYMS = set('parkinson alzheimer hodgkin bell graves crohn cushing addison down kawasaki hansen pott guillain barre'.split())
STOPWORDS = {'महिला', 'पुरुष'} | SYMPTOMS | DRUGS | EPONYMS | set('patient name age sex gender dob born address phone mobile contact email admitted admission discharge summary report record notes diagnosis complaint consultant referred doctor dr bp spo2 pr hr rr temp hb creatinine platelets wbc rbc tab tablet inj injection cap capsule syrup disease syndrome palsy lymphoma spine mg ml g dl cumm iv im po od bd tid qid sos stat daily days day yrs years year din se ko ka hai and with for of the no male female blood test lab ward bed treatment follow up normal negative positive given taking reviewed by on at from to श्रीमती'.split())
CLINICAL_PATTERNS = [
    r'\b[0-2]-[0-2]-[0-2]\b',
    r'\b(?:BP|SpO2|PR|HR|RR|Temp|Hb|Creatinine|Platelets|WBC|RBC)\s*[:=]?\s*\d+(?:[./]\d+)?\s*(?:%|/min|[CF]|g/dL|mg/dL|/cumm)?',
    r'\b\d+(?:\.\d+)?\s*(?:mg|mcg|g|ml|mmol/L|g/dL|mg/dL|/cumm)\b',
    r'\b(?:' + '|'.join(sorted(EPONYMS)) + r")(?:['’]s|s['’])?(?:\s+(?:disease|syndrome|palsy|lymphoma|spine))?\b",
]
CLINICAL = [re.compile(p, re.I) for p in CLINICAL_PATTERNS]

def blocked_word(word):
    return word.casefold().strip(".,:;'’") in STOPWORDS

def protected_ranges(text):
    return [m.span() for pattern in CLINICAL for m in pattern.finditer(text)]

# Generic clinical and structural tokens, not names from the practice dataset.
STOPWORDS.update("summary hospital multispeciality discharge management protocol version patient presenting platelet count workers differential diagnosis nodal officer medicine ward bed opd uhid mrn ipd no mob mobile consultant nursing notes next morning serum random sugar total sodium potassium routine diagnostic report received sample review after weeks condition stable adv medications drug strength frequency duration code display resource type bundle city diagnostics care pain abdomen dm dm2 htn copd k/c/o gayi band ne raat theek ki ko se aur hai behenji amma ji ka साहब को से है का की उम्र आयु वर्ष ग्राम तारीख दवा निदान उपचार".split())

STOPWORDS.update("hypothyroidism tuberculosis generalised generalized loose stools lung essential primary urinary infection chronic kidney acute respiratory tract unspecific unspecified पेशाब में संक्रमण उच्च रक्तचाप किडनी पुरानी बीमारी मधुमेह दमा".split())

STOPWORDS.update("ms surgery mbbs dnb dm mch frcs referred worker diagnostic diagnosticreport procedure icd icd10 loinc".split())

STOPWORDS.update({'दस्त', 'और'})
CLINICAL.append(re.compile(r'\bASHA\s+worker(?:s)?\b', re.I))

CLINICAL.append(re.compile(r'\bH/O\s+[A-Za-z0-9 /]+?\s+\d+\s+yrs?\s+back\b', re.I))
