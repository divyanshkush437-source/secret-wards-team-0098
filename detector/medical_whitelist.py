"""Editable seed vocabulary, not a complete clinical terminology database."""
import re
SYMPTOMS = set('fever vomiting cough chest pain breathlessness headache nausea weakness dizziness abdominal burning bleeding fatigue swelling rash cold diabetes hypertension asthma dengue malaria typhoid bukhar dard khansi बुखार दर्द खांसी उल्टी सांस कमजोरी'.split())
DRUGS = set('ramipril dolo paracetamol acetaminophen augmentin amoxicillin ceftriaxone azithromycin metformin insulin amlodipine atenolol losartan telmisartan atorvastatin aspirin clopidogrel pantoprazole omeprazole cetirizine levocetirizine montelukast salbutamol budesonide diclofenac ibuprofen tramadol ondansetron domperidone ors crocin calpol combiflam ecosprin glycomet lasix furosemide thyroxine levothyroxine prednisolone dexamethasone doxycycline ciprofloxacin metronidazole'.split())
EPONYMS = set('parkinson alzheimer hodgkin bell graves crohn cushing addison down kawasaki hansen pott guillain barre'.split())
STOPWORDS = {'महिला', 'पुरुष'} | SYMPTOMS | DRUGS | set('patient name age sex gender dob born address phone mobile contact email admitted admission discharge summary report record notes diagnosis complaint consultant referred doctor dr bp spo2 pr hr rr temp hb creatinine platelets wbc rbc tab tablet inj injection cap capsule syrup disease syndrome palsy lymphoma spine mg ml g dl cumm iv im po od bd tid qid sos stat daily days day yrs years year din se ko ka hai and with for of the no male female blood test lab ward bed treatment follow up normal negative positive given taking reviewed by on at from to श्रीमती'.split())
CLINICAL_PATTERNS = [
    r'\b[0-2]-[0-2]-[0-2]\b',
    r'\b(?:BP|SpO2|PR|HR|RR|Temp|Hb|Creatinine|Platelets|WBC|RBC)\s*[:=]?\s*\d+(?:[./]\d+)?\s*(?:%|/min|[CF]|g/dL|mg/dL|/cumm)?',
    r'\b\d+(?:\.\d+)?\s*(?:mg|mcg|g|ml|mmol/L|g/dL|mg/dL|/cumm)\b',
    # Eponyms are protected in medical form only ("Bell's palsy", "Parkinson disease");
    # the bare word can be a surname ("Anita Bell").
    r'\b(?:' + '|'.join(sorted(EPONYMS)) + r")(?:(?:['’]s|s['’])(?:\s+(?:disease|syndrome|palsy|lymphoma|spine|sign|tremor))?|\s+(?:disease|syndrome|palsy|lymphoma|spine|sign|tremor))\b",
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

# Hindi document headings and form labels (structural words, not names).
STOPWORDS.update("डिस्चार्ज सारांश पर्चा ओपीडी आईपीडी रिपोर्ट मरीज़ मरीज रोगी नाम पता आयु उम्र लिंग निदान दवा दवाई सलाह जांच परीक्षण भर्ती छुट्टी तारीख दिनांक पंजीकरण अस्पताल वार्ड बिस्तर डॉक्टर चिकित्सक नर्सिंग नोट्स समरी इलाज उपचार सं संख्या मोबाइल".split())

# A phrase directly before an ICD-10 code in brackets, or after a diagnosis
# label, is a diagnosis in any script ("जापानी इंसेफेलाइटिस (A83.0)").
CLINICAL.append(re.compile(r"[A-Za-z\u0900-\u097f][A-Za-z\u0900-\u097f '’,-]{1,60}?(?=\s*\(\s*[A-TV-Z]\d{2}(?:\.\d{1,2})?\s*\))"))
CLINICAL.append(re.compile(r"(?i)(?<![\w\u0900-\u097f])(?:निदान|रोग|बीमारी|diagnosis|diagnosed with|treated for|dx)(?![\w\u0900-\u097f])\s*[:-]?\s*[^\n(;:]{2,60}"))
STOPWORDS.update("vitamin calcium iron zinc folic folate magnesium potassium sodium b12 d3".split())

# Codes and lot numbers that look like identifiers ("SNOMED CT 234567890127" passes the
# Aadhaar checksum, "Batch ABC1234567" looks like a voter ID, a 14-digit log timestamp like ABHA).
CLINICAL.append(re.compile(r"(?i)\b(?:SNOMED(?:[\s-]*CT)?|LOINC|ICD-?(?:10|11)?|CPT|ATC|Batch|Lot|Log|Specimen|Barcode|Expiry|Exp\.?|Mfg\.?)"
                           r"(?:\s*(?:no\.?|code|id|#))?\s*[:#.]?\s*[A-Z0-9][A-Z0-9./-]{3,}"))
STOPWORDS.update("snomed loinc ct batch lot specimen barcode".split())
STOPWORDS.update("voter epic elector electors".split())
STOPWORDS.update("जन्म तिथि जन्मतिथि आधार पिन कोड गाँव गांव जिला ज़िला मोबाइल फ़ोन फोन लिंग पुरुष महिला पंजीकरण सं संख्या पता मकान नं वार्ड बिस्तर".split())
STOPWORDS.update("duo forte plus kid dt sr er xr cr cv mr od hbp pkg package सिंड्रोम रोग बीमारी लक्षण".split())
