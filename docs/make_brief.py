"""Build Project_Brief.pdf (2 A4 pages). Dev-only: needs `pip install reportlab`.

    python3 docs/make_brief.py            # writes Project_Brief.pdf at the repo root

Numbers come from `python3 test_attacker.py` on the practice kit; update the
METRICS block below when they change.
"""
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (Flowable, PageBreak, Paragraph, SimpleDocTemplate,
                                Spacer, Table, TableStyle)

OUT = Path(__file__).resolve().parent.parent / 'Project_Brief.pdf'
INK = colors.HexColor('#1f2933')
ACCENT = colors.HexColor('#0f766e')
SOFT = colors.HexColor('#e6f4f1')

body = ParagraphStyle('body', fontName='Helvetica', fontSize=10, leading=12.6, textColor=INK, spaceAfter=3)
small = ParagraphStyle('small', parent=body, fontSize=10, leading=12)
h1 = ParagraphStyle('h1', parent=body, fontName='Helvetica-Bold', fontSize=16, leading=19, textColor=ACCENT, spaceAfter=2)
h2 = ParagraphStyle('h2', parent=body, fontName='Helvetica-Bold', fontSize=11.5, leading=14, textColor=ACCENT, spaceBefore=5, spaceAfter=2)
cell = ParagraphStyle('cell', parent=body, fontSize=10, leading=11.6, spaceAfter=0)


class Pipeline(Flowable):
    """Architecture diagram: ingestion -> detection -> linkage -> privacy -> export."""
    STAGES = [
        ('1 Ingest', 'CSV/TSV/JSON/FHIR/TXT\nUTF-8, BOM, UTF-16, cp1252\nquarantine bad files'),
        ('2 Detect', 'rules + context + gazetteer\nLatin / Devanagari /\nHinglish, medical shield'),
        ('3 Link', 'transliterate, Jaro-Winkler,\nblocking, vetoes,\nconflict-safe clusters'),
        ('4 Privacy', 'HMAC pseudonyms, per-\npatient date shift, bands,\nrare-dx coarsening'),
        ('5 Export', 'sanitized/ mirror\nreport.json (SHA-256)\nrecords.jsonl'),
    ]

    def __init__(self, width):
        super().__init__()
        self.width, self.height = width, 33 * mm

    def draw(self):
        c = self.canv
        n = len(self.STAGES)
        gap = 5 * mm
        w = (self.width - gap * (n - 1)) / n
        h = 24 * mm
        y = 6 * mm
        for i, (title, text) in enumerate(self.STAGES):
            x = i * (w + gap)
            c.setFillColor(SOFT)
            c.setStrokeColor(ACCENT)
            c.roundRect(x, y, w, h, 2.5 * mm, stroke=1, fill=1)
            c.setFillColor(ACCENT)
            c.setFont('Helvetica-Bold', 10)
            c.drawCentredString(x + w / 2, y + h - 5 * mm, title)
            c.setFillColor(INK)
            c.setFont('Helvetica', 7.6)
            for j, line in enumerate(text.split('\n')):
                c.drawCentredString(x + w / 2, y + h - 10 * mm - j * 3.4 * mm, line)
            if i < n - 1:
                ax = x + w + 0.8 * mm
                c.setStrokeColor(ACCENT)
                c.line(ax, y + h / 2, ax + gap - 1.6 * mm, y + h / 2)
                c.line(ax + gap - 3 * mm, y + h / 2 + 1.2 * mm, ax + gap - 1.6 * mm, y + h / 2)
                c.line(ax + gap - 3 * mm, y + h / 2 - 1.2 * mm, ax + gap - 1.6 * mm, y + h / 2)
        c.setFont('Helvetica-Oblique', 7.6)
        c.setFillColor(INK)
        c.drawString(0, 1.5 * mm, 'Two passes over the input: observe() collects evidence in RAM, finish() links patients, '
                     'clean() rewrites each record. Nothing sensitive is logged or written to temp files.')


def table(rows, widths, header=True):
    data = [[Paragraph(str(c), cell) for c in r] for r in rows]
    t = Table(data, colWidths=widths, hAlign='LEFT')
    style = [('GRID', (0, 0), (-1, -1), 0.4, colors.HexColor('#9fb3ad')),
             ('VALIGN', (0, 0), (-1, -1), 'TOP'),
             ('LEFTPADDING', (0, 0), (-1, -1), 3), ('RIGHTPADDING', (0, 0), (-1, -1), 3),
             ('TOPPADDING', (0, 0), (-1, -1), 1.5), ('BOTTOMPADDING', (0, 0), (-1, -1), 1.5)]
    if header:
        style += [('BACKGROUND', (0, 0), (-1, 0), SOFT)]
    t.setStyle(TableStyle(style))
    return t


def P(text, style=body):
    return Paragraph(text, style)


def build():
    doc = SimpleDocTemplate(str(OUT), pagesize=A4, leftMargin=15 * mm, rightMargin=15 * mm,
                            topMargin=12 * mm, bottomMargin=11 * mm,
                            title='Secret Wards - Team 0098 - Project Brief')
    W = A4[0] - 30 * mm
    s = []
    s.append(P('Secret Wards &mdash; Team 0098 Privacy Firewall', h1))
    s.append(P('<b>Repo:</b> github.com/divyanshkush437-source/secret-wards-team-0098 &nbsp;|&nbsp; '
               '<b>Track 3</b>, Yugaantar DevForge &nbsp;|&nbsp; Member 1: ingestion &amp; export, '
               'Member 2: multilingual detection, Member 3: linkage, privacy layer &amp; red-team.'))
    s.append(P('<b>Pitch:</b> an offline, CPU-only, LLM-free pipeline that recognises the same patient across '
               'English, Devanagari and Hinglish records, gives them one keyed pseudonym, and coarsens only the '
               'demographics that make a patient findable, while every dose, vital, lab value and stay length survives.'))
    s.append(P('2. Architecture', h2))
    s.append(Pipeline(W))
    s.append(P('3. How each part works', h2))
    s.append(table([
        ['Part', 'Technique and why'],
        ['Ingestion', 'Encoding sniffing (BOM, UTF-16, cp1252 fallback), strict CSV, duplicate-key / NaN / depth-limited JSON. '
         'Anything unparseable or unsupported (XML, PDF, JPEG, truncated, 1,500-deep JSON) is quarantined, never copied. '
         'Arrays of records get their own RFC 6901 locators; file names with PII are renamed by keyed HMAC.'],
        ['Detection', 'Bounded regex for Aadhaar, ABHA, PAN, UHID/IPD, phones (incl. Devanagari digits), PIN, dates; '
         'context rules for S/o, W/o, D/o, C/O, honorifics (ji, sahab, didi) and labels in all three scripts; a '
         'medical shield (doses, 1-0-1, vitals, eponyms like Parkinson\'s) and Dr.-prefix protection. Unseen labels '
         'such as <i>Naam</i>, <i>Umar</i>, <i>Janm Tithi</i> are recognised after transliteration.'],
        ['Linkage', 'Each record becomes evidence (names, relatives, IDs, phone, DOB, age + reference year, gender, village). '
         'Devanagari is transliterated with schwa deletion, variants are folded (Mohd/Md., aa/a, ph/f, au/ou), tokens '
         'compared with Jaro-Winkler. Blocking on IDs, phones and phonetic keys; Fellegi-Sunter style weights '
         '(ID 10, phone 5, full name 5, relative 4, DOB 4, village 2, age 1; threshold 7). Hard vetoes on gender, DOB, '
         'birth year and conflicting full names; a merge is refused if the <i>merged cluster</i> would conflict, which stops '
         'transitive over-merging. A shared phone with a different name never links (families share phones).'],
        ['Pseudonyms', '<font face="Courier">PSN-</font> + 8 chars from HMAC-SHA256(RAKSHA_SECRET, cluster evidence). '
         'Stable for a release, different under another secret, not invertible by hash dictionaries, never embeds UHID '
         'or phone digits. The pseudonym replaces the patient\'s name and reference IDs inside the record.'],
    ], [24 * mm, W - 24 * mm]))
    s.append(P('4. USP', h2))
    s.append(P('&bull; <b>Cross-script identity</b>: one patient in Latin, Devanagari and Hinglish gets one pseudonym '
               '(language-trap patients: 100% of pairs linked). &bull; <b>Precision first</b>: 0 false merges on practice '
               'data, both homonym pairs kept apart. &bull; <b>Patient-aware redaction</b>: once linked, spelling '
               'variants of that patient\'s name (Zenab/Zainab) are removed even where the context detector missed them. '
               '&bull; <b>Risk-targeted generalisation</b> instead of blanket deletion.'))
    s.append(PageBreak())

    s.append(P('5. Privacy-utility trade-off (measured on the practice kit)', h2))
    s.append(table([
        ['Quasi-identifier', 'What we release', 'Why / cost'],
        ['Dates', 'Shifted by a secret per-patient offset of &plusmn;20-200 days (unlinked records: per-record)',
         'Defeats global-shift recovery; all 22 admission/discharge intervals kept exactly'],
        ['Age', '10-year band (47 &rarr; 40-49); 85+ top-coded; 20-year band when the patient\'s cell is sparse',
         'Bands always contain the true age. Fixed 5-year bands left 9/50 profiles re-identifiable, fixed 10-year 4/50, adaptive 0/50'],
        ['DOB', 'Birth-decade band in text/CSV; shifted date in FHIR birthDate (stays valid R4)',
         'Exact DOB never survives'],
        ['Village, house, locality', 'Removed; district kept unless the patient\'s estimated registry cell is &lt; 5 people',
         'Cell = 4 x patients(district) x share(gender) x share(band); then 20-yr band, then no district (also masked in letterheads)'],
        ['PIN', '3-digit prefix (226XXX); removed at higher risk', '54 of 93 district probes are given up for privacy'],
        ['Rare diagnosis', 'Kept; demographics around it coarsened (20-yr band, no district, no PIN) if < 3 patients share the ICD code',
         'Utility of diagnosis statistics kept; 3 district values lost'],
    ], [30 * mm, 78 * mm, W - 108 * mm]))
    s.append(Spacer(1, 3))
    s.append(table([
        ['Measure (practice data, 200 files)', 'Result'],
        ['Files sanitized / quarantined / records', '193 / 7 / 822 records, 775 linked'],
        ['Linkage pairwise precision / recall / F0.5', '1.000 / 0.985 / 0.997 (6,892 linkable pairs); homonyms 2/2 separated'],
        ['Trap patients (pairs linked)', 'language 100%, meaning 100%, re-identification 100%, fragmented 87-89%'],
        ['Direct identifiers surviving', '0 of 1,250 (Aadhaar, ABHA, PAN, phone, email, UHID/IPD); villages/houses/localities 0 of 389'],
        ['Names surviving', 'Devanagari 0/135, Hinglish 2/111, Latin 1/2,587 (all 3 are the allowed doctor name in multi-visit files); canaries 0'],
        ['Clinical probes kept', '4,801 / 4,855 (98.9%; all 54 lost are districts suppressed for high-risk patients)'],
        ['Registry attack (district, gender, band, PIN prefix)', 'profiles &ge; 0.5: 0 / 50 (raw input 10 / 48); records: 0 / 746 (raw 11); mean on true person 0.05 per profile'],
        ['Determinism / other secret', 'byte-identical sanitized/ and records.jsonl; 0 pseudonyms shared across secrets'],
        ['Speed and memory', '4.6 s, 34 MB (practice); 6x data: 1,200 files in 43 s, 149 MB peak'],
    ], [62 * mm, W - 62 * mm]))
    s.append(P('6. Security design', h2))
    s.append(P('All evidence stays in process memory; no intermediate files are written (the only staging directory '
               'is inside the output folder and is renamed into place only on success, so a crash publishes nothing). '
               'RAKSHA_SECRET is read from the environment, used only as an HMAC key and never printed or written. '
               'report.json is identified by SHA-256 only and holds aggregate counts. Errors produce fixed messages with '
               'no exception payloads. Failed files are quarantined by status only; they are never copied. '
               'If disk staging is ever needed, the plan is AES-GCM with a key derived from the secret (cryptography).'))
    s.append(P('7. Known limitations', h2))
    s.append(P('&bull; Practice data has only ~50 patients; the registry size is estimated (4x patients), and our attack is an '
               'approximation of the organisers\' attacker (it ignores names, which we remove). &bull; Rare-diagnosis protection coarsens '
               'demographics; the diagnosis itself plus exact stay length can still single out a patient for an attacker '
               'who already knows both (targeted attack A5 was not measured). &bull; Fragmented notes with only a first name and no relative stay unlinked by '
               'design. &bull; Context rules can still miss names in unseen label styles; free-text village names without '
               'markers may survive. &bull; Scaling on duplicated data grew faster than linear (6x data, ~10x time) '
               'because large blocks share identifiers. &bull; No ML model is used; all rules were written during the event.', small))
    doc.build(s)
    return OUT


if __name__ == '__main__':
    print(build())
