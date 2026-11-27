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
        ('1 Ingest', 'Files in\nUTF-8/16\nQuarantine'),
        ('2 Detect', 'Rules\n3 scripts\nClinical shield'),
        ('3 Link', 'Transliterate\nMatch + veto\nCluster'),
        ('4 Privacy', 'HMAC IDs\nDate shifts\nRisk bands'),
        ('5 Export', 'Cleaned files\nAudit report\nRecord links'),
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
            c.setFont('Helvetica', 10)
            for j, line in enumerate(text.split('\n')):
                c.drawCentredString(x + w / 2, y + h - 10 * mm - j * 3.4 * mm, line)
            if i < n - 1:
                ax = x + w + 0.8 * mm
                c.setStrokeColor(ACCENT)
                c.line(ax, y + h / 2, ax + gap - 1.6 * mm, y + h / 2)
                c.line(ax + gap - 3 * mm, y + h / 2 + 1.2 * mm, ax + gap - 1.6 * mm, y + h / 2)
                c.line(ax + gap - 3 * mm, y + h / 2 - 1.2 * mm, ax + gap - 1.6 * mm, y + h / 2)
        c.setFont('Helvetica-Oblique', 10)
        c.setFillColor(INK)
        c.drawString(0, 1.5 * mm, 'Two passes: collect evidence in RAM, then clean and export.')


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
        ['Detection', 'Bounded regex for Aadhaar, ABHA, PAN, UHID/IPD, PIN and dates; phonenumbers for phone formats and E.164; '
         'context rules for S/o, W/o, D/o, C/O, honorifics (ji, sahab, didi) and labels in all three scripts; a '
         'medical shield (doses, 1-0-1, vitals, eponyms like Parkinson\'s) and Dr.-prefix protection. Unseen labels '
         'such as <i>Naam</i>, <i>Umar</i>, <i>Janm Tithi</i> are recognised after transliteration.'],
        ['Linkage', 'Each record becomes evidence (names, relatives, IDs, phone, DOB, age + reference year, gender, village). '
         'indic-transliteration plus a Hindi schwa adapter converts Devanagari; variants are folded (Mohd/Md., aa/a, ph/f, au/ou), tokens '
         'compared with Jaro-Winkler. Blocking on IDs, phones and phonetic keys; Fellegi-Sunter style weights '
         '(ID 10, phone 5, full name 5, relative 4, DOB 4, village 2, age 1; threshold 7). Hard vetoes on gender, DOB, '
         'birth year and conflicting full names; a merge is refused if the <i>merged cluster</i> would conflict, which stops '
         'transitive over-merging. A shared phone does not justify linking conflicting identities.'],
        ['Pseudonyms', '<font face="Courier">PSN-</font> + 8 chars from HMAC-SHA256(RAKSHA_SECRET, cluster evidence). '
         'Stable for a release, different under another secret, not invertible by hash dictionaries, never embeds UHID '
         'or phone digits. The pseudonym replaces the patient\'s name and reference IDs inside the record.'],
    ], [24 * mm, W - 24 * mm]))
    s.append(P('4. USP', h2))
    s.append(P('&bull; <b>Cross-script identity</b>: one patient in Latin, Devanagari and Hinglish gets one pseudonym '
               '(validated on synthetic multilingual records). &bull; <b>Precision first</b>: conflicting guardian '
               'evidence prevents household-phone merges. &bull; <b>Patient-aware redaction</b>: once linked, spelling '
               'variants of that patient\'s name (Zenab/Zainab) are removed even where the context detector missed them. '
               '&bull; <b>Risk-targeted generalisation</b> instead of blanket deletion.'))
    s.append(PageBreak())

    s.append(P('5. Privacy-utility trade-off (27 November evaluation)', h2))
    s.append(table([
        ['Quasi-identifier', 'What we release', 'Why / cost'],
        ['Dates', 'Shifted by a secret per-patient offset of &plusmn;20-200 days (unlinked records: per-record)',
         'Offsets vary by patient; all 452 intervals kept on the final three test sets'],
        ['Age', '10-year band (47 &rarr; 40-49); 20-year, then adult/minor only (18+ / 0-17) when the patient\'s cell is sparse',
         'Bands contain the true age. Widen age first; suppress district only if the estimated group remains too small'],
        ['DOB', 'Birth-decade band in text/CSV; shifted date in FHIR birthDate (stays valid R4)',
         'DOB handled as a quasi-identifier'],
        ['Village, house, locality', 'Removed; district also removed for sparse patients (default max_level 3)',
         'Cell = 4 x patients(district) x share(gender) x share(band) must reach 5 people, else the age is widened'],
        ['PIN', '3-digit prefix (226XXX); removed at higher risk', 'Sorting-district granularity only'],
        ['Rare diagnosis', 'Name and ICD code kept exactly; age released only as adult/minor if &lt; 3 patients share the code',
         'Diagnosis statistics fully kept'],
    ], [30 * mm, 78 * mm, W - 108 * mm]))
    s.append(Spacer(1, 3))
    s.append(table([
        ['Measure (three synthetic regression sets)', 'Final result'],
        ['Dataset seeds', '2117101, 2117102, 2117103; 120 requested patients each. Rerun after an ID-format fix'],
        ['Practice composite / 100', '96.65, 94.21, 97.28 (mean 96.05). This is not universal accuracy or the official hidden score'],
        ['Weighted leak matches', '1, 5, 0; zero planted canaries on all three sets'],
        ['Patient linking precision / recall', '100% / 100%; 100% / 99.646%; 100% / 100%'],
        ['Clinical preservation probes', '3906 / 3920; 3674 / 3689; 3608 / 3620. Lost values are districts'],
        ['Admission / discharge intervals', '157 / 157; 149 / 149; 146 / 146. No unshifted date surfaces flagged'],
        ['Targeted known-person identifications', '7 / 36; 13 / 36; 7 / 36. Residual re-identification risk remains'],
        ['Validation', '201 unit tests; official submission checks pass; 106/106 output bundles pass independent FHIR resource-model checks'],
        ['Limits', 'Not a complete runtime FHIR profile validator. Tested generators are synthetic and team-authored; no learned model'],
    ], [62 * mm, W - 62 * mm]))
    s.append(P('6. Security design', h2))
    s.append(P('All evidence stays in process memory; no intermediate files are written (the only staging directory '
               'is inside the output folder; the completion report is published last). '
               'RAKSHA_SECRET is read from the environment, used only as an HMAC key and never printed or written. '
               'report.json is identified by SHA-256 only and holds aggregate counts. Errors produce fixed messages with '
               'no exception payloads. Failed files are quarantined by status only; they are never copied. '
               'Raw input is not encrypted by this pipeline. Encrypted source storage and backups are deployment responsibilities.'))
    s.append(P('7. Known limitations', h2))
    s.append(P('The practice scorer approximates the official scoring rules; its total is not universal accuracy. '
               'Synthetic sets share a generator and do not establish performance on arbitrary real data. '
               'Keeping exact conditions, stay lengths and demographics leaves re-identification risk. '
               'District suppression improves privacy but loses geographic utility; max_level 2 restores the earlier district-preserving policy. '
               'Ambiguous date order and yearless dates require assumptions. Unsupported inputs are quarantined. '
               'All results, keys for synthetic reproduction, and limitations are recorded in docs/privacy-tuning-2026-11-27. '
               'No ML model is used; this is rule and policy tuning.', small))
    doc.build(s)
    return OUT


if __name__ == '__main__':
    print(build())
