import docx
from docx.shared import Inches, Pt, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT, WD_ALIGN_VERTICAL
from docx.oxml import parse_xml, OxmlElement
from docx.oxml.ns import nsdecls, qn

def set_cell_background(cell, hex_color):
    shading_xml = f'<w:shd {nsdecls("w")} w:fill="{hex_color}"/>'
    cell._tc.get_or_add_tcPr().append(parse_xml(shading_xml))

def set_cell_margins(cell, top=100, bottom=100, left=150, right=150):
    tcPr = cell._tc.get_or_add_tcPr()
    tcMar = parse_xml(f'<w:tcMar {nsdecls("w")}><w:top w:w="{top}" w:type="dxa"/><w:bottom w:w="{bottom}" w:type="dxa"/><w:left w:w="{left}" w:type="dxa"/><w:right w:w="{right}" w:type="dxa"/></w:tcMar>')
    tcPr.append(tcMar)

def create_report():
    doc = docx.Document()

    # Page Margins: 0.7 inches for compact 4-page layout
    for section in doc.sections:
        section.top_margin = Inches(0.65)
        section.bottom_margin = Inches(0.65)
        section.left_margin = Inches(0.7)
        section.right_margin = Inches(0.7)

    # Styles
    styles = doc.styles
    normal_style = styles['Normal']
    normal_style.font.name = 'Calibri'
    normal_style.font.size = Pt(10)
    normal_style.font.color.rgb = RGBColor(30, 41, 59)
    normal_style.paragraph_format.line_spacing = 1.15
    normal_style.paragraph_format.space_after = Pt(4)

    # Colors
    PRIMARY = RGBColor(15, 23, 42)      # Deep Navy
    SECONDARY = RGBColor(2, 132, 199)   # Vibrant Blue
    DARK_TEXT = RGBColor(15, 23, 42)
    MUTED_TEXT = RGBColor(100, 116, 139)

    # --- TITLE & HEADER BLOCK ---
    title_p = doc.add_paragraph()
    title_p.paragraph_format.space_after = Pt(2)
    title_p.paragraph_format.space_before = Pt(0)
    run_title = title_p.add_run("FILEGUARD: SECURE EPHEMERAL FILE SHARING SYSTEM")
    run_title.font.size = Pt(17)
    run_title.font.bold = True
    run_title.font.color.rgb = PRIMARY

    sub_p = doc.add_paragraph()
    sub_p.paragraph_format.space_after = Pt(8)
    run_sub = sub_p.add_run("Technical Architecture, Cryptographic Integrity Verification & Forensic Telemetry")
    run_sub.font.size = Pt(11)
    run_sub.font.bold = True
    run_sub.font.color.rgb = SECONDARY

    # Meta Table (Compact)
    meta_table = doc.add_table(rows=2, cols=2)
    meta_table.alignment = WD_TABLE_ALIGNMENT.CENTER
    meta_table.autofit = False

    col_widths = [Inches(3.5), Inches(3.6)]
    meta_data = [
        [("Course / Domain:", " Information & Network Security (INS::2026)"),
         ("Live Production URL:", " https://files.deeptanil.in")],
        [("Core Stack:", " Python 3.14, Flask, PostgreSQL, B2 S3"),
         ("Source Repository:", " https://github.com/Deeptanil/FileGuard.git")]
    ]

    for row_idx, row in enumerate(meta_table.rows):
        for col_idx, cell in enumerate(row.cells):
            cell.width = col_widths[col_idx]
            set_cell_background(cell, "F1F5F9")
            set_cell_margins(cell, top=60, bottom=60, left=100, right=100)
            p = cell.paragraphs[0]
            p.paragraph_format.space_after = Pt(0)
            k, v = meta_data[row_idx][col_idx]
            r1 = p.add_run(k)
            r1.font.bold = True
            r1.font.size = Pt(8.5)
            r2 = p.add_run(v)
            r2.font.size = Pt(8.5)

    doc.add_paragraph().paragraph_format.space_after = Pt(4)

    def add_heading(text, level=1):
        h = doc.add_paragraph()
        h.paragraph_format.space_before = Pt(10)
        h.paragraph_format.space_after = Pt(3)
        h.paragraph_format.keep_with_next = True
        r = h.add_run(text)
        r.font.bold = True
        if level == 1:
            r.font.size = Pt(12)
            r.font.color.rgb = PRIMARY
            # Add bottom accent border via XML
            pPr = h._p.get_or_add_pPr()
            pBdr = parse_xml(f'<w:pBdr {nsdecls("w")}><w:bottom w:val="single" w:sz="8" w:space="2" w:color="0284C7"/></w:pBdr>')
            pPr.append(pBdr)
        else:
            r.font.size = Pt(10.5)
            r.font.color.rgb = SECONDARY
        return h

    def add_bullet(bold_prefix="", text=""):
        p = doc.add_paragraph(style='List Bullet')
        p.paragraph_format.space_after = Pt(2)
        p.paragraph_format.line_spacing = 1.15
        if bold_prefix:
            r_bold = p.add_run(bold_prefix)
            r_bold.font.bold = True
            r_bold.font.size = Pt(9.5)
        if text:
            r_txt = p.add_run(text)
            r_txt.font.size = Pt(9.5)
        return p

    # --- 1. EXECUTIVE SUMMARY & PROBLEM STATEMENT ---
    add_heading("1. Executive Summary & Problem Formulation")
    p1 = doc.add_paragraph()
    p1.add_run(
        "Modern cloud file-transfer utilities suffer from three critical architectural flaws: (1) silent data degradation and undetectable bit-rot, (2) 'ghost file persistence' where expired assets linger on remote disks for weeks, and (3) pervasive tracking requiring mandatory user registration and cookie surveillance. "
        "FileGuard resolves these vulnerabilities by pairing an authoritative 12-hour ephemeral lifecycle with a pre-flight cryptographic gate that guarantees zero-knowledge anonymity, bit-level integrity, and immediate multi-cloud storage purging."
    )

    # --- 2. SYSTEM ARCHITECTURE & DATA FLOW ---
    add_heading("2. System Architecture & Core Specifications")
    p2 = doc.add_paragraph()
    p2.add_run(
        "FileGuard is architected as an asynchronous, defensive gateway coordinating application-layer security, relational state, and S3-compatible cloud object storage."
    )

    # Table of Core System Specifications
    spec_table = doc.add_table(rows=6, cols=3)
    spec_table.alignment = WD_TABLE_ALIGNMENT.CENTER
    spec_headers = ["Subsystem", "Engineering Technology", "Security Function & Standard"]
    spec_data = [
        ["Gateway Runtime", "Python 3.14 / Flask / Gunicorn", "Strict CSPRNG tokenization, CSRF, and nosniff enforcement"],
        ["Relational State", "Neon Serverless PostgreSQL", "Stores SHA-256 token hashes & authoritative UTC deadlines"],
        ["Object Storage", "Backblaze B2 S3 (boto3)", "Parallel chunk streaming (10 threads, 256 KB memory buffer)"],
        ["Integrity Gate", "SHA-256 Pre-Flight Engine", "Dynamic bit-level validation halting modified downloads (HTTP 409)"],
        ["Subnet Gate", "Flask-Limiter / CIDR Masking", "Anonymous abuse mitigation (100 MB per 12h per /64 IPv6, /24 IPv4)"]
    ]

    for col_idx, h_text in enumerate(spec_headers):
        cell = spec_table.rows[0].cells[col_idx]
        set_cell_background(cell, "0F172A")
        set_cell_margins(cell, top=80, bottom=80, left=100, right=100)
        p = cell.paragraphs[0]
        p.paragraph_format.space_after = Pt(0)
        r = p.add_run(h_text)
        r.font.bold = True
        r.font.size = Pt(8.5)
        r.font.color.rgb = RGBColor(255, 255, 255)

    col_w = [Inches(1.6), Inches(2.3), Inches(3.2)]
    for row_idx, row_data in enumerate(spec_data):
        row = spec_table.rows[row_idx + 1]
        bg = "F8FAFC" if row_idx % 2 == 0 else "FFFFFF"
        for col_idx, cell_text in enumerate(row_data):
            cell = row.cells[col_idx]
            cell.width = col_w[col_idx]
            set_cell_background(cell, bg)
            set_cell_margins(cell, top=60, bottom=60, left=100, right=100)
            p = cell.paragraphs[0]
            p.paragraph_format.space_after = Pt(0)
            r = p.add_run(cell_text)
            r.font.size = Pt(8.5)

    doc.add_paragraph().paragraph_format.space_after = Pt(2)

    # --- 3. CRYPTOGRAPHIC & SECURITY MECHANISMS ---
    add_heading("3. Cryptographic Verification & Defense Mechanisms")
    add_bullet(bold_prefix="Pre-Flight SHA-256 Anti-Tamper Gate: ", 
               text="Upon file upload, an immutable SHA-256 reference digest is computed chunk-by-chunk and committed to PostgreSQL. Prior to serving any download, FileGuard dynamically hashes the physical storage block. If an adversary alters even a single bit in storage, the stream is abruptly aborted, returning HTTP 409 Conflict.")
    add_bullet(bold_prefix="CSPRNG Tokenization & At-Rest Hash Isolation: ", 
               text="Public sharing tokens are generated via Python's secrets module (256-bit entropy formatted as XXXX-XXXX). The raw token is delivered exclusively to the uploader and never saved in plaintext; only its SHA-256 digest is indexed, rendering database dumps useless for link enumeration.")
    add_bullet(bold_prefix="In-Memory Multi-File & Folder Bundling: ", 
               text="Users can drop nested folder hierarchies directly into the upload zone. FileGuard auto-packages the contents dynamically into a standardized ZIP stream entirely in memory, preserving directory structures without writing unencrypted intermediate files to host storage.")
    add_bullet(bold_prefix="Subnet CIDR Quota Isolation: ", 
               text="To deter automated denial-of-service without compromising anonymity, incoming client IPs are normalized to /64 CIDR blocks (for IPv6) and /24 blocks (for IPv4). Each subnet is capped at 100 MB per rolling 12-hour window.")

    # --- 4. DIGITAL FORENSICS & SIEM TELEMETRY ---
    add_heading("4. Digital Forensics & Audit Telemetry")
    p4 = doc.add_paragraph()
    p4.add_run(
        "FileGuard incorporates a structured Security Information and Event Management (SIEM) module. Operating in the administrative portal, it records five audit tiers (INFO, LOW, MEDIUM, HIGH, CRITICAL) and maps external tampering attempts."
    )
    add_bullet(bold_prefix="Live Bit-Flip Attack Simulator: ", 
               text="An integrated forensic laboratory allows security evaluators to inject controlled 1-byte corruptions directly into Backblaze B2 storage blocks to observe the circuit breaker intercepting the download live.")
    add_bullet(bold_prefix="OS vs. Application Discrepancy Audits: ", 
               text="Cross-verifies PostgreSQL catalog timestamps against low-level filesystem inode metadata (stat ctime, mtime, atime) to detect out-of-band administrative tampering.")
    add_bullet(bold_prefix="Forensic Chain-of-Custody Export: ", 
               text="Generates signed JSON audit packages containing complete download attempts, IP headers, and integrity verifications for legal evidence trails.")

    # --- 5. CLOUD INFRASTRUCTURE & STORAGE OPTIMIZATIONS ---
    add_heading("5. Cloud Infrastructure & Storage Engineering")
    p5 = doc.add_paragraph()
    p5.add_run(
        "Production deployment on Render Web Services communicates with Backblaze B2 Object Storage and Neon Serverless PostgreSQL in the Asia-Pacific (Singapore) region. Multi-threaded transfer optimizations resolve traditional latency overhead:"
    )
    add_bullet(bold_prefix="10-Thread Parallel S3 Multipart Streaming: ", 
               text="Configured boto3.s3.transfer.TransferConfig with 10 concurrent threads and 256 KB memory buffers, reducing transmission latency for high-resolution images, video files, and dense ZIP archives.")
    add_bullet(bold_prefix="10 GB Capacity Tracker with 90% Threshold Alert: ", 
               text="Real-time capacity gauge continuously tallies active bytes against cloud tier quotas, accompanied by a 7-day dual-axis trajectory graph tracking cumulative data consumption.")
    add_bullet(bold_prefix="Zero-Downtime Conditional Schema Migrations: ", 
               text="Embedded dialect-aware DDL scripts inside init_db.py automatically sync missing database columns and indices during Render deployment cycles without data loss.")

    # --- 6. CLIENT-SIDE EPHEMERAL VAULT & FRONTEND ARCHITECTURE ---
    add_heading("6. Privacy-First Client Vault & UX Architecture")
    p6 = doc.add_paragraph()
    p6.add_run(
        "The frontend implements a high-contrast Neo-Brutalist design language constructed entirely in vanilla ES6+ JavaScript and CSS3 custom properties, achieving sub-second first-contentful paint without heavy JavaScript framework overhead."
    )
    add_bullet(bold_prefix="Dual-Tab LocalStorage Vault (/history): ", 
               text="Stores records of 'Uploaded By Me' and 'Shared With Me (Viewed)' directly on the client's device. No user profiles or personal tracking data are ever transmitted to the server.")
    add_bullet(bold_prefix="Batch Live Status Synchronization (/api/files/batch-status): ", 
               text="On page load, the history vault transmits up to 50 local tokens in a single JSON payload to query current state, updating live 1-second countdown tickers in real time.")
    add_bullet(bold_prefix="Instant 1-Click Early Purge: ", 
               text="Uploaders can immediately revoke and delete their active files from Backblaze B2 ahead of the 12-hour limit, triggering instant cloud deletion.")

    # --- 7. VERIFICATION, TESTING & METRICS ---
    add_heading("7. Verification, Testing & Empirical Results")
    p7 = doc.add_paragraph()
    p7.add_run(
        "The platform undergoes continuous regression verification using an automated Pytest test harness comprising 43 unit, penetration, and integration tests."
    )

    # Test Results Table
    test_table = doc.add_table(rows=5, cols=3)
    test_table.alignment = WD_TABLE_ALIGNMENT.CENTER
    test_headers = ["Testing Domain", "Test Cases Executed", "Observed Outcome & Status"]
    test_data = [
        ["Cryptographic Integrity", "Pre-flight match, bit-flip tampering, corrupted stream abort", "100% Pass — HTTP 409 Anti-Tamper successfully verified"],
        ["Authoritative Expiration", "12-hr deadline expiry, uncleaned disk access, purge sweeper", "100% Pass — HTTP 410 enforced; cloud storage unlinked"],
        ["Penetration & Hardening", "Subnet quota saturation, CSRF injection, path traversal", "100% Pass — Subnet 429 triggered; path traversal sanitized"],
        ["SEO & Discovery Gates", "robots.txt, sitemap.xml, llms.txt, JSON-LD Schema.org", "100% Pass — All crawler & AI discovery manifests verified"]
    ]

    for col_idx, h_text in enumerate(test_headers):
        cell = test_table.rows[0].cells[col_idx]
        set_cell_background(cell, "0F172A")
        set_cell_margins(cell, top=60, bottom=60, left=100, right=100)
        p = cell.paragraphs[0]
        p.paragraph_format.space_after = Pt(0)
        r = p.add_run(h_text)
        r.font.bold = True
        r.font.size = Pt(8.5)
        r.font.color.rgb = RGBColor(255, 255, 255)

    test_col_w = [Inches(2.0), Inches(2.7), Inches(2.4)]
    for row_idx, row_data in enumerate(test_data):
        row = test_table.rows[row_idx + 1]
        bg = "F8FAFC" if row_idx % 2 == 0 else "FFFFFF"
        for col_idx, cell_text in enumerate(row_data):
            cell = row.cells[col_idx]
            cell.width = test_col_w[col_idx]
            set_cell_background(cell, bg)
            set_cell_margins(cell, top=50, bottom=50, left=100, right=100)
            p = cell.paragraphs[0]
            p.paragraph_format.space_after = Pt(0)
            r = p.add_run(cell_text)
            r.font.size = Pt(8.5)

    doc.add_paragraph().paragraph_format.space_after = Pt(2)

    # --- 8. CONCLUSION & PRODUCTION LINKS ---
    add_heading("8. Conclusion & Project Deliverables")
    p8 = doc.add_paragraph()
    p8.add_run(
        "FileGuard demonstrates that temporary file sharing does not require compromising user privacy or accepting data corruption risks. By uniting strict 12-hour self-destruct routines, in-memory folder compression, SHA-256 pre-flight circuit breakers, and client-side vault architectures, the project establishes a production-hardened standard for zero-knowledge ephemeral computing."
    )

    callout_table = doc.add_table(rows=1, cols=1)
    callout_table.alignment = WD_TABLE_ALIGNMENT.CENTER
    c_cell = callout_table.rows[0].cells[0]
    c_cell.width = Inches(7.1)
    set_cell_background(c_cell, "F1F5F9")
    set_cell_margins(c_cell, top=80, bottom=80, left=120, right=120)
    cp = c_cell.paragraphs[0]
    cp.paragraph_format.space_after = Pt(0)
    r_c1 = cp.add_run("Project Verification Links: ")
    r_c1.font.bold = True
    r_c1.font.size = Pt(9)
    r_c2 = cp.add_run("Live Deployment: https://files.deeptanil.in  |  GitHub Repository: https://github.com/Deeptanil/FileGuard.git  |  AI Manifest: https://files.deeptanil.in/llms.txt")
    r_c2.font.size = Pt(9)

    out_file = "FileGuard_Project_Report.docx"
    doc.save(out_file)
    print(f"Successfully generated {out_file}")

if __name__ == "__main__":
    create_report()
