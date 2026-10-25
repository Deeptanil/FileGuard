import docx
from docx.shared import Inches, Pt, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.oxml import parse_xml
from docx.oxml.ns import nsdecls

def set_cell_background(cell, hex_color):
    shading_xml = f'<w:shd {nsdecls("w")} w:fill="{hex_color}"/>'
    cell._tc.get_or_add_tcPr().append(parse_xml(shading_xml))

def set_cell_margins(cell, top=80, bottom=80, left=120, right=120):
    tcPr = cell._tc.get_or_add_tcPr()
    tcMar = parse_xml(
        f'<w:tcMar {nsdecls("w")}>'
        f'<w:top w:w="{top}" w:type="dxa"/>'
        f'<w:bottom w:w="{bottom}" w:type="dxa"/>'
        f'<w:left w:w="{left}" w:type="dxa"/>'
        f'<w:right w:w="{right}" w:type="dxa"/>'
        f'</w:tcMar>'
    )
    tcPr.append(tcMar)

def create_report():
    doc = docx.Document()

    # Page Margins: 0.7 inch for a clean, professional, compact 4-page report
    for section in doc.sections:
        section.top_margin = Inches(0.7)
        section.bottom_margin = Inches(0.7)
        section.left_margin = Inches(0.75)
        section.right_margin = Inches(0.75)

    # Base Typography - Standard Professional Academic Font (Calibri)
    normal_style = doc.styles['Normal']
    normal_style.font.name = 'Calibri'
    normal_style.font.size = Pt(10.5)
    normal_style.font.color.rgb = RGBColor(0, 0, 0)
    normal_style.paragraph_format.line_spacing = 1.15
    normal_style.paragraph_format.space_after = Pt(4)

    # 1. HEADER & METADATA
    title_p = doc.add_paragraph()
    title_p.paragraph_format.space_before = Pt(0)
    title_p.paragraph_format.space_after = Pt(2)
    run_title = title_p.add_run("FILEGUARD: SECURE EPHEMERAL FILE SHARING SYSTEM")
    run_title.font.size = Pt(16)
    run_title.font.bold = True
    run_title.font.color.rgb = RGBColor(0, 0, 0)

    sub_p = doc.add_paragraph()
    sub_p.paragraph_format.space_after = Pt(8)
    run_sub = sub_p.add_run("Cryptographic Integrity Monitoring, Digital Forensics & Ephemeral Cloud Architecture")
    run_sub.font.size = Pt(11)
    run_sub.font.bold = True
    run_sub.font.color.rgb = RGBColor(0, 0, 0)

    # Metadata & Student Information Table (Alphabetical Order)
    meta_table = doc.add_table(rows=4, cols=2)
    meta_table.alignment = WD_TABLE_ALIGNMENT.CENTER
    meta_table.autofit = False

    col_widths = [Inches(3.45), Inches(3.55)]
    meta_rows = [
        [("Course & Subject:", " Information & Network Security (INS)"),
         ("Class & Cohort:", " Class: IT-A, Semester - V, Year 3")],
        [("Group Member 1 (Alpha):", " Aaditya Abhijit (Student ID: 245811404)"),
         ("Group Member 2 (Alpha):", " Deeptanil Sinha (Student ID: 245811402)")],
        [("Live Production System:", " https://files.deeptanil.in"),
         ("Source Repository:", " https://github.com/Deeptanil/FileGuard.git")],
        [("Deployment Environment:", " Render Web Service, Neon PostgreSQL, Backblaze B2 S3"),
         ("Security Test Suite:", " 43 Automated Pytest Tests (100% Pass Rate)")]
    ]

    for row_idx, row in enumerate(meta_table.rows):
        for col_idx, cell in enumerate(row.cells):
            cell.width = col_widths[col_idx]
            set_cell_background(cell, "F8FAFC" if row_idx % 2 == 0 else "FFFFFF")
            set_cell_margins(cell, top=50, bottom=50, left=90, right=90)
            p = cell.paragraphs[0]
            p.paragraph_format.space_after = Pt(0)
            k, v = meta_rows[row_idx][col_idx]
            rk = p.add_run(k)
            rk.font.bold = True
            rk.font.size = Pt(8.5)
            rv = p.add_run(v)
            rv.font.size = Pt(8.5)

    doc.add_paragraph().paragraph_format.space_after = Pt(4)

    def add_heading(text, level=1):
        h = doc.add_paragraph()
        h.paragraph_format.space_before = Pt(8)
        h.paragraph_format.space_after = Pt(3)
        h.paragraph_format.keep_with_next = True
        r = h.add_run(text)
        r.font.bold = True
        r.font.color.rgb = RGBColor(0, 0, 0)
        if level == 1:
            r.font.size = Pt(12)
        else:
            r.font.size = Pt(10.5)
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

    # --- 1. ABSTRACT & PROBLEM STATEMENT ---
    add_heading("1. Abstract & Problem Statement")
    p1 = doc.add_paragraph()
    p1.add_run(
        "Temporary file transmission across open networks presents critical security vulnerabilities: persistent data exposure on remote servers, silent data corruption (bit-rot or malicious in-flight modification), unauthorized token enumeration, and intrusive user tracking. "
        "FileGuard is an academic and production-engineered web platform providing zero-knowledge temporary file sharing. It implements a strict 12-hour self-destruct lifecycle, pre-flight SHA-256 cryptographic verification, in-memory folder ZIP bundling, CIDR-masked subnet quota controls, and a digital forensics inspection lab."
    )

    # --- 2. ARCHITECTURAL OVERVIEW & SUBSYSTEM SPECIFICATIONS ---
    add_heading("2. Architectural Overview & Subsystem Specifications")
    p2 = doc.add_paragraph()
    p2.add_run(
        "The system coordinates web routing, object storage, and relational state without disk bottlenecks or unencrypted staging leaks:"
    )

    spec_table = doc.add_table(rows=6, cols=3)
    spec_table.alignment = WD_TABLE_ALIGNMENT.CENTER
    spec_headers = ["Subsystem", "Core Technology", "Security Function & Implementation"]
    spec_data = [
        ["Application Gateway", "Python 3.14 / Flask / Gunicorn", "Enforces CSPRNG tokenization, CSRF tokens, nosniff headers"],
        ["Relational State", "Neon Serverless PostgreSQL", "Stores SHA-256 token hashes, storage UUIDs, expiration timestamps"],
        ["Cloud Storage", "Backblaze B2 S3 (boto3)", "Multi-threaded multipart streaming (10 threads, 256 KB memory buffer)"],
        ["Integrity Engine", "SHA-256 Pre-Flight Gate", "Dynamic byte-level hash verification halting altered downloads (HTTP 409)"],
        ["Abuse Mitigation", "Flask-Limiter / Subnet Masking", "Anonymous quota protection: 100 MB per 12 hrs per /64 IPv6 or /24 IPv4"]
    ]

    for col_idx, h_text in enumerate(spec_headers):
        cell = spec_table.rows[0].cells[col_idx]
        set_cell_background(cell, "0F172A")
        set_cell_margins(cell, top=60, bottom=60, left=90, right=90)
        p = cell.paragraphs[0]
        p.paragraph_format.space_after = Pt(0)
        r = p.add_run(h_text)
        r.font.bold = True
        r.font.size = Pt(8.5)
        r.font.color.rgb = RGBColor(255, 255, 255)

    col_w = [Inches(1.5), Inches(2.2), Inches(3.3)]
    for row_idx, row_data in enumerate(spec_data):
        row = spec_table.rows[row_idx + 1]
        bg = "F8FAFC" if row_idx % 2 == 0 else "FFFFFF"
        for col_idx, cell_text in enumerate(row_data):
            cell = row.cells[col_idx]
            cell.width = col_w[col_idx]
            set_cell_background(cell, bg)
            set_cell_margins(cell, top=50, bottom=50, left=90, right=90)
            p = cell.paragraphs[0]
            p.paragraph_format.space_after = Pt(0)
            r = p.add_run(cell_text)
            r.font.size = Pt(8.5)

    doc.add_paragraph().paragraph_format.space_after = Pt(2)

    # --- 3. CRYPTOGRAPHIC & DEFENSIVE SECURITY MECHANISMS ---
    add_heading("3. Cryptographic Verification & Defensive Controls")
    add_bullet(bold_prefix="Pre-Flight SHA-256 Anti-Tamper Gate: ", 
               text="During upload, an authoritative SHA-256 reference hash is calculated chunk-by-chunk and committed to PostgreSQL. On download, the server hashes the storage block before streaming bytes to the client. Any 1-bit variance triggers an immediate HTTP 409 Anti-Tamper block, logs a CRITICAL security event, and aborts delivery.")
    add_bullet(bold_prefix="CSPRNG Tokenization & At-Rest Hash Isolation: ", 
               text="Sharing tokens are created via Python's secrets module (256-bit entropy formatted as XXXX-XXXX). The raw token is returned solely to the uploader and never saved in plaintext; only its SHA-256 digest is indexed in PostgreSQL, protecting active links against database disclosure.")
    add_bullet(bold_prefix="In-Memory Multi-File & Folder Bundling: ", 
               text="Users can drag-and-drop entire directory trees or multiple files up to 100 MB. FileGuard compresses them on the fly into an organized ZIP archive in memory, preserving folder paths without creating unencrypted temporary files on the host disk.")
    add_bullet(bold_prefix="CIDR Subnet Quota Enforcement: ", 
               text="To eliminate anonymous quota evasion via IPv6 rotation or dynamic IP reassignment, client IP addresses are normalized to /64 CIDR blocks (for IPv6) and /24 blocks (for IPv4). Each subnet is constrained to 100 MB per rolling 12-hour window.")

    # --- 4. DIGITAL FORENSICS & SIEM TELEMETRY ---
    add_heading("4. Digital Forensics & Audit Telemetry")
    p4 = doc.add_paragraph()
    p4.add_run(
        "The administrative module provides structured security monitoring and tamper investigation capabilities:"
    )
    add_bullet(bold_prefix="Interactive Bit-Flip Attack Simulator: ", 
               text="Enables evaluators to inject controlled 1-byte mutations into stored objects to observe real-time detection, HTTP 409 blocking, and automated forensic alert logging.")
    add_bullet(bold_prefix="Filesystem Inode & Metadata Auditing: ", 
               text="Cross-references database timestamps with low-level OS stat attributes (ctime, mtime, atime) to uncover unauthorized out-of-band administrative tampering.")
    add_bullet(bold_prefix="SIEM Audit Event Stream: ", 
               text="Records events across five severity tiers (INFO, LOW, MEDIUM, HIGH, CRITICAL) and four outcomes (SUCCESS, BLOCKED, WARNING, FAILURE) with client IP telemetry.")

    # --- 5. CLOUD INFRASTRUCTURE & STORAGE ENGINEERING ---
    add_heading("5. Cloud Infrastructure & Storage Engineering")
    add_bullet(bold_prefix="Multi-Threaded S3 Multipart Transfers: ", 
               text="Configured boto3 TransferConfig with 10 parallel threads and 256 KB memory buffers, drastically reducing latency for large document packages and video files.")
    add_bullet(bold_prefix="10 GB Capacity Monitor & 90% Threshold Alert: ", 
               text="Continuously tallies active storage consumption against Backblaze B2 bucket limits, displaying real-time metrics and a 7-day usage trajectory chart.")
    add_bullet(bold_prefix="Automated Conditional Schema Migrations: ", 
               text="Embedded DDL migration handlers inside init_db.py dynamically apply schema adjustments during Render build cycles, preventing schema drift on serverless PostgreSQL.")

    # --- 6. CLIENT-SIDE VAULT & UX ARCHITECTURE ---
    add_heading("6. Privacy-First Client Vault & User Experience")
    add_bullet(bold_prefix="Dual-Tab LocalStorage Vault (/history): ", 
               text="Records 'Uploaded By Me' and 'Shared With Me (Viewed)' directly in client-side localStorage. No user accounts, passwords, or personal profiling exist on the server.")
    add_bullet(bold_prefix="Live Batch Status Synchronization (/api/files/batch-status): ", 
               text="Queries up to 50 local tokens in a single JSON payload to update live status badges (Active, Expired, Revoked) and 1-second countdown tickers.")
    add_bullet(bold_prefix="1-Click Early Remote Revocation: ", 
               text="Uploaders can immediately purge their active files from Backblaze B2 ahead of the 12-hour deadline, instantly invalidating the link.")

    # --- 7. VERIFICATION, TESTING & TEAM CONTRIBUTIONS ---
    add_heading("7. Verification, Testing & Team Contributions")
    p7 = doc.add_paragraph()
    p7.add_run(
        "FileGuard was validated with an automated Pytest test suite of 43 test cases covering functional, security, and SEO domains (100% pass rate):"
    )

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
        set_cell_margins(cell, top=50, bottom=50, left=90, right=90)
        p = cell.paragraphs[0]
        p.paragraph_format.space_after = Pt(0)
        r = p.add_run(h_text)
        r.font.bold = True
        r.font.size = Pt(8.5)
        r.font.color.rgb = RGBColor(255, 255, 255)

    test_col_w = [Inches(1.8), Inches(2.7), Inches(2.5)]
    for row_idx, row_data in enumerate(test_data):
        row = test_table.rows[row_idx + 1]
        bg = "F8FAFC" if row_idx % 2 == 0 else "FFFFFF"
        for col_idx, cell_text in enumerate(row_data):
            cell = row.cells[col_idx]
            cell.width = test_col_w[col_idx]
            set_cell_background(cell, bg)
            set_cell_margins(cell, top=40, bottom=40, left=90, right=90)
            p = cell.paragraphs[0]
            p.paragraph_format.space_after = Pt(0)
            r = p.add_run(cell_text)
            r.font.size = Pt(8.5)

    doc.add_paragraph().paragraph_format.space_after = Pt(2)

    # Team Contributions (Alphabetical Order)
    add_heading("Team Member Contributions (Listed Alphabetically)", level=2)
    add_bullet(bold_prefix="Aaditya Abhijit (Student ID: 245811404): ", 
               text="Engineered the SHA-256 cryptographic pre-flight verification pipeline; built the OS filesystem inode metadata auditing module; created the interactive bit-flip tampering simulator; designed the structured SIEM security event logger; developed automated test suites for file tampering and missing file detection.")
    add_bullet(bold_prefix="Deeptanil Sinha (Student ID: 245811402): ", 
               text="Designed the end-to-end full-stack architecture and Neo-Brutalist UI; engineered the in-memory streaming ZIP packager for folder uploads; implemented CIDR-normalized subnet quota controls; integrated Neon Serverless PostgreSQL and Backblaze B2 S3 multipart transfers; developed the client-side localStorage vault with batch status synchronization.")

    # --- 8. CONCLUSION ---
    add_heading("8. Conclusion & Academic Verification")
    p8 = doc.add_paragraph()
    p8.add_run(
        "FileGuard demonstrates that temporary file sharing can achieve enterprise-grade security without sacrificing user convenience or privacy. By coupling strict 12-hour self-destruct routines, in-memory folder compression, pre-flight cryptographic validation, and zero-knowledge client vaults, FileGuard provides a robust reference implementation for Information & Network Security."
    )

    callout_table = doc.add_table(rows=1, cols=1)
    callout_table.alignment = WD_TABLE_ALIGNMENT.CENTER
    c_cell = callout_table.rows[0].cells[0]
    c_cell.width = Inches(7.0)
    set_cell_background(c_cell, "F1F5F9")
    set_cell_margins(c_cell, top=60, bottom=60, left=100, right=100)
    cp = c_cell.paragraphs[0]
    cp.paragraph_format.space_after = Pt(0)
    r_c1 = cp.add_run("Academic Verification Deliverables: ")
    r_c1.font.bold = True
    r_c1.font.size = Pt(8.5)
    r_c2 = cp.add_run("Production URL: https://files.deeptanil.in  |  Repository: https://github.com/Deeptanil/FileGuard.git  |  AI Manifest: https://files.deeptanil.in/llms.txt")
    r_c2.font.size = Pt(8.5)

    out_file = "FileGuard_Project_Report.docx"
    doc.save(out_file)
    print(f"Successfully generated {out_file}")

if __name__ == "__main__":
    create_report()
