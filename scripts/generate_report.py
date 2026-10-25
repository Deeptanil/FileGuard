import os
import docx
from docx.shared import Pt, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH

BLACK = RGBColor(0, 0, 0)
WHITE = RGBColor(255, 255, 255)

def update_report(doc_path="FileGuard_Project_Report.docx"):
    """
    Updates FileGuard_Project_Report.docx preserving the Page 1 cover template,
    correcting the author name spelling to 'Aditya Abhijit', updating factual technical
    specifications, and applying standard academic typography (Times New Roman, 12pt body,
    14pt H1, 13pt H2, 10pt tables, 1.5 line spacing).
    """
    if not os.path.exists(doc_path):
        raise FileNotFoundError(f"Report document not found at {doc_path}")

    doc = docx.Document(doc_path)

    # 1. Update Page 1 author spelling on Paragraph 17 (preserving cover template)
    if len(doc.paragraphs) > 17:
        p17 = doc.paragraphs[17]
        p17.text = "Aditya Abhijit (245811404) & Deeptanil Sinha (245811402)"
        p17.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.CENTER

    # 2. Update Content of Pages 2+
    # P20: Heading 1
    p20 = doc.paragraphs[20]
    p20.text = "1. Abstract & Problem Statement"

    # P21: Body
    p21 = doc.paragraphs[21]
    p21.text = (
        "Temporary file transmission across open networks presents critical security vulnerabilities: "
        "persistent data exposure on remote servers, silent data corruption (bit-rot or malicious in-flight modification), "
        "unauthorized token enumeration, and intrusive user tracking. FileGuard is an academic and production-oriented "
        "web platform providing privacy-focused temporary file sharing. It implements transparent AES-256-GCM encryption "
        "at rest, strict 12-hour automated lifecycle purging, pre-flight SHA-256 cryptographic verification, in-memory "
        "folder ZIP bundling, client-IP upload quota controls, and an administrative digital forensics inspection lab."
    )

    # P22: Heading 1
    p22 = doc.paragraphs[22]
    p22.text = "2. Architectural Overview & Subsystem Specifications"

    # P23: Body
    p23 = doc.paragraphs[23]
    p23.text = "The system coordinates web routing, object storage, and relational state without disk bottlenecks or unencrypted staging leaks:"

    # Table 0: Architectural Subsystems
    spec_data = [
        ["Application Gateway", "Python 3.14 / Flask / Gunicorn", "Enforces CSPRNG tokenization, CSRF protection, nosniff & CSP defensive headers"],
        ["Relational State", "Neon Serverless PostgreSQL", "Stores SHA-256 token digests, storage UUIDs, password hashes, and expiration timestamps"],
        ["Cloud Storage", "Backblaze B2 S3 (boto3)", "Multi-threaded multipart streaming (10 threads, 256 KB memory buffer) with transparent AES-256-GCM encryption at rest"],
        ["Integrity Engine", "SHA-256 Pre-Flight Gate", "Dynamic byte-level hash verification halting altered downloads before delivery (HTTP 409)"],
        ["Abuse Mitigation", "Flask-Limiter / Client-IP Quota", "Strict rate limiting and 100 MB per rolling 12-hour quota allowance per client device (HTTP 429)"]
    ]
    t0 = doc.tables[0]
    for r_idx, row_data in enumerate(spec_data):
        row = t0.rows[r_idx + 1]
        for c_idx, val in enumerate(row_data):
            row.cells[c_idx].text = val

    # P25: Heading 1
    p25 = doc.paragraphs[25]
    p25.text = "3. Cryptographic Verification & Defensive Controls"

    # P26: Bullet
    p26 = doc.paragraphs[26]
    p26.text = ""
    r1 = p26.add_run("Pre-Flight SHA-256 Anti-Tamper Gate: ")
    r1.bold = True
    r2 = p26.add_run(
        "During upload, an authoritative SHA-256 reference hash is calculated chunk-by-chunk and committed to PostgreSQL. "
        "On download, the server hashes the storage block before streaming bytes to the client. Any 1-bit variance triggers an "
        "immediate HTTP 409 Anti-Tamper block, logs a CRITICAL security event, and aborts delivery."
    )

    # P27: Bullet
    p27 = doc.paragraphs[27]
    p27.text = ""
    r1 = p27.add_run("CSPRNG Tokenization & At-Rest Hash Isolation: ")
    r1.bold = True
    r2 = p27.add_run(
        "Sharing tokens are 8-digit human-friendly codes (approx. 26.4 bits entropy) generated via Python's secrets module "
        "(formatted as XXXX-XXXX). To protect active links against database disclosure, raw tokens are returned solely to the uploader "
        "and never saved in plaintext; only their 256-bit SHA-256 digests are indexed in PostgreSQL."
    )

    # P28: Bullet
    p28 = doc.paragraphs[28]
    p28.text = ""
    r1 = p28.add_run("In-Memory Multi-File & Folder Bundling: ")
    r1.bold = True
    r2 = p28.add_run(
        "Users can drag-and-drop entire directory trees or multiple files up to 100 MB. FileGuard compresses them on the fly into an "
        "organized ZIP archive in memory using io.BytesIO streams, preserving folder paths without creating unencrypted temporary "
        "files on the host disk."
    )

    # P29: Bullet
    p29 = doc.paragraphs[29]
    p29.text = ""
    r1 = p29.add_run("Client-IP Upload Quota Enforcement: ")
    r1.bold = True
    r2 = p29.add_run(
        "To mitigate anonymous upload abuse and resource exhaustion, client IP addresses are extracted (sanitizing reverse-proxy headers) "
        "and constrained to an aggregate 100 MB quota over a rolling 12-hour window. Excess volume is rejected with HTTP 429."
    )

    # P30: Heading 1
    p30 = doc.paragraphs[30]
    p30.text = "4. Digital Forensics & Audit Telemetry"

    # P31: Body
    p31 = doc.paragraphs[31]
    p31.text = "The administrative module provides structured security monitoring and tamper investigation capabilities:"

    # P32: Bullet
    p32 = doc.paragraphs[32]
    p32.text = ""
    r1 = p32.add_run("Interactive Bit-Flip Attack Simulator: ")
    r1.bold = True
    r2 = p32.add_run(
        "Enables evaluators to inject controlled 1-byte mutations into stored objects to observe real-time detection, HTTP 409 blocking, "
        "and automated forensic alert logging."
    )

    # P33: Bullet
    p33 = doc.paragraphs[33]
    p33.text = ""
    r1 = p33.add_run("Local Host Filesystem Inode & Metadata Auditing: ")
    r1.bold = True
    r2 = p33.add_run(
        "Cross-references database timestamps with low-level OS stat attributes (ctime, mtime, atime) across the host storage staging "
        "tier to uncover unauthorized out-of-band administrative tampering."
    )

    # P34: Bullet
    p34 = doc.paragraphs[34]
    p34.text = ""
    r1 = p34.add_run("Security Audit Event Logger: ")
    r1.bold = True
    r2 = p34.add_run(
        "Records events across five severity tiers (INFO, LOW, MEDIUM, HIGH, CRITICAL) and four outcomes (SUCCESS, BLOCKED, WARNING, FAILURE) "
        "with client IP telemetry."
    )

    # P35: Heading 1
    p35 = doc.paragraphs[35]
    p35.text = "5. Cloud Infrastructure & Storage Engineering"

    # P36: Bullet
    p36 = doc.paragraphs[36]
    p36.text = ""
    r1 = p36.add_run("Multi-Threaded S3 Multipart Transfers: ")
    r1.bold = True
    r2 = p36.add_run(
        "Configured boto3 TransferConfig with 10 parallel threads and 256 KB memory buffers, drastically reducing latency for large document "
        "packages and video files."
    )

    # P37: Bullet
    p37 = doc.paragraphs[37]
    p37.text = ""
    r1 = p37.add_run("10 GB Capacity Monitor & 90% Threshold Alert: ")
    r1.bold = True
    r2 = p37.add_run(
        "Continuously tallies active storage consumption against Backblaze B2 bucket limits, displaying real-time metrics and an automated "
        "7-day usage trajectory chart."
    )

    # P38: Bullet
    p38 = doc.paragraphs[38]
    p38.text = ""
    r1 = p38.add_run("Automated Conditional Schema Migrations: ")
    r1.bold = True
    r2 = p38.add_run(
        "Embedded DDL migration handlers dynamically apply schema adjustments during deployment cycles, preventing schema drift on "
        "serverless PostgreSQL."
    )

    # P39: Heading 1
    p39 = doc.paragraphs[39]
    p39.text = "6. Privacy-First Client Vault & User Experience"

    # P40: Bullet
    p40 = doc.paragraphs[40]
    p40.text = ""
    r1 = p40.add_run("Dual-Tab LocalStorage Vault (/history): ")
    r1.bold = True
    r2 = p40.add_run(
        "Records 'Uploaded By Me' and 'Shared With Me' directly in client-side localStorage. No user accounts, passwords, or personal profiling "
        "exist on the server."
    )

    # P41: Bullet
    p41 = doc.paragraphs[41]
    p41.text = ""
    r1 = p41.add_run("Live Batch Status Synchronization (/api/files/batch-status): ")
    r1.bold = True
    r2 = p41.add_run(
        "Queries up to 50 local tokens in a single JSON payload to update live status badges (Active, Expired, Revoked) and 1-second countdown tickers."
    )

    # P42: Bullet
    p42 = doc.paragraphs[42]
    p42.text = ""
    r1 = p42.add_run("1-Click Early Remote Revocation: ")
    r1.bold = True
    r2 = p42.add_run(
        "Uploaders can immediately purge their active files from Backblaze B2 ahead of the 12-hour deadline, instantly invalidating the link."
    )

    # P43: Heading 1
    p43 = doc.paragraphs[43]
    p43.text = "7. Verification, Testing & Team Contributions"

    # P44: Body
    p44 = doc.paragraphs[44]
    p44.text = (
        "FileGuard was validated with an automated Pytest test suite of 48 test cases covering functional, cryptographic integrity, "
        "security penetration (OWASP WSTG v4.2), and SEO domains (100% pass rate):"
    )

    # Table 1: Testing Table
    test_data = [
        ["Cryptographic Integrity", "Pre-flight match, bit-flip tampering, corrupted stream abort", "100% Pass — HTTP 409 Anti-Tamper successfully verified"],
        ["Authoritative Expiration", "12-hr deadline expiry, uncleaned disk access, purge sweeper", "100% Pass — HTTP 410 enforced; cloud storage unlinked"],
        ["Penetration & Hardening (OWASP WSTG v4.2)", "Subnet quota, CSRF bypass, path traversal, stored XSS, IDOR, SQL injection", "100% Pass — All 10 assessed OWASP vulnerability categories mitigated and verified resilient"],
        ["SEO & Discovery Gates", "robots.txt, sitemap.xml, llms.txt, JSON-LD Schema.org", "100% Pass — All crawler & AI discovery manifests verified"]
    ]
    t1 = doc.tables[1]
    for r_idx, row_data in enumerate(test_data):
        row = t1.rows[r_idx + 1]
        for c_idx, val in enumerate(row_data):
            row.cells[c_idx].text = val

    # P46: Heading 2
    p46 = doc.paragraphs[46]
    p46.text = "Team Member Contributions (Listed Alphabetically)"

    # P47: Bullet
    p47 = doc.paragraphs[47]
    p47.text = ""
    r1 = p47.add_run("Aditya Abhijit (Student ID: 245811404): ")
    r1.bold = True
    r2 = p47.add_run(
        "Engineered the SHA-256 cryptographic pre-flight verification pipeline; built the OS filesystem inode metadata auditing module; "
        "created the interactive bit-flip tampering simulator; designed the structured security audit event logger; developed automated test suites "
        "for file tampering and missing file detection."
    )

    # P48: Bullet
    p48 = doc.paragraphs[48]
    p48.text = ""
    r1 = p48.add_run("Deeptanil Sinha (Student ID: 245811402): ")
    r1.bold = True
    r2 = p48.add_run(
        "Designed the end-to-end full-stack architecture and Neo-Brutalist UI; engineered the in-memory streaming ZIP packager for folder uploads; "
        "implemented client-IP quota controls; integrated Neon Serverless PostgreSQL and Backblaze B2 S3 multipart transfers; developed the "
        "client-side localStorage vault with batch status synchronization."
    )

    # P49: Heading 1
    p49 = doc.paragraphs[49]
    p49.text = "8. Conclusion & Academic Verification"

    # P50: Body
    p50 = doc.paragraphs[50]
    p50.text = (
        "FileGuard demonstrates that temporary file sharing can achieve robust security without sacrificing user convenience or privacy. "
        "By coupling strict 12-hour automated purging, transparent AES-256-GCM encryption at rest, in-memory folder compression, pre-flight "
        "cryptographic validation, and anonymous client-side vaults, FileGuard provides a resilient reference implementation for Information & "
        "Network Security. A live preview can be inspected at: https://files.deeptanil.in"
    )

    # 3. Apply Rigorous Standard Typography across Pages 2+
    H1_PREFIXES = (
        "1. Abstract", "2. Architectural", "3. Cryptographic", "4. Digital",
        "5. Cloud", "6. Privacy", "7. Verification", "8. Conclusion"
    )
    H2_PREFIXES = ("Team Member",)

    for i in range(20, len(doc.paragraphs)):
        p = doc.paragraphs[i]
        text = p.text.strip()
        if not text:
            p.paragraph_format.space_before = Pt(0)
            p.paragraph_format.space_after = Pt(2)
            continue

        is_h1 = any(text.startswith(h) for h in H1_PREFIXES)
        is_h2 = any(text.startswith(h) for h in H2_PREFIXES)
        is_bullet = (p.style.name == 'List Bullet')

        if is_h1:
            p.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.LEFT
            p.paragraph_format.space_before = Pt(14)
            p.paragraph_format.space_after = Pt(4)
            p.paragraph_format.line_spacing = 1.15
            p.paragraph_format.keep_with_next = True
            for r in p.runs:
                r.font.name = "Times New Roman"
                r.font.size = Pt(14)
                r.font.bold = True
                r.font.color.rgb = BLACK

        elif is_h2:
            p.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.LEFT
            p.paragraph_format.space_before = Pt(12)
            p.paragraph_format.space_after = Pt(3)
            p.paragraph_format.line_spacing = 1.15
            p.paragraph_format.keep_with_next = True
            for r in p.runs:
                r.font.name = "Times New Roman"
                r.font.size = Pt(13)
                r.font.bold = True
                r.font.color.rgb = BLACK

        elif is_bullet:
            p.paragraph_format.space_before = Pt(2)
            p.paragraph_format.space_after = Pt(4)
            p.paragraph_format.line_spacing = 1.5
            for r in p.runs:
                r.font.name = "Times New Roman"
                r.font.size = Pt(12)
                r.font.color.rgb = BLACK

        else:
            # Normal body
            p.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
            p.paragraph_format.space_before = Pt(0)
            p.paragraph_format.space_after = Pt(6)
            p.paragraph_format.line_spacing = 1.5
            for r in p.runs:
                r.font.name = "Times New Roman"
                r.font.size = Pt(12)
                r.font.color.rgb = BLACK

    # Format all tables
    for t_idx, table in enumerate(doc.tables):
        for r_idx, row in enumerate(table.rows):
            is_header_row = (r_idx == 0)
            for cell in row.cells:
                for cp in cell.paragraphs:
                    cp.paragraph_format.line_spacing = 1.15
                    cp.paragraph_format.space_after = Pt(2)
                    for cr in cp.runs:
                        cr.font.name = "Times New Roman"
                        cr.font.size = Pt(10)
                        if is_header_row:
                            cr.font.color.rgb = WHITE
                            cr.font.bold = True
                        else:
                            cr.font.color.rgb = BLACK

    doc.save(doc_path)
    print(f"Report successfully updated and saved to {doc_path}")

if __name__ == "__main__":
    update_report()
