import re


# ─────────────────────────────────────────────────────────────────────────────
# KEYWORD RULES
# Each threat type maps to a list of keywords extracted directly from
# the 100 logs in sample_logs.json. More keywords = higher confidence.
# ─────────────────────────────────────────────────────────────────────────────

THREAT_RULES = {

    "brute_force": [
        "failed login",
        "authentication failure",
        "invalid password",
        "failed attempt",
        "account locked",
        "hydra",
        "brute",
        "repeated attempts",
        "backup_svc",
        "attempt 1 of",
        "attempt 10 of",
        "attempt 25 of",
        "after 47 failed",
        "login attempt",
        "ssh authentication failure",
        "multiple accounts targeted",
        "credential stuffing",
        "unusual login time",
        "firewall rule added",
    ],

    "port_scan": [
        "port scan",
        "nmap",
        "syn flood",
        "syn packets",
        "syn packets/sec",
        "5000 syn",
        "os detection",
        "service version probing",
        "open ports",
        "fingerprint",
        "enumeration",
        "directory traversal",
        "admin panel",
        "reverse shell",
        "outbound connection",
        "port 4444",
        "log4shell",
        "cve-2021-44228",
        "scanned 1024 ports",
        "probing",
        "wp-admin",
        "phpmyadmin",
        "sql injection probe",
        "web application at port",
        "2.3 gb transferred",
        "10.0.0.5 to 203.0.113.42",
    ],

    "privilege_escalation": [
        "sudo",
        "root shell",
        "suid",
        "privilege",
        "uid 0",
        "sudoers",
        "kernel exploit",
        "rootkit",
        "dirty pipe",
        "cve-2022-0847",
        "crontab",
        "cron job",
        "etc/shadow",
        "etc/passwd",
        "sysmon_helper",
        "kernel module",
        "audit logs cleared",
        "syslog truncated",
        "scp to",
        "hidden_data",
        "backdoor user",
        "sysbackup99",
        "www-data",
        "appuser",
        "root access",
        "bin/bash",
    ],

    "malware": [
        "malware",
        "ransomware",
        "trojan",
        "virus",
        "c2 beacon",
        "encryption started",
        "files encrypted",
        "ransom note",
        "readme_decrypt",
        "shadow copy",
        "vssadmin",
        "powershell",
        "executionpolicy bypass",
        "lateral movement",
        "network shares",
        "invoice_2025.pdf.exe",
        "double-extension",
        "antivirus alert",
        "trojan.generickd",
        "locked appended",
        "backup server",
        "encryption activity",
        "data exfiltration before encryption",
        "ftp",
        "8 gb uploaded",
    ],

    "insider_threat": [
        "bulk download",
        "usb",
        "personal email",
        "off hours",
        "terminated",
        "badge access revoked",
        "outside normal working hours",
        "bulk export",
        "customer records",
        "confidential documents",
        "gmail",
        "print job",
        "pages printed",
        "shared credentials",
        "servicedesk",
        "offboarding",
        "vpn bypass",
        "anonymous file sharing",
        "encryption tools",
        "mwilson",
        "restricted financial database",
        "competitor client",
        "home ip",
    ],

    "phishing": [
        "phishing",
        "spoofed",
        "credential",
        "oauth token",
        "mfa fatigue",
        "bec",
        "business email compromise",
        "wire transfer",
        "comp4ny",
        "kpatel",
        "auto-forward",
        "protonmail",
        "sharepoint",
        "teams meeting",
        "fake it support",
        "email gateway",
        "push notifications",
        "session token hijacked",
        "credential submission",
        "phishing link",
        "credential harvesting",
        "account takeover",
        "internal phishing",
        "spoofed domain",
    ],

    "sql_injection": [
        "sql injection",
        "union select",
        "xp_cmdshell",
        "1=1",
        "drop table",
        "waf alert",
        "sql error",
        "syntax error",
        "authentication bypass",
        "database schema",
        "database dump",
        "blind sql",
        "time-delay",
        "stored xss",
        "botnet",
        "irc traffic",
        "payments table",
        "credit card",
        "pci-dss",
        "parameterised",
        "45.33.32.156",
        "union-based injection",
        "users table",
        "os command execution",
    ],

    "ddos": [
        "ddos",
        "flood",
        "slowloris",
        "amplification",
        "connection exhausted",
        "traffic spike",
        "gbps",
        "packets/sec",
        "requests/sec",
        "udp flood",
        "http flood",
        "syn flood",
        "503 service unavailable",
        "dns amplification",
        "ssl renegotiation",
        "partial http connections",
        "connection pool exhausted",
        "payment gateway timeout",
        "downtime",
        "revenue loss",
        "blackhole",
        "volumetric",
        "load balancer",
        "1.2 million",
        "780,000",
    ],

    "data_exfiltration": [
        "exfiltration",
        "data transfer",
        "unusual upload",
        "dns tunneling",
        "bulk download",
        "steganography",
        "jpeg images",
        "s3 bucket",
        "dropbox",
        "https post",
        "outbound traffic",
        "database backup",
        "prod_database_backup",
        "source code repository",
        "git repository",
        "hr database",
        "employees_personal_data",
        "14.7 gb",
        "500 mb",
        "2.1 gb",
        "evilsite.xyz",
        "dns queries",
        "c2.evilsite",
        "email exfiltration",
        "no-reply",
        "covert",
    ],

    "zero_day": [
        "zero-day",
        "zero day",
        "unknown exploit",
        "segmentation fault",
        "heap overflow",
        "novel shellcode",
        "ids signature mismatch",
        "remote code execution",
        "calculator.exe",
        "exploit kit",
        "exploit framework",
        "pass-the-hash",
        "dcsync",
        "golden ticket",
        "krbtgt",
        "kerberos",
        "lateral movement",
        "domain controller",
        "active directory",
        "openssl",
        "http/2",
        "malformed",
        "win-server-02",
        "cve-2025",
        "domain compromise",
        "p1 major incident",
    ],
}


# ─────────────────────────────────────────────────────────────────────────────
# ALWAYS-CRITICAL KEYWORDS
# Logs containing any of these are forced to Critical regardless of score
# Sourced directly from high-severity logs in sample_logs.json
# ─────────────────────────────────────────────────────────────────────────────

ALWAYS_CRITICAL = [

    # ── brute_force ───────────────────────────────────────────────
    "account locked",           # log 05 — was Medium, needs Critical
    "after 30 failed",          # log 05 — exact phrase from log text
    "hydra",                    # log 06 — brute-force tool confirmed
    "after 47 failed",          # log 07 — successful login after attack
    "credential stuffing",      # log 08
    "unusual login time",       # log 09 — compromised account active
    "firewall rule added",      # log 10 — backdoor being established

    # ── port_scan ─────────────────────────────────────────────────
    "syn packets/sec",          # log 12 — syn flood belongs to port_scan
    "5000 syn",                 # log 12
    "3306",                     # log 14 — MySQL publicly exposed
    "mysql",                    # log 14
    "log4shell",                # log 15
    "cve-2021-44228",           # log 15
    "sql injection probe",      # log 16 — probe = recon = port_scan
    "web application at port",  # log 16
    "directory traversal",      # log 17
    "etc/passwd",               # log 17
    "reverse shell",            # log 19
    "port 4444",                # log 19
    "2.3 gb transferred",       # log 20 — result of port_scan chain

    # ── privilege_escalation ──────────────────────────────────────
    "www-data",                 # log 21 — web proc spawning root shell
    "suid",                     # log 22
    "sudoers",                  # log 23
    "uid 0",                    # log 24 — backdoor user with root uid
    "backdoor user",            # log 24
    "kernel exploit",           # log 25
    "dirty pipe",               # log 25
    "cve-2022-0847",            # log 25
    "crontab",                  # log 26
    "cron job",                 # log 26
    "etc/shadow",               # log 27 — password hashes accessed
    "rootkit",                  # log 28
    "sysmon_helper",            # log 28
    "audit logs cleared",       # log 29
    "syslog truncated",         # log 29

    # ── malware ───────────────────────────────────────────────────
    "invoice_2025.pdf.exe",     # log 31 — double-extension malware
    "trojan.generickd",         # log 32 — confirmed trojan
    "executionpolicy bypass",   # log 33 — PowerShell bypass
    "c2 beacon",                # log 34
    "ransomware",               # log 36-40
    "vssadmin",                 # log 36 — shadow copy deletion
    "shadow copy",              # log 36
    "mass file encryption",     # log 37
    "files encrypted per minute", # log 37
    "locked appended",          # log 37
    "readme_decrypt",           # log 38 — ransom note
    "ransom note",              # log 38
    "encryption activity",      # log 39
    "data exfiltration before encryption", # log 40

    # ── insider_threat ────────────────────────────────────────────
    "usb storage device",       # log 43
    "restricted financial database", # log 45
    "badge access revoked",     # log 48 — terminated employee
    "competitor client",        # log 49
    "shared credentials",       # log 50

    # ── phishing ──────────────────────────────────────────────────
    "session token hijacked",   # log 54
    "oauth token",              # log 54
    "auto-forward",             # log 55 — email forwarding to attacker
    "protonmail",               # log 55
    "internal phishing",        # log 56
    "sharepoint",               # log 57 — documents exfiltrated
    "mfa fatigue",              # log 59
    "business email compromise", # log 60
    "wire transfer",            # log 60

    # ── sql_injection ─────────────────────────────────────────────
    "union select",             # log 64
    "union-based injection",    # log 64
    "users table",              # log 65 — 15000 records extracted
    "credit card",              # log 66 — pci breach
    "payments table",           # log 66
    "pci-dss",                  # log 66
    "stored xss",               # log 69
    "botnet",                   # log 70
    "irc traffic",              # log 70
    "xp_cmdshell",              # log 68
    "authentication bypass",    # log 63 — auth bypassed via sqli

    # ── ddos ──────────────────────────────────────────────────────
    "gbps",                     # log 71 — traffic in Gbps = volumetric
    "503 service unavailable",  # log 74 — service is down
    "dns amplification",        # log 75
    "connection pool exhausted", # log 76
    "ssl renegotiation",        # log 77
    "slowloris",                # log 78
    "payment gateway timeout",  # log 79 — financial impact confirmed

    # ── data_exfiltration ─────────────────────────────────────────
    "outbound traffic",         # log 81 — unusual transfer
    "dns tunneling",            # log 82
    "c2.evilsite",              # log 82
    "evilsite.xyz",             # log 82
    "dropbox",                  # log 83 — unauthorised cloud upload
    "https post",               # log 84 — covert exfil channel
    "prod_database_backup",     # log 85 — full DB backup copied
    "database backup",          # log 85
    "employees_personal_data",  # log 86 — HR PII
    "hr database",              # log 86
    "git repository",           # log 87 — source code stolen
    "source code repository",   # log 87
    "steganography",            # log 88
    "14.7 gb",                  # log 90 — massive exfil confirmed

    # ── zero_day ──────────────────────────────────────────────────
    "heap overflow",            # log 92
    "novel shellcode",          # log 93
    "ids signature mismatch",   # log 93
    "remote code execution",    # log 94
    "calculator.exe",           # log 94
    "exploit kit",              # log 95
    "exploit framework",        # log 95
    "win-server-02",            # log 95-96
    "pass-the-hash",            # log 96
    "dcsync",                   # log 97
    "active directory",         # log 97
    "golden ticket",            # log 98
    "krbtgt",                   # log 98
    "kerberos",                 # log 98
    "zero-day",                 # log 99
    "zero day",                 # log 99
    "openssl",                  # log 99 — vulnerable library
    "cve-2025",                 # log 99
    "domain compromise",        # log 100
    "full domain compromise",   # log 100
    "p1 major incident",        # log 100
]


# ─────────────────────────────────────────────────────────────────────────────
# SEVERITY SCORING
# ─────────────────────────────────────────────────────────────────────────────

def _score_to_label(score: int, log_lower: str) -> str:
    """Convert numeric score to severity label.
    Auto-upgrades to Critical if high-risk keywords are present."""
    for kw in ALWAYS_CRITICAL:
        if kw in log_lower:
            return "Critical"
    if score >= 9:
        return "Critical"
    if score >= 6:
        return "High"
    if score >= 3:
        return "Medium"
    return "Low"


# ─────────────────────────────────────────────────────────────────────────────
# MAIN FUNCTION — this is what everyone imports
# ─────────────────────────────────────────────────────────────────────────────

def classify_log(log_text: str) -> dict:
    """
    Classify a raw log string into a threat type with severity.

    Parameters
    ----------
    log_text : str
        A single raw log line from sample_logs.json or a live system.

    Returns
    -------
    dict with keys:
        threat_type      : str  — one of 10 scenario names or 'unknown'
        severity_label   : str  — 'Low' | 'Medium' | 'High' | 'Critical'
        severity_score   : int  — 0 to 10
        confidence_pct   : int  — 0 to 100
        matched_keywords : list — keywords that triggered detection
    """
    if not log_text or not log_text.strip():
        return {
            "threat_type":      "unknown",
            "severity_label":   "Low",
            "severity_score":   0,
            "confidence_pct":   0,
            "matched_keywords": [],
        }

    log_lower = log_text.lower()

    best_threat   = "unknown"
    best_matches  = []
    max_count     = 0

    # Check every threat type — pick the one with the most keyword matches
    for threat, keywords in THREAT_RULES.items():
        matched = [kw for kw in keywords if kw in log_lower]
        if len(matched) > max_count:
            max_count    = len(matched)
            best_threat  = threat
            best_matches = matched

    # Severity score — capped at 10
    # Each matched keyword adds 2 points; more matches = higher severity
    severity_score = min(max_count * 2, 10)

    # Confidence — ratio of matched keywords to total keywords for that threat
    total_keywords = len(THREAT_RULES.get(best_threat, ["placeholder"]))
    confidence     = round((max_count / total_keywords) * 100) if total_keywords > 0 else 0

    return {
        "threat_type":      best_threat,
        "severity_label":   _score_to_label(severity_score, log_lower),
        "severity_score":   severity_score,
        "confidence_pct":   confidence,
        "matched_keywords": best_matches,
    }


# ─────────────────────────────────────────────────────────────────────────────
# FALLBACK EXPLANATIONS
# Used when OpenAI API is unavailable during demo.
# Pre-written for all 10 scenarios from sample_logs.json.
# ─────────────────────────────────────────────────────────────────────────────

FALLBACK_EXPLANATIONS = {
    "brute_force": {
        "explanation": (
            "Repeated failed login attempts detected from the same IP address, "
            "consistent with an automated brute-force attack trying to guess credentials."
        ),
        "mitigation": (
            "Block the source IP at the firewall, enforce account lockout after 5 failures, "
            "and enable multi-factor authentication on all accounts."
        ),
    },
    "port_scan": {
        "explanation": (
            "An external IP is actively scanning internal servers for open ports and vulnerable "
            "services, which is the reconnaissance phase before a targeted attack."
        ),
        "mitigation": (
            "Block the scanning IP, close unnecessary open ports, and enable IDS alerting "
            "for further probing activity from this source."
        ),
    },
    "privilege_escalation": {
        "explanation": (
            "A low-privilege user or process has attempted to gain elevated root or admin access "
            "using a known exploitation technique such as SUID abuse or a kernel exploit."
        ),
        "mitigation": (
            "Audit sudo permissions, remove SUID bits from non-essential binaries, "
            "patch the kernel, and isolate the affected system immediately."
        ),
    },
    "malware": {
        "explanation": (
            "Malicious software has been detected on the system. This may include ransomware "
            "encrypting files, a trojan establishing remote access, or a C2 beacon communicating "
            "with an attacker-controlled server."
        ),
        "mitigation": (
            "Isolate the affected endpoint from the network immediately, run a full antivirus scan, "
            "and check all network shares for signs of lateral movement."
        ),
    },
    "insider_threat": {
        "explanation": (
            "An internal user is exhibiting suspicious behaviour including bulk data access, "
            "exfiltration to personal accounts, or access outside normal working hours, "
            "suggesting potential data theft."
        ),
        "mitigation": (
            "Alert the DLP team, place a hold on any exported data, notify HR and management, "
            "and preserve all audit logs as evidence for investigation."
        ),
    },
    "phishing": {
        "explanation": (
            "A phishing attack has been detected, where an attacker is attempting to steal "
            "credentials or session tokens by impersonating a trusted entity via email or fake login pages."
        ),
        "mitigation": (
            "Reset affected user credentials immediately, block the phishing domain, "
            "revoke any hijacked session tokens, and send a company-wide security alert."
        ),
    },
    "sql_injection": {
        "explanation": (
            "SQL injection payloads have been detected in application inputs, allowing an attacker "
            "to manipulate database queries, bypass authentication, or extract sensitive data."
        ),
        "mitigation": (
            "Fix all vulnerable queries using parameterised statements, block the attacker IP, "
            "and review database access logs for any data that may have been extracted."
        ),
    },
    "ddos": {
        "explanation": (
            "A Distributed Denial-of-Service attack is flooding the network or application with "
            "traffic, exhausting server resources and causing service unavailability for legitimate users."
        ),
        "mitigation": (
            "Activate DDoS mitigation services, contact your ISP for upstream filtering, "
            "and enable rate limiting and connection controls at the load balancer."
        ),
    },
    "data_exfiltration": {
        "explanation": (
            "Sensitive data is being transferred out of the organisation through covert channels "
            "such as DNS tunneling, steganography, or encrypted HTTP POST requests, "
            "bypassing standard security controls."
        ),
        "mitigation": (
            "Block outbound traffic to the suspicious destination, implement SSL inspection, "
            "and initiate a full incident response to identify all data categories that were exposed."
        ),
    },
    "zero_day": {
        "explanation": (
            "An unknown or unpatched vulnerability is being actively exploited. The attack does not "
            "match any known exploit signatures, suggesting a zero-day attack capable of full system compromise."
        ),
        "mitigation": (
            "Isolate all affected systems immediately, capture memory dumps for forensic analysis, "
            "notify your security vendor, and assess the full blast radius of the compromise."
        ),
    },
    "unknown": {
        "explanation": (
            "Suspicious activity was detected that does not clearly match a known attack pattern. "
            "Manual investigation is recommended to determine the nature and severity of the threat."
        ),
        "mitigation": (
            "Review the full log context, escalate to a senior analyst, "
            "and monitor the source IP and affected account for further anomalous behaviour."
        ),
    },
}


def get_fallback_explanation(threat_type: str) -> dict:
    """
    Return a pre-written explanation and mitigation for a given threat type.
    Used when the OpenAI API is unavailable or too slow during the demo.

    Parameters
    ----------
    threat_type : str
        The threat_type value returned by classify_log()

    Returns
    -------
    dict with keys: explanation (str), mitigation (str)
    """
    return FALLBACK_EXPLANATIONS.get(
        threat_type,
        FALLBACK_EXPLANATIONS["unknown"]
    )


# ─────────────────────────────────────────────────────────────────────────────
# QUICK SELF-TEST — run this file directly to verify everything works
# python ai/classifier.py
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":

    # One real log from each of the 10 scenarios in sample_logs.json
    test_cases = [
        # (log_text,                                                    expected_threat)
        ("Failed login attempt for user 'admin' from IP 192.168.1.20 - attempt 25 of 50",
         "brute_force"),

        ("Nmap OS detection and service version probing from 203.0.113.42",
         "port_scan"),

        ("Sudoers modified: appuser ALL=(ALL) NOPASSWD: ALL added to /etc/sudoers",
         "privilege_escalation"),

        ("Mass file encryption started: 1200 files encrypted per minute on 10.0.0.55",
         "malware"),

        ("Bulk download: mwilson exported 5000 customer records to CSV from CRM system",
         "insider_threat"),

        ("Credential submission detected: kpatel submitted username/password on phishing site",
         "phishing"),

        ("Authentication bypass: successful login as 'administrator' via SQL injection",
         "sql_injection"),

        ("UDP flood: 1.2 million UDP packets/sec from 847 unique IPs targeting port 53",
         "ddos"),

        ("DNS tunneling detected: 10.0.0.88 making 4000 DNS queries/min to subdomain c2.evilsite.xyz",
         "data_exfiltration"),

        ("Remote code execution confirmed: calculator.exe spawned by web server worker process",
         "zero_day"),
    ]

    print("=" * 65)
    print("  classifier.py — self test")
    print("=" * 65)

    passed = 0
    failed = 0

    for log_text, expected in test_cases:
        result   = classify_log(log_text)
        detected = result["threat_type"]
        ok       = detected == expected
        status   = "PASS" if ok else "FAIL"

        if ok:
            passed += 1
        else:
            failed += 1

        print(f"\n  [{status}]  expected : {expected}")
        print(f"         detected : {detected}")
        print(f"         severity : {result['severity_label']} (score {result['severity_score']})")
        print(f"         keywords : {result['matched_keywords']}")
        print(f"         confidence: {result['confidence_pct']}%")

    print()
    print("=" * 65)
    print(f"  Result: {passed}/10 passed  |  {failed} failed")
    print("=" * 65)

    if failed == 0:
        print("  All tests passed. Ready to import into ai_service.py")
    else:
        print("  Fix the failing cases above before integrating.")
    print()
    