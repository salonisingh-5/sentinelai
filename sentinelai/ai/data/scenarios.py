import json
import os

# ─────────────────────────────────────────────────────────────
# scenarios.py — SentinelAI Attack Scenario Definitions
# Person 4 (Backend) — owns this file
# Defines all 10 attack scenarios with ordered log sequences
# Used by POST /simulate endpoint
# ─────────────────────────────────────────────────────────────

# Load the sample_logs.json from the same folder as this file
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FILE_PATH = os.path.join(BASE_DIR, "sample_logs.json")


def load_logs(filepath):
    """Load and validate the sample_logs.json file."""
    if not os.path.exists(filepath):
        print(f"ERROR: File not found at: {filepath}")
        return None

    if os.path.getsize(filepath) == 0:
        print(f"ERROR: File is empty: {filepath}")
        return None

    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()

    if not content.strip():
        print("ERROR: File content is blank.")
        return None

    try:
        return json.loads(content)
    except json.JSONDecodeError as e:
        print(f"ERROR: JSON parse failed — {e}")
        return None


# ─────────────────────────────────────────────────────────────
# SCENARIO DEFINITIONS
# Each scenario has:
#   - name        : display name
#   - description : what the attack does
#   - log_ids     : all log IDs belonging to this scenario
#   - simulate_order : order to insert logs during /simulate
#   - delay_seconds  : pause between each log insert (for live feel)
#   - timeline    : attack stages for the incident view
# ─────────────────────────────────────────────────────────────

SCENARIOS = {

    "brute_force": {
        "name": "Brute Force Attack",
        "description": (
            "Attacker repeatedly guesses passwords using Hydra tool "
            "until gaining access to backup_svc, then establishes a backdoor"
        ),
        "log_ids": [1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
        "simulate_order": [1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
        "delay_seconds": 1,
        "timeline": [
            {"stage": "Initial Access Attempt",  "log_ids": [1, 2],       "description": "First failed logins detected"},
            {"stage": "Escalating Attack",        "log_ids": [3, 4, 5],    "description": "Repeated failures targeting root and admin"},
            {"stage": "Tool Identified",          "log_ids": [6],          "description": "Hydra brute-force tool fingerprinted"},
            {"stage": "Account Compromise",       "log_ids": [7, 8],       "description": "Successful login, multiple accounts targeted"},
            {"stage": "Post-Compromise Activity", "log_ids": [9, 10],      "description": "Attacker establishes persistent backdoor"},
        ],
    },

    "port_scan": {
        "name": "Port Scan to Intrusion",
        "description": (
            "Attacker scans network, discovers vulnerable services, exploits a web app, "
            "achieves reverse shell, and exfiltrates 2.3 GB"
        ),
        "log_ids": [11, 12, 13, 14, 15, 16, 17, 18, 19, 20],
        "simulate_order": [11, 12, 13, 14, 15, 16, 17, 18, 19, 20],
        "delay_seconds": 1,
        "timeline": [
            {"stage": "Reconnaissance",       "log_ids": [11, 12],         "description": "Port scanning and SYN flood"},
            {"stage": "Service Enumeration",  "log_ids": [13, 14],         "description": "OS fingerprinting, open ports mapped"},
            {"stage": "Vulnerability Probing","log_ids": [15, 16, 17, 18], "description": "CVEs and injection tested"},
            {"stage": "Exploitation",         "log_ids": [19],             "description": "Reverse shell established"},
            {"stage": "Data Exfiltration",    "log_ids": [20],             "description": "2.3 GB of data stolen"},
        ],
    },

    "privilege_escalation": {
        "name": "Insider Privilege Escalation",
        "description": (
            "Low-privilege user escalates to root, installs rootkit, "
            "clears logs, and exfiltrates 4.7 GB"
        ),
        "log_ids": [21, 22, 23, 24, 25, 26, 27, 28, 29, 30],
        "simulate_order": [21, 22, 23, 24, 25, 26, 27, 28, 29, 30],
        "delay_seconds": 1,
        "timeline": [
            {"stage": "Initial Privilege Attempt", "log_ids": [21, 22],    "description": "Sudo and SUID exploitation"},
            {"stage": "Persistence Established",   "log_ids": [23, 24],    "description": "Sudoers modified, backdoor user created"},
            {"stage": "Full System Compromise",    "log_ids": [25, 26],    "description": "Kernel exploit, cron backdoor"},
            {"stage": "Credential Theft",          "log_ids": [27],        "description": "Shadow file read"},
            {"stage": "Cover Tracks & Exfil",      "log_ids": [28, 29, 30],"description": "Rootkit, logs wiped, data stolen"},
        ],
    },

    "malware": {
        "name": "Ransomware Attack",
        "description": (
            "Phishing email delivers ransomware that spreads via network shares, "
            "deletes backups, encrypts 1200 files/min, and exfiltrates 8 GB"
        ),
        "log_ids": [31, 32, 33, 34, 35, 36, 37, 38, 39, 40],
        "simulate_order": [31, 32, 33, 34, 35, 36, 37, 38, 39, 40],
        "delay_seconds": 1,
        "timeline": [
            {"stage": "Payload Delivery",      "log_ids": [31, 32],          "description": "Malicious file downloaded and confirmed"},
            {"stage": "Execution & C2",        "log_ids": [33, 34],          "description": "PowerShell bypass, C2 beacon established"},
            {"stage": "Lateral Movement",      "log_ids": [35],              "description": "Spreading to network shares"},
            {"stage": "Pre-Encryption Prep",   "log_ids": [36],              "description": "Shadow copies deleted"},
            {"stage": "Encryption & Extortion","log_ids": [37, 38, 39, 40],  "description": "Files encrypted, ransom note, backup targeted, data exfil"},
        ],
    },

    "insider_threat": {
        "name": "Malicious Insider",
        "description": (
            "Disgruntled employee exfiltrates 5000 customer records via USB, "
            "email, and cloud storage before and after account termination"
        ),
        "log_ids": [41, 42, 43, 44, 45, 46, 47, 48, 49, 50],
        "simulate_order": [41, 42, 43, 44, 45, 46, 47, 48, 49, 50],
        "delay_seconds": 1,
        "timeline": [
            {"stage": "Anomalous Access",        "log_ids": [41, 42],       "description": "After-hours bulk data access"},
            {"stage": "Data Theft Attempts",     "log_ids": [43, 44],       "description": "USB connection, personal email forwarding"},
            {"stage": "Escalation Attempts",     "log_ids": [45, 46],       "description": "Restricted DB access, researching evasion"},
            {"stage": "Cover Tracks",            "log_ids": [47],           "description": "Bulk printing of sensitive data"},
            {"stage": "Post-Termination Access", "log_ids": [48, 49, 50],   "description": "Remote access after badge revoked"},
        ],
    },

    "phishing": {
        "name": "Phishing & Account Takeover",
        "description": (
            "Spoofed email compromises employee credentials leading to M365 account takeover, "
            "BEC fraud attempt of $47,000, and internal phishing"
        ),
        "log_ids": [51, 52, 53, 54, 55, 56, 57, 58, 59, 60],
        "simulate_order": [51, 52, 53, 54, 55, 56, 57, 58, 59, 60],
        "delay_seconds": 1,
        "timeline": [
            {"stage": "Phishing Delivery",  "log_ids": [51, 52],       "description": "Spoofed email sent, user clicks link"},
            {"stage": "Credential Theft",   "log_ids": [53, 54],       "description": "Credentials submitted, session token hijacked"},
            {"stage": "Mailbox Compromise", "log_ids": [55, 56],       "description": "Auto-forward rule, internal phishing launched"},
            {"stage": "Data Theft",         "log_ids": [57, 58],       "description": "Documents downloaded, fake support call"},
            {"stage": "Financial Fraud",    "log_ids": [59, 60],       "description": "MFA fatigue attack, BEC wire transfer request"},
        ],
    },

    "sql_injection": {
        "name": "SQL Injection to Full DB Compromise",
        "description": (
            "SQL injection bypasses authentication, extracts 15,000 user records "
            "and 3,200 payment cards, then achieves OS-level command execution"
        ),
        "log_ids": [61, 62, 63, 64, 65, 66, 67, 68, 69, 70],
        "simulate_order": [61, 62, 63, 64, 65, 66, 67, 68, 69, 70],
        "delay_seconds": 1,
        "timeline": [
            {"stage": "Probing Phase",         "log_ids": [61, 62],       "description": "WAF detection and SQL error confirmation"},
            {"stage": "Authentication Bypass", "log_ids": [63],           "description": "Admin login without credentials"},
            {"stage": "Data Extraction",       "log_ids": [64, 65, 66],   "description": "Schema dump, users and payments extracted"},
            {"stage": "Blind Injection",       "log_ids": [67],           "description": "Time-based blind injection on API"},
            {"stage": "Full Compromise",       "log_ids": [68, 69, 70],   "description": "OS command execution, stored XSS, botnet"},
        ],
    },

    "ddos": {
        "name": "DDoS Attack (47-min Outage)",
        "description": (
            "Multi-vector DDoS combining UDP flood, HTTP flood, DNS amplification, "
            "and Slowloris causes 47-minute outage with $94,000 revenue loss"
        ),
        "log_ids": [71, 72, 73, 74, 75, 76, 77, 78, 79, 80],
        "simulate_order": [71, 72, 73, 74, 75, 76, 77, 78, 79, 80],
        "delay_seconds": 1,
        "timeline": [
            {"stage": "Attack Start",         "log_ids": [71, 72],       "description": "Traffic spike, UDP flood begins"},
            {"stage": "Application Layer",    "log_ids": [73, 74],       "description": "HTTP flood, service goes down"},
            {"stage": "Amplification",        "log_ids": [75, 76],       "description": "DNS amplification, DB connections exhausted"},
            {"stage": "Layer 7 Attacks",      "log_ids": [77, 78],       "description": "SSL renegotiation, Slowloris"},
            {"stage": "Business Impact",      "log_ids": [79, 80],       "description": "Payment gateway failure, attack ends"},
        ],
    },

    "data_exfiltration": {
        "name": "Multi-Channel Data Exfiltration",
        "description": (
            "Sophisticated attacker uses DNS tunneling, steganography, and 3 other channels "
            "to exfiltrate 14.7 GB including HR data, source code, and payment cards"
        ),
        "log_ids": [81, 82, 83, 84, 85, 86, 87, 88, 89, 90],
        "simulate_order": [81, 82, 83, 84, 85, 86, 87, 88, 89, 90],
        "delay_seconds": 1,
        "timeline": [
            {"stage": "Initial Detection",    "log_ids": [81],           "description": "Unusual outbound traffic noticed"},
            {"stage": "Covert Channels",      "log_ids": [82, 83, 84],   "description": "DNS tunneling, Dropbox, HTTPS POST"},
            {"stage": "Sensitive Data",       "log_ids": [85, 86, 87],   "description": "DB backup, HR records, source code"},
            {"stage": "Evasion Techniques",   "log_ids": [88, 89],       "description": "Steganography, email exfiltration"},
            {"stage": "Summary",              "log_ids": [90],           "description": "14.7 GB exfiltrated via 5 channels"},
        ],
    },

    "zero_day": {
        "name": "Zero-Day Exploit to Full Domain Compromise",
        "description": (
            "Unknown OpenSSL vulnerability exploited to gain RCE, pivot to 47 servers "
            "via Pass-the-Hash, extract all AD credentials via Golden Ticket attack"
        ),
        "log_ids": [91, 92, 93, 94, 95, 96, 97, 98, 99, 100],
        "simulate_order": [91, 92, 93, 94, 95, 96, 97, 98, 99, 100],
        "delay_seconds": 1,
        "timeline": [
            {"stage": "Zero-Day Discovery", "log_ids": [91, 92, 93],    "description": "Crash, heap overflow, unknown shellcode"},
            {"stage": "Initial Compromise", "log_ids": [94, 95],        "description": "RCE confirmed, exploit toolkit uploaded"},
            {"stage": "Lateral Movement",   "log_ids": [96, 97],        "description": "Pass-the-Hash to 4 servers, DC targeted"},
            {"stage": "Domain Takeover",    "log_ids": [98],            "description": "Golden Ticket forged, 10-year validity"},
            {"stage": "Full Compromise",    "log_ids": [99, 100],       "description": "CVE published, all 47 systems compromised"},
        ],
    },
}


# ─────────────────────────────────────────────────────────────
# HELPER FUNCTIONS
# These are imported by P4 backend's simulate.py and incidents.py
# ─────────────────────────────────────────────────────────────

def get_scenario(scenario_key: str) -> dict:
    """Return a single scenario definition by key."""
    if scenario_key not in SCENARIOS:
        raise KeyError(f"Scenario '{scenario_key}' not found. Available: {list(SCENARIOS.keys())}")
    return SCENARIOS[scenario_key]


def get_simulate_logs(scenario_key: str, all_logs: list) -> list:
    """
    Given a scenario key and the full logs list from sample_logs.json,
    return logs in the correct simulate_order for that scenario.

    Usage in simulate.py:
        logs = get_simulate_logs("brute_force", data["logs"])
    """
    scenario = get_scenario(scenario_key)
    order = scenario["simulate_order"]
    log_map = {log["id"]: log for log in all_logs}
    return [log_map[log_id] for log_id in order if log_id in log_map]


def get_all_scenario_keys() -> list:
    """Return list of all scenario keys — useful for dropdown in frontend."""
    return list(SCENARIOS.keys())


# ─────────────────────────────────────────────────────────────
# SELF-TEST — run this file directly to verify everything works
# Command: python scenarios.py
# ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 60)
    print("SentinelAI — scenarios.py self-test")
    print("=" * 60)

    # Step 1: Load the JSON
    data = load_logs(FILE_PATH)
    if data is None:
        print("\nFAILED: Could not load sample_logs.json")
        print(f"Make sure sample_logs.json is in the same folder as this file:")
        print(f"  Expected path: {FILE_PATH}")
        exit(1)

    print(f"\n✅ sample_logs.json loaded successfully")
    print(f"   Total logs     : {len(data['logs'])}")
    print(f"   Total scenarios: {len(data['scenarios'])}")

    # Step 2: Check all 10 scenarios exist
    print(f"\n{'─'*60}")
    print("Checking all 10 scenarios...")
    print(f"{'─'*60}")

    all_good = True
    for key, scenario in SCENARIOS.items():
        simulate_logs = get_simulate_logs(key, data["logs"])
        log_count = len(simulate_logs)
        status = "✅" if log_count == 10 else "❌"
        if log_count != 10:
            all_good = False
        print(f"  {status}  {key:<25} | {log_count} logs | {scenario['name']}")

    # Step 3: Check total log coverage
    print(f"\n{'─'*60}")
    all_covered_ids = []
    for scenario in SCENARIOS.values():
        all_covered_ids.extend(scenario["log_ids"])

    covered = set(all_covered_ids)
    expected = set(range(1, 101))
    missing = expected - covered

    print(f"Total log IDs covered: {len(covered)} / 100")
    if missing:
        print(f"❌ Missing log IDs: {sorted(missing)}")
        all_good = False
    else:
        print(f"✅ All 100 log IDs accounted for")

    # Step 4: Print a sample simulate sequence
    print(f"\n{'─'*60}")
    print("Sample simulate order for: brute_force")
    print(f"{'─'*60}")
    brute_logs = get_simulate_logs("brute_force", data["logs"])
    for i, log in enumerate(brute_logs, 1):
        print(f"  Step {i:>2} → [{log['severity']:<8}] {log['log_text'][:65]}")

    # Step 5: Final result
    print(f"\n{'=' * 60}")
    if all_good:
        print("✅ ALL CHECKS PASSED — scenarios.py is ready for backend P4")
        print("   Import in simulate.py with:")
        print("   from scenarios import SCENARIOS, get_simulate_logs")
    else:
        print("❌ SOME CHECKS FAILED — fix the issues above before handing over")
    print("=" * 60)