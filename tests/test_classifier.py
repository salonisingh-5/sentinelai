"""
test_classifier.py
==================
Full test suite for classifier.py — SentinelAI Project
100 tests covering all 10 attack scenarios from sample_logs.json
plus edge cases, return type checks, and severity validation.

Run from the project root folder:
    pytest ai/test_classifier.py -v

Or run with a summary:
    pytest ai/test_classifier.py -v --tb=short
"""

import sys
import os

# Make sure Python can find the ai/ package
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from classifier import classify_log, get_fallback_explanation


# =============================================================================
# HELPER — reusable assertion so every test stays one line
# =============================================================================

def check(log_text, expected_threat, expected_severities=None):
    """
    Run classify_log and assert threat_type matches expected_threat.
    Optionally assert severity_label is in expected_severities list.
    Also asserts the return dict has all required keys.
    """
    result = classify_log(log_text)

    # Must always return a dict
    assert isinstance(result, dict), f"Expected dict, got {type(result)}"

    # Must always have all 5 required keys
    required_keys = [
        "threat_type",
        "severity_label",
        "severity_score",
        "confidence_pct",
        "matched_keywords",
    ]
    for key in required_keys:
        assert key in result, f"Missing key '{key}' in result for log: {log_text[:60]}"

    # Threat type must match
    assert result["threat_type"] == expected_threat, (
        f"\nLog    : {log_text[:80]}\n"
        f"Got    : {result['threat_type']}\n"
        f"Expect : {expected_threat}\n"
        f"Keywords matched: {result['matched_keywords']}"
    )

    # Severity label must be one of the 4 valid values
    assert result["severity_label"] in ["Low", "Medium", "High", "Critical"], (
        f"Invalid severity_label: {result['severity_label']}"
    )

    # Severity score must be 0 to 10
    assert 0 <= result["severity_score"] <= 10, (
        f"severity_score out of range: {result['severity_score']}"
    )

    # Confidence must be 0 to 100
    assert 0 <= result["confidence_pct"] <= 100, (
        f"confidence_pct out of range: {result['confidence_pct']}"
    )

    # matched_keywords must be a list
    assert isinstance(result["matched_keywords"], list), (
        f"matched_keywords should be list, got {type(result['matched_keywords'])}"
    )

    # Optional severity check
    if expected_severities:
        assert result["severity_label"] in expected_severities, (
            f"\nLog      : {log_text[:80]}\n"
            f"Got      : {result['severity_label']}\n"
            f"Expected one of: {expected_severities}"
        )

    return result


# =============================================================================
# SCENARIO 1 — BRUTE FORCE (logs 1-10)
# =============================================================================

class TestBruteForce:

    def test_log_01_initial_failed_login(self):
        check(
            "Failed login attempt for user 'admin' from IP 192.168.1.20 - attempt 1 of 50",
            "brute_force",
            ["Low", "Medium", "High"],
        )

    def test_log_02_ten_failed_logins(self):
        check(
            "Failed login attempt for user 'admin' from IP 192.168.1.20 - attempt 10 of 50",
            "brute_force",
            ["Medium", "High"],
        )

    def test_log_03_twenty_five_failed_logins(self):
        check(
            "Failed login attempt for user 'admin' from IP 192.168.1.20 - attempt 25 of 50",
            "brute_force",
            ["High", "Critical"],
        )

    def test_log_04_ssh_root_failure(self):
        check(
            "SSH authentication failure: invalid password for root from 192.168.1.20 port 54321",
            "brute_force",
            ["High", "Critical"],
        )

    def test_log_05_account_locked(self):
        check(
            "Account 'admin' locked after 30 failed login attempts from 192.168.1.20",
            "brute_force",
            ["High", "Critical"],
        )

    def test_log_06_hydra_tool_detected(self):
        check(
            "Brute-force tool signature detected: Hydra/v9.4 user-agent from IP 192.168.1.20",
            "brute_force",
            ["High", "Critical"],
        )

    def test_log_07_successful_login_after_attempts(self):
        check(
            "Successful login for user 'backup_svc' from IP 192.168.1.20 after 47 failed attempts",
            "brute_force",
            ["Critical"],
        )

    def test_log_08_multiple_accounts_targeted(self):
        check(
            "Multiple accounts targeted from 192.168.1.20: admin, root, guest, backup_svc, dbadmin",
            "brute_force",
        )

    def test_log_09_unusual_login_time(self):
        check(
            "Unusual login time: user 'backup_svc' active at 02:01 AM from new device 192.168.1.20",
            "brute_force",
            ["High", "Critical"],
        )

    def test_log_10_firewall_rule_added(self):
        check(
            "Firewall rule added by 'backup_svc' to allow inbound traffic on port 4444",
            "brute_force",
            ["High", "Critical"],
        )


# =============================================================================
# SCENARIO 2 — PORT SCAN (logs 11-20)
# =============================================================================

class TestPortScan:

    def test_log_11_port_scan_1024(self):
        check(
            "Port scan: IP 203.0.113.42 scanned 1024 ports on 10.0.0.5 in 4 seconds",
            "port_scan",
            ["Medium", "High"],
        )

    def test_log_12_syn_flood(self):
        check(
            "SYN flood: 5000 SYN packets/sec from 203.0.113.42 targeting port 443",
            "port_scan",
            ["High", "Critical"],
        )

    def test_log_13_nmap_os_detection(self):
        check(
            "Nmap OS detection and service version probing from 203.0.113.42",
            "port_scan",
            ["High", "Critical"],
        )

    def test_log_14_open_ports_mysql_exposed(self):
        check(
            "Open ports on 10.0.0.5: 22 (SSH), 80 (HTTP), 443 (HTTPS), 3306 (MySQL), 8080 (HTTP-Alt)",
            "port_scan",
            ["High", "Critical"],
        )

    def test_log_15_log4shell_probe(self):
        check(
            "CVE-2021-44228 (Log4Shell) probe from 203.0.113.42 on port 8080",
            "port_scan",
            ["Critical"],
        )

    def test_log_16_sql_injection_probe(self):
        check(
            "SQL injection probe from 203.0.113.42 on web application at port 80",
            "port_scan",
        )

    def test_log_17_directory_traversal(self):
        check(
            "Directory traversal attempt from 203.0.113.42: GET /../../../../etc/passwd HTTP/1.1",
            "port_scan",
            ["High", "Critical"],
        )

    def test_log_18_admin_panel_enumeration(self):
        check(
            "Admin panel enumeration from 203.0.113.42: probing /admin /wp-admin /phpmyadmin",
            "port_scan",
            ["High", "Critical"],
        )

    def test_log_19_reverse_shell_established(self):
        check(
            "Reverse shell: outbound connection from 10.0.0.5 to 203.0.113.42 on port 4444",
            "port_scan",
            ["Critical"],
        )

    def test_log_20_data_exfil_via_port_scan(self):
        check(
            "Data exfiltration: 2.3 GB transferred from 10.0.0.5 to 203.0.113.42 over 10 minutes",
            "port_scan",
        )


# =============================================================================
# SCENARIO 3 — PRIVILEGE ESCALATION (logs 21-30)
# =============================================================================

class TestPrivilegeEscalation:

    def test_log_21_www_data_sudo(self):
        check(
            "User 'www-data' executed sudo /bin/bash without prior authorisation on server-01",
            "privilege_escalation",
            ["Critical"],
        )

    def test_log_22_suid_exploitation(self):
        check(
            "SUID exploitation: /usr/bin/find executed with -exec /bin/sh by user 'appuser'",
            "privilege_escalation",
            ["Critical"],
        )

    def test_log_23_sudoers_modified(self):
        check(
            "Sudoers modified: appuser ALL=(ALL) NOPASSWD: ALL added to /etc/sudoers",
            "privilege_escalation",
            ["Critical"],
        )

    def test_log_24_backdoor_user_created(self):
        check(
            "Backdoor user created: 'sysbackup99' added to /etc/passwd with UID 0",
            "privilege_escalation",
            ["Critical"],
        )

    def test_log_25_dirty_pipe_exploit(self):
        check(
            "Kernel exploit: CVE-2022-0847 (Dirty Pipe) binary executed on server-01 by appuser",
            "privilege_escalation",
            ["Critical"],
        )

    def test_log_26_crontab_backdoor(self):
        check(
            "Crontab modified by appuser: root cron job added to run reverse shell every 5 minutes",
            "privilege_escalation",
            ["Critical"],
        )

    def test_log_27_shadow_file_read(self):
        check(
            "Sensitive file read: /etc/shadow accessed by process running as 'appuser'",
            "privilege_escalation",
            ["High", "Critical"],
        )

    def test_log_28_rootkit_detected(self):
        check(
            "Rootkit detected: kernel module 'sysmon_helper.ko' loaded from /tmp by root process",
            "privilege_escalation",
            ["Critical"],
        )

    def test_log_29_audit_logs_cleared(self):
        check(
            "Audit logs cleared: /var/log/auth.log and /var/log/syslog truncated to zero bytes by root",
            "privilege_escalation",
            ["Critical"],
        )

    def test_log_30_data_exfil_via_scp(self):
        check(
            "Data exfiltration: 4.7 GB archive /tmp/.hidden_data.tar.gz transferred via SCP to 10.0.0.10",
            "privilege_escalation",
        )


# =============================================================================
# SCENARIO 4 — MALWARE / RANSOMWARE (logs 31-40)
# =============================================================================

class TestMalware:

    def test_log_31_double_extension_exe(self):
        check(
            "Suspicious executable detected: invoice_2025.pdf.exe downloaded by user jsmith from 185.220.101.5",
            "malware",
            ["High", "Critical"],
        )

    def test_log_32_antivirus_trojan_alert(self):
        check(
            "Antivirus alert: Trojan.GenericKD.47293821 detected in C:\\Users\\jsmith\\Downloads\\invoice_2025.pdf.exe",
            "malware",
            ["High", "Critical"],
        )

    def test_log_33_powershell_bypass(self):
        check(
            "PowerShell execution policy bypass: powershell -ExecutionPolicy Bypass -File C:\\temp\\update.ps1",
            "malware",
            ["High", "Critical"],
        )

    def test_log_34_c2_beacon(self):
        check(
            "C2 beacon detected: outbound HTTPS connection from 10.0.0.55 to 185.220.101.5 every 60 seconds",
            "malware",
            ["Critical"],
        )

    def test_log_35_lateral_movement_shares(self):
        check(
            "Lateral movement: malware spreading to 3 network shares: \\\\fileserver01\\share, \\\\fileserver02\\data",
            "malware",
            ["High", "Critical"],
        )

    def test_log_36_shadow_copy_deletion(self):
        check(
            "Shadow copy deletion: vssadmin delete shadows /all /quiet executed on 10.0.0.55",
            "malware",
            ["Critical"],
        )

    def test_log_37_mass_file_encryption(self):
        check(
            "Mass file encryption started: 1200 files encrypted per minute on 10.0.0.55, extension .locked appended",
            "malware",
            ["Critical"],
        )

    def test_log_38_ransom_note_created(self):
        check(
            "Ransom note created: README_DECRYPT.txt written to Desktop, Downloads, and Documents on 10.0.0.55",
            "malware",
            ["Critical"],
        )

    def test_log_39_ransomware_spreading_to_backup(self):
        check(
            "Ransomware spreading to backup server: encryption activity detected on backupserver-01",
            "malware",
            ["Critical"],
        )

    def test_log_40_data_exfil_before_encryption(self):
        check(
            "Data exfiltration before encryption: 8 GB uploaded from 10.0.0.55 to 185.220.101.5 via FTP",
            "malware",
        )


# =============================================================================
# SCENARIO 5 — INSIDER THREAT (logs 41-50)
# =============================================================================

class TestInsiderThreat:

    def test_log_41_after_hours_access(self):
        check(
            "User 'mwilson' accessed 340 customer records outside normal working hours at 11:48 PM",
            "insider_threat",
            ["Medium", "High"],
        )

    def test_log_42_bulk_csv_export(self):
        check(
            "Bulk download: mwilson exported 5000 customer records to CSV from CRM system",
            "insider_threat",
            ["High", "Critical"],
        )

    def test_log_43_usb_device_connected(self):
        check(
            "USB storage device connected to mwilson's workstation at 11:55 PM",
            "insider_threat",
            ["High", "Critical"],
        )

    def test_log_44_email_to_personal_gmail(self):
        check(
            "Email alert: mwilson forwarded 3 confidential documents to personal Gmail account mwilson88@gmail.com",
            "insider_threat",
            ["High", "Critical"],
        )

    def test_log_45_restricted_db_access_denied(self):
        check(
            "Access attempt to restricted financial database by mwilson - access denied (no clearance)",
            "insider_threat",
            ["High", "Critical"],
        )

    def test_log_46_vpn_bypass_search(self):
        check(
            "mwilson searched internal wiki for: VPN bypass, encryption tools, anonymous file sharing",
            "insider_threat",
            ["High", "Critical"],
        )

    def test_log_47_bulk_print_job(self):
        check(
            "Large print job by mwilson: 287 pages printed from customer database report at midnight",
            "insider_threat",
            ["Medium", "High"],
        )

    def test_log_48_post_termination_login(self):
        check(
            "mwilson's badge access revoked but account still active - login from home IP 88.99.100.55 at 1:20 AM",
            "insider_threat",
            ["Critical"],
        )

    def test_log_49_competitor_contact_list(self):
        check(
            "mwilson accessed competitor client contact list - 1200 records viewed in 8 minutes",
            "insider_threat",
            ["Critical"],
        )

    def test_log_50_shared_credentials_active(self):
        check(
            "Account mwilson disabled by IT after security alert, but shared credentials found active on servicedesk01",
            "insider_threat",
            ["Critical"],
        )


# =============================================================================
# SCENARIO 6 — PHISHING (logs 51-60)
# =============================================================================

class TestPhishing:

    def test_log_51_spoofed_email_to_42_users(self):
        check(
            "Email gateway alert: suspicious email received by 42 users, sender: it-support@comp4ny.com (spoofed)",
            "phishing",
            ["Medium", "High"],
        )

    def test_log_52_user_clicked_phishing_link(self):
        check(
            "User kpatel clicked phishing link in email: http://comp4ny-portal.xyz/login at 09:03 AM",
            "phishing",
            ["High", "Critical"],
        )

    def test_log_53_credential_submission(self):
        check(
            "Credential submission detected: kpatel submitted username/password on phishing site comp4ny-portal.xyz",
            "phishing",
            ["Critical"],
        )

    def test_log_54_oauth_token_theft(self):
        check(
            "OAuth token theft: kpatel Microsoft 365 session token hijacked, used from IP 91.210.45.33 (Romania)",
            "phishing",
            ["Critical"],
        )

    def test_log_55_email_auto_forward_rule(self):
        check(
            "Email rule created: all inbound emails auto-forwarded to attacker@protonmail.com from kpatel mailbox",
            "phishing",
            ["Critical"],
        )

    def test_log_56_internal_phishing_campaign(self):
        check(
            "Internal phishing: attacker using kpatel account to send phishing emails to 150 internal employees",
            "phishing",
            ["Critical"],
        )

    def test_log_57_sharepoint_documents_stolen(self):
        check(
            "SharePoint access: attacker downloaded 3 confidential strategy documents from kpatel SharePoint",
            "phishing",
            ["High", "Critical"],
        )

    def test_log_58_fake_teams_meeting(self):
        check(
            "Teams meeting invite sent by kpatel account: fake IT support session requesting remote access",
            "phishing",
            ["High", "Critical"],
        )

    def test_log_59_mfa_fatigue_attack(self):
        check(
            "MFA fatigue attack: kpatel received 27 MFA push notifications in 10 minutes from IP 91.210.45.33",
            "phishing",
            ["Critical"],
        )

    def test_log_60_bec_wire_transfer(self):
        check(
            "Business Email Compromise: attacker using kpatel account requested $47,000 wire transfer to CFO",
            "phishing",
            ["Critical"],
        )


# =============================================================================
# SCENARIO 7 — SQL INJECTION (logs 61-70)
# =============================================================================

class TestSQLInjection:

    def test_log_61_waf_sql_pattern(self):
        check(
            "WAF alert: SQL injection pattern detected in login form parameter from IP 45.33.32.156",
            "sql_injection",
            ["Medium", "High"],
        )

    def test_log_62_sql_error_or_1_equals_1(self):
        check(
            "SQL error logged: syntax error near ' OR 1=1-- in query from 45.33.32.156",
            "sql_injection",
            ["High", "Critical"],
        )

    def test_log_63_auth_bypass_admin(self):
        check(
            "Authentication bypass: successful login as 'administrator' via SQL injection from 45.33.32.156",
            "sql_injection",
            ["Critical"],
        )

    def test_log_64_union_select_schema_dump(self):
        check(
            "UNION SELECT attack: attacker extracting database schema via UNION-based injection from 45.33.32.156",
            "sql_injection",
            ["Critical"],
        )

    def test_log_65_users_table_15000_rows(self):
        check(
            "Database dump: attacker extracted users table with 15,000 rows via SQL injection from 45.33.32.156",
            "sql_injection",
            ["Critical"],
        )

    def test_log_66_credit_card_data_extracted(self):
        check(
            "Credit card data accessed: payments table extracted via SQL injection - 3,200 card records",
            "sql_injection",
            ["Critical"],
        )

    def test_log_67_blind_sql_time_delay(self):
        check(
            "Blind SQL injection detected: boolean-based time-delay attacks from 45.33.32.156 on /api/products",
            "sql_injection",
            ["High", "Critical"],
        )

    def test_log_68_xp_cmdshell_os_execution(self):
        check(
            "OS command execution via SQL: xp_cmdshell enabled and executed by attacker on MSSQL server",
            "sql_injection",
            ["Critical"],
        )

    def test_log_69_stored_xss_via_sql(self):
        check(
            "Stored XSS injected via SQL: malicious JavaScript inserted into product descriptions table",
            "sql_injection",
            ["High", "Critical"],
        )

    def test_log_70_db_server_botnet(self):
        check(
            "Database server added to botnet: outbound IRC traffic to 45.33.32.156 from database server",
            "sql_injection",
            ["Critical"],
        )


# =============================================================================
# SCENARIO 8 — DDOS (logs 71-80)
# =============================================================================

class TestDDoS:

    def test_log_71_traffic_spike_gbps(self):
        check(
            "Traffic spike: inbound traffic increased from 200 Mbps to 9.4 Gbps in 30 seconds",
            "ddos",
            ["High", "Critical"],
        )

    def test_log_72_udp_flood_dns(self):
        check(
            "UDP flood: 1.2 million UDP packets/sec from 847 unique IPs targeting port 53 (DNS)",
            "ddos",
            ["High", "Critical"],
        )

    def test_log_73_http_flood_780k(self):
        check(
            "HTTP flood: 780,000 requests/sec to https://company.com/login from bot network",
            "ddos",
            ["High", "Critical"],
        )

    def test_log_74_web_server_503(self):
        check(
            "Web server down: company.com returning 503 Service Unavailable, response time >30 seconds",
            "ddos",
            ["High", "Critical"],
        )

    def test_log_75_dns_amplification_380gbps(self):
        check(
            "DNS amplification: attacker using open resolvers to amplify attack 40x, 380 Gbps traffic",
            "ddos",
            ["Critical"],
        )

    def test_log_76_db_connection_pool_exhausted(self):
        check(
            "Database connection pool exhausted: all 500 DB connections occupied by flood requests",
            "ddos",
            ["High", "Critical"],
        )

    def test_log_77_ssl_renegotiation_cpu_100(self):
        check(
            "SSL renegotiation attack: attacker forcing expensive SSL handshakes, CPU at 100% on load balancer",
            "ddos",
            ["High", "Critical"],
        )

    def test_log_78_slowloris_partial_connections(self):
        check(
            "Slowloris attack detected: 12,000 partial HTTP connections kept open from 345 IPs",
            "ddos",
            ["High", "Critical"],
        )

    def test_log_79_payment_gateway_timeout(self):
        check(
            "Payment gateway timeout: all payment transactions failing due to DDoS impact on API gateway",
            "ddos",
            ["Critical"],
        )

    def test_log_80_attack_subsiding_revenue_loss(self):
        check(
            "Attack subsiding: traffic returning to 1.2 Gbps. Total downtime: 47 minutes. Estimated revenue loss: $94,000",
            "ddos",
            ["High", "Critical"],
        )


# =============================================================================
# SCENARIO 9 — DATA EXFILTRATION (logs 81-90)
# =============================================================================

class TestDataExfiltration:

    def test_log_81_unusual_outbound_500mb(self):
        check(
            "Unusual outbound traffic: 10.0.0.88 transferring 500 MB to unknown external IP 91.108.4.77",
            "data_exfiltration",
            ["High", "Critical"],
        )

    def test_log_82_dns_tunneling(self):
        check(
            "DNS tunneling detected: 10.0.0.88 making 4000 DNS queries/min to subdomain c2.evilsite.xyz",
            "data_exfiltration",
            ["Critical"],
        )

    def test_log_83_dropbox_upload(self):
        check(
            "Cloud storage upload: 2.1 GB uploaded to Dropbox from server 10.0.0.88 outside business hours",
            "data_exfiltration",
            ["High", "Critical"],
        )

    def test_log_84_https_post_exfil(self):
        check(
            "HTTPS exfiltration: data encoded in HTTPS POST body to 91.108.4.77, 180 requests in 5 minutes",
            "data_exfiltration",
            ["High", "Critical"],
        )

    def test_log_85_db_backup_copied(self):
        check(
            "Database backup file copied: prod_database_backup_2025.sql.gz accessed by unauthorised process",
            "data_exfiltration",
            ["Critical"],
        )

    def test_log_86_hr_pii_8400_records(self):
        check(
            "Employee PII accessed: HR database table employees_personal_data queried for all 8,400 records",
            "data_exfiltration",
            ["Critical"],
        )

    def test_log_87_git_repo_cloned(self):
        check(
            "Source code repository cloned: entire Git repository company-core-product cloned by unknown IP",
            "data_exfiltration",
            ["Critical"],
        )

    def test_log_88_steganography_jpeg(self):
        check(
            "Steganography detected: 140 JPEG images with hidden encoded data uploaded to public S3 bucket",
            "data_exfiltration",
            ["High", "Critical"],
        )

    def test_log_89_email_exfiltration(self):
        check(
            "Email exfiltration: 44 emails with attachments sent to external domain from no-reply@company.com",
            "data_exfiltration",
            ["High", "Critical"],
        )

    def test_log_90_total_147gb_5_channels(self):
        check(
            "Total exfiltration summary: 14.7 GB data transferred out of network over 45 minutes via 5 channels",
            "data_exfiltration",
            ["Critical"],
        )


# =============================================================================
# SCENARIO 10 — ZERO DAY (logs 91-100)
# =============================================================================

class TestZeroDay:

    def test_log_91_http2_segfault(self):
        check(
            "Unknown exploit: web server crashed with segmentation fault from malformed HTTP/2 header from 5.188.62.14",
            "zero_day",
            ["High", "Critical"],
        )

    def test_log_92_heap_overflow_openssl(self):
        check(
            "Heap overflow detected: abnormal memory allocation pattern in OpenSSL library on port 443 from 5.188.62.14",
            "zero_day",
            ["Critical"],
        )

    def test_log_93_novel_shellcode(self):
        check(
            "Novel shellcode detected: IDS signature mismatch - payload does not match any known exploit signatures",
            "zero_day",
            ["Critical"],
        )

    def test_log_94_rce_calculator_exe(self):
        check(
            "Remote code execution confirmed: calculator.exe spawned by web server worker process on WIN-SERVER-02",
            "zero_day",
            ["Critical"],
        )

    def test_log_95_exploit_kit_uploaded(self):
        check(
            "Exploit kit deployed: attacker uploaded exploit framework tools to C:\\Windows\\Temp\\ on WIN-SERVER-02",
            "zero_day",
            ["Critical"],
        )

    def test_log_96_pass_the_hash(self):
        check(
            "Lateral movement: attacker pivoting from WIN-SERVER-02 to 4 internal servers using Pass-the-Hash technique",
            "zero_day",
            ["Critical"],
        )

    def test_log_97_dcsync_ad_credentials(self):
        check(
            "Domain controller targeted: attacker attempting DCSync attack to dump all AD credentials from DC-01",
            "zero_day",
            ["Critical"],
        )

    def test_log_98_golden_ticket(self):
        check(
            "Golden ticket attack: Kerberos TGT forged using extracted KRBTGT hash, valid for 10 years",
            "zero_day",
            ["Critical"],
        )

    def test_log_99_cve_published(self):
        check(
            "Zero-day reported: vulnerability CVE-2025-99872 in OpenSSL 3.1.2 published 2 hours after this attack started",
            "zero_day",
            ["Critical"],
        )

    def test_log_100_full_domain_compromise(self):
        check(
            "Full domain compromise: attacker has admin access to all 47 domain-joined systems. Incident severity: P1",
            "zero_day",
            ["Critical"],
        )


# =============================================================================
# EDGE CASE TESTS — robustness checks
# =============================================================================

class TestEdgeCases:

    def test_empty_string_returns_unknown(self):
        result = classify_log("")
        assert result["threat_type"] == "unknown"
        assert result["severity_label"] == "Low"
        assert result["severity_score"] == 0
        assert result["confidence_pct"] == 0
        assert result["matched_keywords"] == []

    def test_whitespace_only_returns_unknown(self):
        result = classify_log("   \n\t  ")
        assert result["threat_type"] == "unknown"
        assert result["severity_score"] == 0

    def test_none_handled_gracefully(self):
        # None should not crash the function
        try:
            result = classify_log(None)
            assert result["threat_type"] == "unknown"
        except (TypeError, AttributeError):
            # Acceptable — some implementations may raise on None
            pass

    def test_random_normal_log_returns_dict(self):
        result = classify_log("User john logged in successfully from 10.0.0.1")
        assert isinstance(result, dict)
        assert "threat_type" in result

    def test_all_required_keys_always_present(self):
        logs = [
            "test log with no keywords",
            "Failed login",
            "SQL injection",
            "",
        ]
        required = ["threat_type", "severity_label", "severity_score",
                    "confidence_pct", "matched_keywords"]
        for log in logs:
            result = classify_log(log)
            for key in required:
                assert key in result, f"Key '{key}' missing for log: '{log}'"

    def test_severity_score_never_exceeds_10(self):
        # A log with many keywords should still cap at 10
        long_log = (
            "Failed login attempt brute force hydra authentication failure "
            "invalid password account locked backup_svc repeated attempts "
            "ssh authentication failure multiple accounts credential stuffing"
        )
        result = classify_log(long_log)
        assert result["severity_score"] <= 10

    def test_severity_score_never_below_0(self):
        result = classify_log("hello world nothing here")
        assert result["severity_score"] >= 0

    def test_severity_label_always_valid(self):
        valid = {"Low", "Medium", "High", "Critical"}
        test_logs = [
            "some normal activity",
            "Failed login from 1.2.3.4",
            "Ransomware detected immediately",
            "",
        ]
        for log in test_logs:
            result = classify_log(log)
            assert result["severity_label"] in valid, (
                f"Invalid label '{result['severity_label']}' for: {log}"
            )

    def test_matched_keywords_is_always_list(self):
        logs = ["", "brute force attack", "nmap scan", "ransomware detected"]
        for log in logs:
            result = classify_log(log)
            assert isinstance(result["matched_keywords"], list)

    def test_confidence_pct_between_0_and_100(self):
        logs = [
            "Failed login from 192.168.1.1",
            "SQL injection union select",
            "ransomware encryption started files encrypted",
        ]
        for log in logs:
            result = classify_log(log)
            assert 0 <= result["confidence_pct"] <= 100, (
                f"confidence_pct={result['confidence_pct']} for: {log}"
            )

    def test_case_insensitive_detection(self):
        # Classifier should detect threat even if log is all uppercase
        result_lower = classify_log("failed login attempt from ip 1.2.3.4")
        result_upper = classify_log("FAILED LOGIN ATTEMPT FROM IP 1.2.3.4")
        assert result_lower["threat_type"] == result_upper["threat_type"]


# =============================================================================
# FALLBACK EXPLANATION TESTS
# =============================================================================

class TestFallbackExplanations:

    def test_all_10_scenarios_have_fallback(self):
        scenarios = [
            "brute_force", "port_scan", "privilege_escalation", "malware",
            "insider_threat", "phishing", "sql_injection", "ddos",
            "data_exfiltration", "zero_day",
        ]
        for scenario in scenarios:
            result = get_fallback_explanation(scenario)
            assert isinstance(result, dict), f"Fallback for {scenario} is not a dict"
            assert "explanation" in result, f"No 'explanation' key for {scenario}"
            assert "mitigation" in result, f"No 'mitigation' key for {scenario}"
            assert len(result["explanation"]) > 20, f"Explanation too short for {scenario}"
            assert len(result["mitigation"]) > 20, f"Mitigation too short for {scenario}"

    def test_unknown_threat_returns_default(self):
        result = get_fallback_explanation("unknown")
        assert "explanation" in result
        assert "mitigation" in result

    def test_invalid_threat_returns_default_not_crash(self):
        result = get_fallback_explanation("this_does_not_exist")
        assert isinstance(result, dict)
        assert "explanation" in result

    def test_fallback_explanation_is_string(self):
        result = get_fallback_explanation("brute_force")
        assert isinstance(result["explanation"], str)
        assert isinstance(result["mitigation"], str)

    def test_fallback_returns_something_for_all_classify_outputs(self):
        # Whatever classify_log returns, get_fallback_explanation must not crash
        test_logs = [
            "Failed login from 192.168.1.20",
            "Nmap scan detected",
            "Ransomware detected",
            "SQL injection union select",
            "Unknown random garbage input xyz 123",
        ]
        for log in test_logs:
            threat = classify_log(log)["threat_type"]
            fallback = get_fallback_explanation(threat)
            assert isinstance(fallback, dict)
            assert "explanation" in fallback