import os
import hashlib
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

# ── Cache: avoids duplicate API calls for the same log ──────────────────────
_cache: dict[str, dict] = {}

# ── Fallback explanations (used if OpenAI fails or times out) ───────────────
FALLBACK_EXPLANATIONS: dict[str, dict] = {
    "brute_force": {
        "explanation": "Repeated failed login attempts were detected from a single IP address, consistent with an automated brute-force attack trying to guess credentials.",
        "mitigation": "Block the source IP at the firewall and enforce account lockout after 5 failed attempts. Enable MFA on all accounts."
    },
    "port_scan": {
        "explanation": "A systematic scan of multiple ports was detected from an external IP, indicating an attacker is mapping open services before launching an exploit.",
        "mitigation": "Block the scanning IP at the perimeter firewall. Review and close any unnecessarily exposed ports and services."
    },
    "privilege_escalation": {
        "explanation": "A low-privileged process or user attempted to gain elevated system access, which may indicate exploitation of a misconfiguration or known vulnerability.",
        "mitigation": "Audit sudo and SUID permissions. Remove unnecessary privileges and investigate the process that triggered the alert."
    },
    "malware": {
        "explanation": "Malicious software activity was detected on the endpoint, including suspicious process execution or network callbacks consistent with ransomware or trojans.",
        "mitigation": "Isolate the affected endpoint immediately. Run a full antivirus scan and investigate all recently executed processes."
    },
    "insider_threat": {
        "explanation": "Unusual data access patterns were detected from an internal user account, suggesting possible data theft or policy violation outside normal working hours.",
        "mitigation": "Flag the user account for HR and security review. Check DLP logs for data exfiltration and preserve all audit evidence."
    },
    "phishing": {
        "explanation": "A phishing attempt was detected involving a spoofed sender or credential-harvesting link that may have already compromised a user account.",
        "mitigation": "Reset affected user credentials immediately, enforce MFA, and recall the phishing email from all inboxes."
    },
    "sql_injection": {
        "explanation": "SQL injection syntax was detected in an application input field, indicating an attacker is attempting to manipulate the database directly.",
        "mitigation": "Switch all database queries to parameterised statements. Enable WAF rules to block injection patterns and audit all query inputs."
    },
    "ddos": {
        "explanation": "A high volume of requests from multiple sources is overwhelming the server, causing degraded performance or complete service unavailability.",
        "mitigation": "Activate DDoS mitigation and contact your ISP for upstream traffic scrubbing. Enable rate limiting and CAPTCHA on exposed endpoints."
    },
    "data_exfiltration": {
        "explanation": "An unusually large or suspicious outbound data transfer was detected, suggesting sensitive data may be leaving the network without authorisation.",
        "mitigation": "Block outbound traffic to the destination IP. Identify the process responsible and determine what data was transferred."
    },
    "zero_day": {
        "explanation": "An unknown exploit pattern was detected that does not match any existing signatures, indicating a possible zero-day vulnerability is being weaponised.",
        "mitigation": "Isolate the affected system immediately. Capture all crash dumps and network traffic. Notify the vendor and relevant security agencies."
    },
    "unknown": {
        "explanation": "Suspicious activity was detected that does not clearly match a known attack pattern. Manual investigation is recommended.",
        "mitigation": "Review the raw log carefully. Escalate to a senior analyst and monitor the source IP for further activity."
    }
}


def _make_cache_key(log_text: str) -> str:
    """Create a unique key from the log text using MD5 hashing."""
    return hashlib.md5(log_text.strip().lower().encode()).hexdigest()


def explain_log(log_text: str, threat_type: str = "unknown") -> dict:
    """
    Takes a raw log line and a threat type, returns a plain-English
    explanation and a mitigation step.

    Returns:
        {
            "explanation": "...",
            "mitigation": "...",
            "source": "ai" | "cache" | "fallback"
        }
    """
    cache_key = _make_cache_key(log_text)

    # Return cached result if available
    if cache_key in _cache:
        result = _cache[cache_key].copy()
        result["source"] = "cache"
        return result

    prompt = (
        f"You are a cybersecurity analyst writing for a SOC dashboard. "
        f"Given the log below, write:\n"
        f"1. A 2-sentence plain-English explanation suitable for a non-technical analyst.\n"
        f"2. One specific, actionable mitigation step.\n\n"
        f"Detected threat type: {threat_type}\n"
        f"Log: {log_text}\n\n"
        f"Respond in this exact format:\n"
        f"EXPLANATION: <your explanation here>\n"
        f"MITIGATION: <your mitigation here>"
    )

    try:
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=200,
            timeout=5
        )

        raw = response.choices[0].message.content.strip()
        explanation, mitigation = _parse_response(raw, threat_type)

        result = {
            "explanation": explanation,
            "mitigation": mitigation,
            "source": "ai"
        }

        # Store in cache
        _cache[cache_key] = {"explanation": explanation, "mitigation": mitigation}
        return result

    except Exception as e:
        print(f"[explainer.py] OpenAI call failed: {e}. Using fallback.")
        fallback = FALLBACK_EXPLANATIONS.get(threat_type, FALLBACK_EXPLANATIONS["unknown"])
        return {
            "explanation": fallback["explanation"],
            "mitigation": fallback["mitigation"],
            "source": "fallback"
        }


def _parse_response(raw: str, threat_type: str) -> tuple[str, str]:
    """
    Parse the structured OpenAI response.
    Falls back to splitting on newline if the expected format is missing.
    """
    explanation = ""
    mitigation = ""

    for line in raw.splitlines():
        if line.startswith("EXPLANATION:"):
            explanation = line.replace("EXPLANATION:", "").strip()
        elif line.startswith("MITIGATION:"):
            mitigation = line.replace("MITIGATION:", "").strip()

    # If parsing failed, use fallback text
    if not explanation or not mitigation:
        fallback = FALLBACK_EXPLANATIONS.get(threat_type, FALLBACK_EXPLANATIONS["unknown"])
        explanation = explanation or fallback["explanation"]
        mitigation = mitigation or fallback["mitigation"]

    return explanation, mitigation