"""
Run with: python -m ai.test_explainer
Make sure you are in the project root when running.
"""

import json
import os
from ai.explainer import explain_log

SAMPLE_LOGS_PATH = os.path.join(os.path.dirname(__file__), "data", "sample_logs.json")


def load_sample_logs(limit: int = 10) -> list:
    with open(SAMPLE_LOGS_PATH, "r") as f:
        data = json.load(f)
    logs = data.get("logs", data) if isinstance(data, dict) else data
    return logs[:limit]


def run_tests():
    print("=" * 60)
    print("Running explainer.py tests against sample_logs.json")
    print("=" * 60)

    logs = load_sample_logs(10)
    passed = 0
    failed = 0

    for entry in logs:
        log_text = entry.get("log_text", "")
        threat_type = entry.get("threat_type", "unknown")
        log_id = entry.get("id", "?")

        print(f"\n[Log ID {log_id}] Threat: {threat_type}")
        print(f"  Raw log : {log_text[:80]}...")

        result = explain_log(log_text, threat_type)

        # Validate output structure
        assert "explanation" in result, "Missing 'explanation' key"
        assert "mitigation" in result, "Missing 'mitigation' key"
        assert len(result["explanation"]) > 20, "Explanation too short"
        assert len(result["mitigation"]) > 10, "Mitigation too short"

        print(f"  Explain : {result['explanation']}")
        print(f"  Mitigate: {result['mitigation']}")
        print(f"  Source  : {result['source']}")
        passed += 1

    print("\n" + "=" * 60)
    print(f"Tests complete: {passed} passed, {failed} failed")
    print("=" * 60)


if __name__ == "__main__":
    run_tests()