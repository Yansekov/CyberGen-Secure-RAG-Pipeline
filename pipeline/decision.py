"""Allow / sanitize / quarantine policy."""
QUARANTINE_MIN = 70


def decide(doc):
    types = {f["type"] for f in doc["findings"]}
    if doc["risk_score"] >= QUARANTINE_MIN or {"hidden_text", "prompt_injection"} <= types:
        return "QUARANTINE"
    return "SANITIZE" if doc["findings"] else "ALLOW"
