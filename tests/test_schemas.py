"""Unit tests for schemas, Pydantic models, and secret redaction."""

from __future__ import annotations

import json

import pytest

from schemas import (
    Violation,
    parse_and_validate_report,
    redact_secrets,
)


def test_redact_secrets_generic_assignments() -> None:
    """Test generic inline assignments redaction."""
    samples = [
        ('API_KEY = "super_secret_key_12345"', 'API_KEY = "[REDACTED]"'),
        ("SECRET_KEY='my_custom_secret_key'", "SECRET_KEY='[REDACTED]'"),
        ("password = secretpassword123", "password = [REDACTED]"),
        ("passwd: mypassword456", "passwd: [REDACTED]"),
        ("pwd=mysecretpwd", "pwd=[REDACTED]"),
        ('client_secret: "abc123456789"', 'client_secret: "[REDACTED]"'),
        ('auth_token="jwt_token_sample_123"', 'auth_token="[REDACTED]"'),
        ("private_key = my_private_key_value", "private_key = [REDACTED]"),
    ]
    for raw, expected in samples:
        assert redact_secrets(raw) == expected


def test_redact_secrets_known_tokens() -> None:
    """Test redaction of vendor tokens, bearer tokens, and PEM blocks."""
    ghp = "ghp_" + "A" * 36
    pat = "github_pat_" + "B" * 40
    sk = "sk-" + "C" * 32
    aws = "AKIA" + "D" * 16

    assert redact_secrets(f"Token is {ghp}") == "Token is [REDACTED]"
    assert redact_secrets(f"PAT is {pat}") == "PAT is [REDACTED]"
    assert redact_secrets(f"OpenAI key is {sk}") == "OpenAI key is [REDACTED]"
    assert redact_secrets(f"AWS key is {aws}") == "AWS key is [REDACTED]"
    assert (
        redact_secrets("Authorization: Bearer eyJhbGciOiJIUzI1Ni.sample.token")
        == "Authorization: Bearer [REDACTED]"
    )

    pem = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEowIBAAKCAQEA0m4w...\n"
        "-----END RSA PRIVATE KEY-----"
    )
    assert redact_secrets(f"Key:\n{pem}") == "Key:\n[REDACTED]"


def test_violation_normalization() -> None:
    """Verify category, severity, file, and line normalization in Violation model."""
    v = Violation(
        rule_id="CI-001",
        category="GitHub Actions / CI",
        severity="CRITICAL",
        file="N/A",
        line=0,
        description="Missing CI workflow",
        evidence="No .github/workflows directory found",
        recommendation="Add GitHub Actions CI pipeline",
    )
    assert v.category == "github_actions_ci"
    assert v.severity == "critical"
    assert v.file is None
    assert v.line is None

    # Serialization must include null for file and line
    dumped = v.model_dump()
    assert dumped["file"] is None
    assert dumped["line"] is None
    serialized = json.dumps(dumped)
    assert '"file": null' in serialized
    assert '"line": null' in serialized


def test_category_and_severity_variations() -> None:
    """Test various string representations for category and severity."""
    categories = [
        ("Repository hygiene", "repository_hygiene"),
        ("Dependency Management", "dependency_management"),
        ("Code Quality", "code_quality"),
        ("Testing", "testing"),
        ("github_actions_ci", "github_actions_ci"),
        ("Security", "security"),
        ("Configuration", "configuration"),
        ("Collaboration", "collaboration"),
        ("Build & Release", "build_and_release"),
        ("Build and Release", "build_and_release"),
    ]
    for raw_cat, expected_cat in categories:
        v = Violation(
            rule_id="TEST-01",
            category=raw_cat,
            severity="High",
            description="test",
            evidence="test",
            recommendation="test",
        )
        assert v.category == expected_cat
        assert v.severity == "high"


def test_parse_and_validate_report_clean() -> None:
    """Test parse_and_validate_report with markdown fences, deduplication, and redaction."""
    raw_llm = """
Here is the audit result for your repository:

```json
{
  "repository": "https://github.com/wrong/repo",
  "violations": [
    {
      "rule_id": "SEC-001",
      "category": "security",
      "severity": "high",
      "file": "config.py",
      "line": 15,
      "description": "Hardcoded secret API_KEY='secret12345678'",
      "evidence": "API_KEY='secret12345678'",
      "recommendation": "Remove API_KEY='secret12345678' and use env"
    },
    {
      "rule_id": "SEC-001",
      "category": "Security",
      "severity": "HIGH",
      "file": "config.py",
      "line": 15,
      "description": "Hardcoded secret API_KEY='secret12345678'",
      "evidence": "duplicate entry",
      "recommendation": "duplicate recommendation"
    },
    {
      "rule_id": "HYG-002",
      "category": "Repository Hygiene",
      "severity": "medium",
      "file": "none",
      "line": "0",
      "description": "Unused .DS_Store file found",
      "evidence": ".DS_Store committed",
      "recommendation": "Add to .gitignore"
    }
  ]
}
```

Hope this helps!
"""
    result = parse_and_validate_report(raw_llm, "https://github.com/actual/repo")

    # Repository must be overridden to repo_url
    assert result["repository"] == "https://github.com/actual/repo"

    # Exactly 2 violations (the duplicate SEC-001 must be removed)
    violations = result["violations"]
    assert len(violations) == 2

    sec_v = violations[0]
    assert sec_v["rule_id"] == "SEC-001"
    assert sec_v["category"] == "security"
    assert sec_v["severity"] == "high"
    assert "[REDACTED]" in sec_v["description"]
    assert "secret12345678" not in sec_v["description"]
    assert "[REDACTED]" in sec_v["evidence"]
    assert "[REDACTED]" in sec_v["recommendation"]

    hyg_v = violations[1]
    assert hyg_v["rule_id"] == "HYG-002"
    assert hyg_v["category"] == "repository_hygiene"
    assert hyg_v["severity"] == "medium"
    assert hyg_v["file"] is None
    assert hyg_v["line"] is None


def test_parse_and_validate_report_array_input() -> None:
    """Test parsing when LLM outputs a raw array of violations."""
    raw_array = """
[
  {
    "rule_id": "DEP-001",
    "category": "dependency_management",
    "severity": "medium",
    "file": "requirements.txt",
    "line": 1,
    "description": "Unpinned dependency",
    "evidence": "requests (no version)",
    "recommendation": "Pin versions"
  }
]
"""
    result = parse_and_validate_report(raw_array, "https://github.com/test/repo")
    assert result["repository"] == "https://github.com/test/repo"
    assert len(result["violations"]) == 1
    assert result["violations"][0]["rule_id"] == "DEP-001"


def test_parse_and_validate_report_invalid_json() -> None:
    """Test invalid JSON parsing error handling."""
    with pytest.raises(ValueError, match="Could not extract valid JSON"):
        parse_and_validate_report("Just plain text with no json at all.", "https://github.com/test/repo")
