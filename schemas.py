"""Output JSON schemas, models, secret redaction, and validation for DevOps Repo Auditor.

Enforces the output JSON contract, field normalization, deduplication,
and sensitive secret masking.
"""

from __future__ import annotations

import json
import re
from typing import Any, Literal

from pydantic import BaseModel, field_validator

# ---------------------------------------------------------------------------
# Secret Redaction Patterns
# ---------------------------------------------------------------------------

# PEM private key blocks (RSA, EC, DSA, OPENSSH, etc.)
PEM_KEY_PATTERN = re.compile(
    r"-----BEGIN [A-Z0-9_\s-]+PRIVATE KEY-----[\s\S]+?-----END [A-Z0-9_\s-]+PRIVATE KEY-----",
    re.IGNORECASE,
)

# HTTP Bearer tokens
BEARER_TOKEN_PATTERN = re.compile(
    r"\bBearer\s+[A-Za-z0-9_\-\.]+",
    re.IGNORECASE,
)

# Known provider token prefixes
KNOWN_TOKENS_PATTERN = re.compile(
    r"\b("
    r"ghp_[A-Za-z0-9]{20,}|"
    r"github_pat_[A-Za-z0-9_]{20,}|"
    r"sk-[A-Za-z0-9]{20,}|"
    r"AKIA[0-9A-Z]{16}"
    r")\b"
)

# Generic assignments (API keys, secrets, passwords, tokens)
ASSIGNMENT_PATTERN = re.compile(
    r'(?i)(["\']?[a-z0-9_]*(?:api[_-]?key|secret|token|password|passwd|pwd|auth_token|client_secret|private_key)[a-z0-9_]*["\']?\s*(?<![!=<>])[:=](?!=)\s*)'
    r'(?:(["\'])(.*?)\2|([A-Za-z0-9_\-\./+=]{8,})|([^\s"\'`,;#]+))'
)


def redact_secrets(text: str) -> str:
    """Mask sensitive tokens, keys, passwords, and PEM blocks in any string."""
    if not text:
        return text

    # 1. Mask PEM private key blocks
    text = PEM_KEY_PATTERN.sub("[REDACTED]", text)

    # 2. Mask HTTP Bearer tokens
    text = BEARER_TOKEN_PATTERN.sub("Bearer [REDACTED]", text)

    # 3. Mask known vendor token formats (GitHub, OpenAI, AWS)
    text = KNOWN_TOKENS_PATTERN.sub("[REDACTED]", text)

    # 4. Mask generic inline secret assignments
    def _replace_assignment(match: re.Match[str]) -> str:
        prefix = match.group(1)
        quote = match.group(2)
        if quote:
            return f"{prefix}{quote}[REDACTED]{quote}"
        return f"{prefix}[REDACTED]"

    text = ASSIGNMENT_PATTERN.sub(_replace_assignment, text)
    return text


# ---------------------------------------------------------------------------
# Categories & Severities
# ---------------------------------------------------------------------------

CategoryType = Literal[
    "repository_hygiene",
    "dependency_management",
    "code_quality",
    "testing",
    "github_actions_ci",
    "security",
    "configuration",
    "collaboration",
    "build_and_release",
]

SeverityType = Literal["critical", "high", "medium", "low"]

CATEGORY_ALIASES: dict[str, CategoryType] = {
    "repository_hygiene": "repository_hygiene",
    "hygiene": "repository_hygiene",
    "repo_hygiene": "repository_hygiene",
    "repository": "repository_hygiene",
    "dependency_management": "dependency_management",
    "dependencies": "dependency_management",
    "dependency": "dependency_management",
    "code_quality": "code_quality",
    "quality": "code_quality",
    "linting": "code_quality",
    "testing": "testing",
    "tests": "testing",
    "test": "testing",
    "github_actions_ci": "github_actions_ci",
    "github_actions": "github_actions_ci",
    "github_action": "github_actions_ci",
    "ci": "github_actions_ci",
    "ci_cd": "github_actions_ci",
    "cicd": "github_actions_ci",
    "actions": "github_actions_ci",
    "security": "security",
    "sec": "security",
    "configuration": "configuration",
    "config": "configuration",
    "collaboration": "collaboration",
    "build_and_release": "build_and_release",
    "build_release": "build_and_release",
    "build": "build_and_release",
    "release": "build_and_release",
}

SEVERITY_ALIASES: dict[str, SeverityType] = {
    "critical": "critical",
    "crit": "critical",
    "high": "high",
    "medium": "medium",
    "med": "medium",
    "moderate": "medium",
    "low": "low",
    "info": "low",
}


def normalize_category_value(val: Any) -> Any:
    """Normalize raw category input string to recognized enum values."""
    if not isinstance(val, str):
        return val
    cleaned = re.sub(r"[\s\-\/&]+", "_", val.strip().lower()).strip("_")
    return CATEGORY_ALIASES.get(cleaned, cleaned)


def normalize_severity_value(val: Any) -> Any:
    """Normalize raw severity input string to standard lower-case levels."""
    if not isinstance(val, str):
        return val
    cleaned = val.strip().lower()
    return SEVERITY_ALIASES.get(cleaned, cleaned)


# ---------------------------------------------------------------------------
# Pydantic Models
# ---------------------------------------------------------------------------


class Violation(BaseModel):
    """Single finding identified during repository audit."""

    rule_id: str
    category: CategoryType
    severity: SeverityType
    file: str | None = None
    line: int | None = None
    description: str
    evidence: str
    recommendation: str

    @field_validator("category", mode="before")
    @classmethod
    def validate_category(cls, v: Any) -> Any:
        return normalize_category_value(v)

    @field_validator("severity", mode="before")
    @classmethod
    def validate_severity(cls, v: Any) -> Any:
        return normalize_severity_value(v)

    @field_validator("file", mode="before")
    @classmethod
    def validate_file(cls, v: Any) -> str | None:
        if v is None:
            return None
        if isinstance(v, str):
            cleaned = v.strip()
            if cleaned.lower() in {"", "none", "null", "n/a", "na", "undefined"}:
                return None
            return cleaned
        return None

    @field_validator("line", mode="before")
    @classmethod
    def validate_line(cls, v: Any) -> int | None:
        if v is None:
            return None
        if isinstance(v, (int, float)):
            val = int(v)
            return val if val > 0 else None
        if isinstance(v, str):
            cleaned = v.strip()
            if cleaned.lower() in {"", "none", "null", "n/a", "na", "undefined"}:
                return None
            try:
                val = int(cleaned)
                return val if val > 0 else None
            except ValueError:
                return None
        return None


class AuditReport(BaseModel):
    """Complete structured audit report for a repository."""

    repository: str
    violations: list[Violation]


# ---------------------------------------------------------------------------
# Extraction, Normalization & Deduplication
# ---------------------------------------------------------------------------


def _extract_json_content(raw_text: str) -> Any:
    """Extract and parse JSON object/array from raw text with markdown fences."""
    text = raw_text.strip()

    # Check for markdown code fences (```json ... ``` or ``` ... ```)
    fence_match = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", text, re.IGNORECASE)
    candidate = fence_match.group(1).strip() if fence_match else text

    try:
        return json.loads(candidate)
    except json.JSONDecodeError:
        # Fall back to searching for outermost curly braces or brackets
        first_brace = candidate.find("{")
        last_brace = candidate.rfind("}")
        if first_brace != -1 and last_brace != -1 and last_brace > first_brace:
            try:
                return json.loads(candidate[first_brace : last_brace + 1])
            except json.JSONDecodeError:
                pass

        first_bracket = candidate.find("[")
        last_bracket = candidate.rfind("]")
        if first_bracket != -1 and last_bracket != -1 and last_bracket > first_bracket:
            try:
                return json.loads(candidate[first_bracket : last_bracket + 1])
            except json.JSONDecodeError:
                pass

        raise ValueError("Could not extract valid JSON from LLM output.") from None


def parse_and_validate_report(raw_llm_output: str, repo_url: str) -> dict[str, Any]:
    """Parse raw LLM JSON output, normalize, redact secrets, deduplicate, and validate.

    Args:
        raw_llm_output: Raw string from model (may contain markdown fences).
        repo_url: Repository URL to set on the final report.

    Returns:
        Validated dictionary matching AuditReport model dump.
    """
    parsed = _extract_json_content(raw_llm_output)

    if isinstance(parsed, list):
        data: dict[str, Any] = {"repository": repo_url, "violations": parsed}
    elif isinstance(parsed, dict):
        data = parsed
        data["repository"] = repo_url
        if "violations" not in data:
            data["violations"] = data.get("findings") or data.get("issues") or []
    else:
        raise TypeError("Parsed JSON must be an object or a list of violations.")

    raw_violations = data.get("violations")
    if not isinstance(raw_violations, list):
        raw_violations = []

    seen: set[tuple[str, str | None, int | None, str]] = set()
    deduped_violations: list[Violation] = []

    for item in raw_violations:
        if not isinstance(item, dict):
            continue

        # Redact secrets in descriptive fields
        item["description"] = redact_secrets(str(item.get("description", "")))
        item["evidence"] = redact_secrets(str(item.get("evidence", "")))
        item["recommendation"] = redact_secrets(str(item.get("recommendation", "")))

        # Validate through Pydantic (applies category/severity/file/line normalization)
        violation = Violation.model_validate(item)

        # Deduplication key based on normalized category, file, line, and lowercase description
        dedup_key = (
            violation.category,
            violation.file,
            violation.line,
            violation.description.lower().strip(),
        )

        if dedup_key not in seen:
            seen.add(dedup_key)
            deduped_violations.append(violation)

    report = AuditReport(repository=repo_url, violations=deduped_violations)
    return report.model_dump()
