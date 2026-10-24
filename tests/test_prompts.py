"""Unit tests for prompts module."""

from __future__ import annotations

from prompts import SYSTEM_PROMPT, make_user_prompt


def test_system_prompt_categories() -> None:
    """Verify all 9 required DevOps inspection categories are in SYSTEM_PROMPT."""
    expected_categories = [
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
    for category in expected_categories:
        assert category in SYSTEM_PROMPT, f"Missing category: {category}"


def test_system_prompt_rule_ids() -> None:
    """Verify all required rule ID prefixes are mentioned in SYSTEM_PROMPT."""
    expected_prefixes = [
        "HYG-001",
        "DEP-001",
        "QUAL-001",
        "TEST-001",
        "CI-001",
        "SEC-001",
        "CFG-001",
        "COL-001",
        "BLD-001",
    ]
    for prefix in expected_prefixes:
        assert prefix in SYSTEM_PROMPT, f"Missing rule prefix: {prefix}"


def test_system_prompt_operational_cycle() -> None:
    """Verify operational tools and steps are defined in SYSTEM_PROMPT."""
    tools = [
        "list_files",
        "git_status",
        "read_file",
        "search_code",
        "git_log",
        "run_ruff",
    ]
    for tool in tools:
        assert tool in SYSTEM_PROMPT, f"Missing tool reference: {tool}"

    # Verify key strategy concepts
    assert "Observe" in SYSTEM_PROMPT
    assert "Reason" in SYSTEM_PROMPT
    assert "Execute Tool" in SYSTEM_PROMPT


def test_system_prompt_anti_false_positive_rules() -> None:
    """Verify anti-false-positive rules and evidence instructions are defined."""
    assert "pyproject.toml" in SYSTEM_PROMPT
    assert "requirements.txt" in SYSTEM_PROMPT
    assert "[REDACTED]" in SYSTEM_PROMPT
    assert "null" in SYSTEM_PROMPT


def test_make_user_prompt() -> None:
    """Verify make_user_prompt includes the repo URL."""
    url = "https://github.com/example/test-repo"
    prompt = make_user_prompt(url)
    assert url in prompt
    assert "audit" in prompt.lower()
