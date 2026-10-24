"""Tests for repository inspection and cloning tools."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from tools import (
    TOOL_SCHEMAS,
    RepoInspector,
    clone_repo,
    redact_secrets,
)


def test_clone_repo_url_validation() -> None:
    """Verify URL validation for GitHub URLs."""
    invalid_urls = [
        "https://gitlab.com/owner/repo",
        "https://bitbucket.org/owner/repo",
        "ftp://github.com/owner/repo",
        "https://github.com/",
        "not_a_url",
        "",
    ]
    for url in invalid_urls:
        with pytest.raises(ValueError, match="Invalid GitHub repository URL"):
            clone_repo(url)


def test_clone_repo_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify clone_repo handles timeout gracefully with RuntimeError."""
    def mock_run(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd=args[0], timeout=30)

    monkeypatch.setattr(subprocess, "run", mock_run)
    with pytest.raises(RuntimeError, match="timed out after 30 seconds"):
        clone_repo("https://github.com/owner/test-repo")


def test_clone_repo_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify clone_repo handles git failure with RuntimeError."""
    mock_res = subprocess.CompletedProcess(
        args=["git", "clone"],
        returncode=128,
        stdout="",
        stderr="fatal: repository 'https://github.com/owner/nonexistent' not found",
    )
    monkeypatch.setattr(subprocess, "run", lambda *args, **kwargs: mock_res)
    with pytest.raises(RuntimeError, match="Failed to clone repository"):
        clone_repo("https://github.com/owner/nonexistent")


def test_redact_secrets() -> None:
    """Test inline secret assignment masking."""
    assert redact_secrets('API_KEY = "my_super_secret"') == 'API_KEY = "[REDACTED]"'
    assert redact_secrets("SECRET_TOKEN = 'token-12345'") == "SECRET_TOKEN = '[REDACTED]'"
    assert redact_secrets("PASSWORD = secret_pass") == "PASSWORD = [REDACTED]"
    assert redact_secrets('  "api_key": "raw_key_123",') == '  "api_key": "[REDACTED]",'
    assert redact_secrets("export GITHUB_TOKEN=ghp_secret") == "export GITHUB_TOKEN=[REDACTED]"
    # Comparisons should not be falsely redacted
    assert redact_secrets('if api_key == "test":') == 'if api_key == "test":'
    assert redact_secrets('if token != "abc":') == 'if token != "abc":'


def test_path_traversal_protection(tmp_path: Path) -> None:
    """Verify _resolve_safe_path blocks paths outside repo root."""
    inspector = RepoInspector(tmp_path)
    (tmp_path / "valid.py").write_text("print('hello')", encoding="utf-8")

    assert inspector._resolve_safe_path("valid.py") == (tmp_path / "valid.py").resolve()

    with pytest.raises(PermissionError, match="traverses outside"):
        inspector._resolve_safe_path("../../outside.txt")


def test_truncate(tmp_path: Path) -> None:
    """Test output truncation."""
    inspector = RepoInspector(tmp_path)
    text = "a" * 100
    assert inspector._truncate(text, max_chars=100) == text
    truncated = inspector._truncate(text, max_chars=50)
    assert len(truncated) < 150
    assert "[Truncated: 50 characters omitted]" in truncated


def test_list_files(tmp_path: Path) -> None:
    """Test list_files skips internal dirs but reports sensitive files."""
    # Internal dirs to skip
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "config").write_text("git config", encoding="utf-8")
    (tmp_path / ".venv").mkdir()
    (tmp_path / ".venv" / "pyvenv.cfg").write_text("venv config", encoding="utf-8")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "package.json").write_text("{}", encoding="utf-8")

    # Files that should be listed
    (tmp_path / ".env").write_text("SECRET=123", encoding="utf-8")
    (tmp_path / ".DS_Store").write_text("binary", encoding="utf-8")
    (tmp_path / "debug.log").write_text("log data", encoding="utf-8")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "main.py").write_text("print('app')", encoding="utf-8")
    (tmp_path / "src" / "__pycache__").mkdir()
    (tmp_path / "src" / "__pycache__" / "main.cpython-311.pyc").write_text("pyc", encoding="utf-8")

    inspector = RepoInspector(tmp_path)
    output = inspector.list_files()
    files = output.splitlines()

    assert ".env" in files
    assert ".DS_Store" in files
    assert "debug.log" in files
    assert "src/main.py" in files
    assert "src/__pycache__/main.cpython-311.pyc" in files
    assert ".git/config" not in files
    assert ".venv/pyvenv.cfg" not in files
    assert "node_modules/package.json" not in files


def test_read_file(tmp_path: Path) -> None:
    """Test read_file with line numbers, slicing, and secret redaction."""
    file_path = tmp_path / "config.py"
    file_path.write_text(
        "import os\n"
        "API_KEY = 'super_secret_value'\n"
        "PORT = 8080\n"
        "DEBUG = False\n",
        encoding="utf-8",
    )
    inspector = RepoInspector(tmp_path)

    # Full read
    content = inspector.read_file("config.py", start_line=1, end_line=10)
    lines = content.splitlines()
    assert lines[0] == "1: import os"
    assert lines[1] == "2: API_KEY = '[REDACTED]'"
    assert lines[2] == "3: PORT = 8080"
    assert lines[3] == "4: DEBUG = False"

    # Line slicing
    sliced = inspector.read_file("config.py", start_line=2, end_line=3)
    sliced_lines = sliced.splitlines()
    assert len(sliced_lines) == 2
    assert sliced_lines[0] == "2: API_KEY = '[REDACTED]'"
    assert sliced_lines[1] == "3: PORT = 8080"

    # Nonexistent file
    error_res = inspector.read_file("nonexistent.py")
    assert "Error: File not found" in error_res

    # Traversal attempt
    traversal_res = inspector.read_file("../../secret.txt")
    assert "Error reading file" in traversal_res


def test_search_code(tmp_path: Path) -> None:
    """Test search_code with regex pattern matching and secret redaction."""
    (tmp_path / "app.py").write_text("DATABASE_PASSWORD = 'db_secret'\nPORT = 5000\n", encoding="utf-8")
    (tmp_path / "docs.txt").write_text("Documentation without password\n", encoding="utf-8")

    inspector = RepoInspector(tmp_path)

    # Valid search with secret redaction
    result = inspector.search_code("password")
    assert "app.py:1: DATABASE_PASSWORD = '[REDACTED]'" in result
    assert "docs.txt:1: Documentation without password" in result

    # No match
    no_match = inspector.search_code("nonexistent_pattern_xyz")
    assert "No matches found" in no_match

    # Invalid regex
    invalid_regex = inspector.search_code("[unclosed")
    assert "Error: Invalid regular expression" in invalid_regex


def test_git_tools_and_ruff(tmp_path: Path) -> None:
    """Test git_log, git_status, and run_ruff."""
    inspector = RepoInspector(tmp_path)

    # In a non-git directory
    log_res = inspector.git_log()
    assert "Error" in log_res or "fatal" in log_res

    status_res = inspector.git_status()
    assert "Error" in status_res or "fatal" in status_res

    # Ruff on empty dir
    ruff_res = inspector.run_ruff()
    assert "All checks passed" in ruff_res or "no output" in ruff_res or "completed" in ruff_res


def test_tool_schemas() -> None:
    """Verify tool schemas follow OpenAI/Cerebras function calling specification."""
    expected_names = {"list_files", "read_file", "search_code", "git_log", "git_status", "run_ruff"}
    schema_names = set()

    assert len(TOOL_SCHEMAS) == 6
    for schema in TOOL_SCHEMAS:
        assert schema.get("type") == "function"
        fn = schema.get("function", {})
        name = fn.get("name")
        schema_names.add(name)
        assert "description" in fn
        assert isinstance(fn["description"], str)
        assert "parameters" in fn
        assert fn["parameters"].get("type") == "object"
        assert "properties" in fn["parameters"]

    assert schema_names == expected_names


def test_execute_tool_dispatch(tmp_path: Path) -> None:
    """Test execute_tool method."""
    (tmp_path / "test.txt").write_text("hello world", encoding="utf-8")
    inspector = RepoInspector(tmp_path)

    files = inspector.execute_tool("list_files")
    assert "test.txt" in files

    read = inspector.execute_tool("read_file", {"path": "test.txt"})
    assert "1: hello world" in read

    unknown = inspector.execute_tool("unknown_tool")
    assert "Error: Unknown tool" in unknown
