"""Unit and integration tests for core_agent.py, tools, and agent CLI."""

from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from agent import build_parser, main
from core_agent import execute_tool_call, run_agent_audit
from schemas import parse_and_validate_report, redact_secrets
from tools import RepoInspector


@pytest.fixture
def dummy_repo(tmp_path: Path) -> Path:
    """Initialize a mock local git repository with realistic DevOps defects."""
    repo_dir = tmp_path / "test_repo"
    repo_dir.mkdir(parents=True)
    wf_dir = repo_dir / ".github" / "workflows"
    wf_dir.mkdir(parents=True)

    # 1. config.py with secret and hardcoded local path
    (repo_dir / "config.py").write_text(
        'API_KEY = "sk-1234567890abcdefghijklmnop"\n'
        'DATA_DIR = "/Users/developer/local_data"\n'
        'DEBUG = True\n',
        encoding="utf-8",
    )

    # 2. requirements.txt with unpinned packages
    (repo_dir / "requirements.txt").write_text(
        "flask\nrequests\n",
        encoding="utf-8",
    )

    # 3. .github/workflows/ci.yml with write-all and continue-on-error
    (wf_dir / "ci.yml").write_text(
        "name: CI\n"
        "on: [push]\n"
        "permissions: write-all\n"
        "jobs:\n"
        "  test:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "      - name: Run tests\n"
        "        run: pytest\n"
        "        continue-on-error: true\n",
        encoding="utf-8",
    )

    # Initialize Git repository and commit files
    subprocess.run(["git", "init"], cwd=str(repo_dir), capture_output=True, check=True)
    subprocess.run(["git", "config", "user.email", "audit@example.com"], cwd=str(repo_dir), capture_output=True, check=True)
    subprocess.run(["git", "config", "user.name", "Auditor"], cwd=str(repo_dir), capture_output=True, check=True)
    subprocess.run(["git", "add", "."], cwd=str(repo_dir), capture_output=True, check=True)
    subprocess.run(["git", "commit", "-m", "Initial commit"], cwd=str(repo_dir), capture_output=True, check=True)

    return repo_dir


def test_dummy_repo_list_files(dummy_repo: Path) -> None:
    """Verify RepoInspector.list_files discovers all committed files."""
    inspector = RepoInspector(dummy_repo)
    file_list = inspector.list_files().splitlines()

    assert ".github/workflows/ci.yml" in file_list
    assert "config.py" in file_list
    assert "requirements.txt" in file_list


def test_dummy_repo_read_file_and_traversal(dummy_repo: Path) -> None:
    """Verify RepoInspector.read_file numbers lines, masks secrets, and blocks traversal."""
    inspector = RepoInspector(dummy_repo)

    # Check line numbers and secret masking
    content = inspector.read_file("config.py", start_line=1, end_line=3)
    lines = content.splitlines()
    assert lines[0] == '1: API_KEY = "[REDACTED]"'
    assert lines[1] == '2: DATA_DIR = "/Users/developer/local_data"'
    assert lines[2] == "3: DEBUG = True"
    assert "sk-1234567890abcdefghijklmnop" not in content

    # Check path traversal protection
    traversal_res = inspector.read_file("../../outside.txt")
    assert "Error reading file" in traversal_res


def test_dummy_repo_search_code(dummy_repo: Path) -> None:
    """Verify RepoInspector.search_code finds matches and masks inline secrets."""
    inspector = RepoInspector(dummy_repo)

    # Search for API_KEY
    api_key_matches = inspector.search_code("API_KEY")
    assert 'config.py:1: API_KEY = "[REDACTED]"' in api_key_matches
    assert "sk-1234567890" not in api_key_matches

    # Search for continue-on-error
    ci_matches = inspector.search_code("continue-on-error")
    assert ".github/workflows/ci.yml:11:" in ci_matches
    assert "continue-on-error: true" in ci_matches


def test_redact_secrets_tokens_and_passwords() -> None:
    """Verify redact_secrets masks sk-..., ghp_..., AKIA..., and password assignments."""
    assert redact_secrets('API_KEY = "sk-abcdefghijklmnopqrstuvwxyz1234"') == 'API_KEY = "[REDACTED]"'
    assert redact_secrets("TOKEN: ghp_123456789012345678901234567890123456") == "TOKEN: [REDACTED]"
    assert redact_secrets("AWS key: AKIAIOSFODNN7EXAMPLE") == "AWS key: [REDACTED]"
    assert redact_secrets("password = my_super_secret_password") == "password = [REDACTED]"
    assert redact_secrets('PASSWD: "my_db_passwd_123"') == 'PASSWD: "[REDACTED]"'


def test_parse_and_validate_report_normalization_and_dedup() -> None:
    """Verify schema validation, null normalization, and deduplication in parse_and_validate_report."""
    raw_output = """
```json
{
  "repository": "https://github.com/placeholder/repo",
  "violations": [
    {
      "rule_id": "SEC-001",
      "category": "Security",
      "severity": "CRITICAL",
      "file": "config.py",
      "line": 1,
      "description": "Hardcoded API key API_KEY = 'sk-1234567890abcdefghijklmnop'",
      "evidence": "API_KEY = 'sk-1234567890abcdefghijklmnop'",
      "recommendation": "Use environment variable"
    },
    {
      "rule_id": "SEC-001",
      "category": "security",
      "severity": "critical",
      "file": "config.py",
      "line": 1,
      "description": "Hardcoded API key API_KEY = 'sk-1234567890abcdefghijklmnop'",
      "evidence": "duplicate entry",
      "recommendation": "Use environment variable"
    },
    {
      "rule_id": "HYG-001",
      "category": "Repository Hygiene",
      "severity": "low",
      "file": "N/A",
      "line": 0,
      "description": "Missing README.md",
      "evidence": "No README in root",
      "recommendation": "Create README.md"
    }
  ]
}
```
"""
    parsed = parse_and_validate_report(raw_output, "https://github.com/actual/target-repo")

    assert parsed["repository"] == "https://github.com/actual/target-repo"
    violations = parsed["violations"]
    assert len(violations) == 2  # Duplicate SEC-001 removed

    sec = violations[0]
    assert sec["rule_id"] == "SEC-001"
    assert sec["category"] == "security"
    assert sec["severity"] == "critical"
    assert "[REDACTED]" in sec["evidence"]
    assert "sk-1234567890" not in sec["evidence"]

    hyg = violations[1]
    assert hyg["file"] is None
    assert hyg["line"] is None
    assert hyg["category"] == "repository_hygiene"


class MockToolCall:
    def __init__(self, tool_id: str, name: str, arguments: str) -> None:
        self.id = tool_id
        self.type = "function"
        self.function = MagicMock(name=name, arguments=arguments)
        self.function.name = name
        self.function.arguments = arguments


class MockMessage:
    def __init__(self, content: str | None, tool_calls: list[Any] | None = None) -> None:
        self.content = content
        self.tool_calls = tool_calls


class MockChoice:
    def __init__(self, message: MockMessage) -> None:
        self.message = message


class MockResponse:
    def __init__(self, message: MockMessage) -> None:
        self.choices = [MockChoice(message)]


def test_run_agent_audit_with_mock_patch(dummy_repo: Path) -> None:
    """Verify run_agent_audit end-to-end when Cerebras and clone_repo are mocked via patch."""
    # Mock clone_repo to return a TemporaryDirectory pointing to dummy_repo
    fake_temp = tempfile.TemporaryDirectory()
    # Copy dummy_repo content into fake_temp
    for p in dummy_repo.rglob("*"):
        rel = p.relative_to(dummy_repo)
        target = Path(fake_temp.name) / rel
        if p.is_dir():
            target.mkdir(parents=True, exist_ok=True)
        else:
            target.write_bytes(p.read_bytes())

    # Step 1: Tool call for list_files and git_status
    tc1 = MockToolCall("call_1", "list_files", "{}")
    tc2 = MockToolCall("call_2", "git_status", "{}")
    msg1 = MockMessage(content="", tool_calls=[tc1, tc2])

    # Step 2: Tool call for read_file
    tc3 = MockToolCall("call_3", "read_file", '{"path": "config.py"}')
    msg2 = MockMessage(content="", tool_calls=[tc3])

    # Step 3: Final JSON output
    final_output = json.dumps({
        "repository": "https://github.com/mocked/repo",
        "violations": [
            {
                "rule_id": "SEC-001",
                "category": "security",
                "severity": "critical",
                "file": "config.py",
                "line": 1,
                "description": "Hardcoded secret found in configuration file",
                "evidence": "API_KEY = '[REDACTED]'",
                "recommendation": "Load API_KEY from environment variables.",
            }
        ],
    })
    msg3 = MockMessage(content=final_output, tool_calls=None)

    with (
        patch("core_agent.clone_repo", return_value=fake_temp),
        patch("core_agent.Cerebras") as mock_cerebras_class,
        patch.dict("os.environ", {"CEREBRAS_API_KEY": "test-api-key", "CEREBRAS_MODEL": "qwen-3.8-27b"}),
    ):
        mock_client = MagicMock()
        mock_cerebras_class.return_value = mock_client
        mock_client.chat.completions.create.side_effect = [
            MockResponse(msg1),
            MockResponse(msg2),
            MockResponse(msg3),
        ]

        report = run_agent_audit(
            repo_url="https://github.com/mocked/repo",
            max_turns=5,
            verbose=False,
        )

        assert report["repository"] == "https://github.com/mocked/repo"
        assert len(report["violations"]) == 1
        assert report["violations"][0]["rule_id"] == "SEC-001"
        assert mock_client.chat.completions.create.call_count == 3


def test_execute_tool_call(tmp_path: Path) -> None:
    """Verify tool dispatching and secret redaction in execute_tool_call."""
    (tmp_path / "app.py").write_text("API_KEY = 'secret12345678'\nprint('ok')", encoding="utf-8")
    inspector = RepoInspector(tmp_path)

    # list_files
    files = execute_tool_call(inspector, "list_files")
    assert "app.py" in files

    # read_file with secret redaction
    content = execute_tool_call(inspector, "read_file", {"path": "app.py"})
    assert "[REDACTED]" in content
    assert "secret12345678" not in content

    # Unknown tool
    unknown = execute_tool_call(inspector, "nonexistent_tool")
    assert "Error: Unknown tool" in unknown


def test_run_agent_audit_missing_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify RuntimeError is raised when CEREBRAS_API_KEY is missing."""
    monkeypatch.delenv("CEREBRAS_API_KEY", raising=False)
    with pytest.raises(RuntimeError, match="Missing required environment variable 'CEREBRAS_API_KEY'"):
        run_agent_audit("https://github.com/test/repo", client=None)


def test_agent_cli_parser() -> None:
    """Test argument parsing for agent.py."""
    parser = build_parser()
    args = parser.parse_args(["--repo", "https://github.com/owner/repo", "--output", "out.json"])
    assert args.repo == "https://github.com/owner/repo"
    assert args.output == "out.json"


def test_agent_cli_main_success(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Test successful CLI execution writing report to file."""
    output_file = tmp_path / "custom_report.json"
    dummy_report = {
        "repository": "https://github.com/owner/repo",
        "violations": [],
    }

    monkeypatch.setattr("agent.run_agent_audit", lambda **kwargs: dummy_report)
    monkeypatch.setattr(
        "sys.argv",
        ["agent.py", "--repo", "https://github.com/owner/repo", "--output", str(output_file)],
    )

    main()
    assert output_file.exists()
    saved_data = json.loads(output_file.read_text(encoding="utf-8"))
    assert saved_data["repository"] == "https://github.com/owner/repo"
    assert saved_data["violations"] == []


def test_agent_cli_fatal_error(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    """Test CLI error handling and exit on fatal exception."""
    def mock_fail(**kwargs):
        raise RuntimeError("Network failure while cloning")

    monkeypatch.setattr("agent.run_agent_audit", mock_fail)
    monkeypatch.setattr(
        "sys.argv",
        ["agent.py", "--repo", "https://github.com/owner/repo"],
    )

    with pytest.raises(SystemExit) as exc_info:
        main()

    assert exc_info.value.code == 1
    captured = capsys.readouterr()
    assert "Error: Network failure while cloning" in captured.err
