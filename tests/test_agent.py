"""Unit tests for core_agent.py and agent.py CLI."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from agent import build_parser, main
from core_agent import execute_tool_call, run_agent_audit
from tools import RepoInspector


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


def test_run_agent_audit_mock_loop(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Test full agent loop with mock LLM client responses."""
    # Mock clone_repo to return a temporary directory with files
    fake_temp = tempfile.TemporaryDirectory()
    (Path(fake_temp.name) / "main.py").write_text("print('test')", encoding="utf-8")
    monkeypatch.setattr("core_agent.clone_repo", lambda url: fake_temp)

    # Response 1: Requests list_files
    msg1 = MockMessage(
        content="",
        tool_calls=[MockToolCall("call_1", "list_files", "{}")],
    )
    # Response 2: Emits final report
    final_json = json.dumps({
        "repository": "https://github.com/mock/repo",
        "violations": [
            {
                "rule_id": "HYG-001",
                "category": "repository_hygiene",
                "severity": "low",
                "file": None,
                "line": None,
                "description": "Missing README.md file in repository root",
                "evidence": "No README found",
                "recommendation": "Add a comprehensive README.md",
            }
        ],
    })
    msg2 = MockMessage(content=final_json, tool_calls=None)

    mock_client = MagicMock()
    mock_client.chat.completions.create.side_effect = [
        MockResponse(msg1),
        MockResponse(msg2),
    ]

    report = run_agent_audit(
        repo_url="https://github.com/mock/repo",
        max_turns=5,
        verbose=False,
        client=mock_client,
    )

    assert report["repository"] == "https://github.com/mock/repo"
    assert len(report["violations"]) == 1
    assert report["violations"][0]["rule_id"] == "HYG-001"
    assert mock_client.chat.completions.create.call_count == 2


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
