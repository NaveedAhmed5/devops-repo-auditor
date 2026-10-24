"""Repository inspection and cloning tools for DevOps Repo Auditor.

Provides safe repository cloning and read-only inspection tools with
strict path traversal protection, secret redaction, and output truncation.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

# Pattern for valid GitHub HTTP/HTTPS repository URLs
GITHUB_URL_PATTERN = re.compile(
    r"^https?://(www\.)?github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:\.git)?/?$"
)

# Directories to skip when listing or searching files
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", ".pytest_cache"}

# Common binary file extensions to skip during text-based code searches
BINARY_EXTENSIONS = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".ico",
    ".webp",
    ".pdf",
    ".zip",
    ".tar",
    ".gz",
    ".bz2",
    ".7z",
    ".exe",
    ".bin",
    ".dll",
    ".so",
    ".dylib",
    ".pyc",
    ".whl",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
}

# Regex to detect and mask obvious inline secret assignments
SECRET_ASSIGNMENT_PATTERN = re.compile(
    r'(?i)(["\']?[a-z0-9_]*(?:api[_-]?key|secret|token|password)[a-z0-9_]*["\']?\s*(?<![!=<>])[:=](?!=)\s*)'
    r'(?:(["\'])(.*?)\2|([^\s"\'`,;#]+))'
)


def redact_secrets(text: str) -> str:
    """Mask obvious inline secret assignments (API_KEY, SECRET, TOKEN, PASSWORD)."""

    def _replace_match(match: re.Match[str]) -> str:
        prefix = match.group(1)
        quote = match.group(2)
        if quote:
            return f"{prefix}{quote}[REDACTED]{quote}"
        return f"{prefix}[REDACTED]"

    return SECRET_ASSIGNMENT_PATTERN.sub(_replace_match, text)


def clone_repo(repo_url: str) -> tempfile.TemporaryDirectory:
    """Clone a GitHub repository into a temporary directory using shallow clone.

    Args:
        repo_url: HTTP or HTTPS GitHub repository URL.

    Returns:
        tempfile.TemporaryDirectory containing the cloned repository.

    Raises:
        ValueError: If repo_url is not a valid HTTP/HTTPS GitHub URL.
        RuntimeError: If cloning fails or times out.
    """
    cleaned_url = repo_url.strip()
    if not GITHUB_URL_PATTERN.match(cleaned_url):
        raise ValueError(
            f"Invalid GitHub repository URL: '{repo_url}'. "
            "Must be a valid HTTP/HTTPS URL (e.g. 'https://github.com/owner/repo')."
        )

    temp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}

    try:
        result = subprocess.run(
            ["git", "clone", "--depth", "25", cleaned_url, temp_dir.name],
            capture_output=True,
            check=False,
            text=True,
            timeout=30,
            env=env,
        )
        if result.returncode != 0:
            err_msg = (
                result.stderr.strip()
                or result.stdout.strip()
                or f"exit code {result.returncode}"
            )
            temp_dir.cleanup()
            raise RuntimeError(
                f"Failed to clone repository '{cleaned_url}': {err_msg}"
            )
    except subprocess.TimeoutExpired as exc:
        temp_dir.cleanup()
        raise RuntimeError(
            f"Cloning repository '{cleaned_url}' timed out after 30 seconds."
        ) from exc
    except Exception:
        temp_dir.cleanup()
        raise

    return temp_dir


class RepoInspector:
    """Read-only inspection suite for an audited repository."""

    def __init__(self, repo_path: str | Path) -> None:
        self.root = Path(repo_path).resolve()

    def _resolve_safe_path(self, rel_path: str) -> Path:
        """Resolve a path and verify it stays strictly inside the repository root."""
        cleaned = rel_path.strip().lstrip("/\\")
        resolved = (self.root / cleaned).resolve()
        if not resolved.is_relative_to(self.root):
            raise PermissionError(
                f"Access denied: path '{rel_path}' traverses outside repository root '{self.root}'."
            )
        return resolved

    def _truncate(self, text: str, max_chars: int = 8000) -> str:
        """Truncate tool output to prevent overflowing LLM context windows."""
        if len(text) > max_chars:
            omitted = len(text) - max_chars
            return text[:max_chars] + f"\n... [Truncated: {omitted} characters omitted]"
        return text

    def list_files(self) -> str:
        """Walk repo root skipping internal tooling dirs but reporting tracked sensitive files."""
        try:
            if not self.root.is_dir():
                return f"Error: Repository directory not found: '{self.root}'"

            file_list: list[str] = []
            for dirpath, dirnames, filenames in os.walk(self.root):
                # Skip internal tooling directory contents
                dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
                for filename in filenames:
                    full_path = Path(dirpath) / filename
                    rel_path = full_path.relative_to(self.root).as_posix()
                    file_list.append(rel_path)

            file_list.sort()
            if not file_list:
                return "No files found in repository."
            return self._truncate("\n".join(file_list))
        except Exception as exc:  # noqa: BLE001
            return f"Error listing files: {exc}"

    def read_file(self, path: str, start_line: int = 1, end_line: int = 250) -> str:
        """Safely read lines from a file with line numbers and secret redaction."""
        try:
            safe_path = self._resolve_safe_path(path)
            if not safe_path.exists():
                return f"Error: File not found: '{path}'"
            if not safe_path.is_file():
                return f"Error: Path is not a regular file: '{path}'"

            content = safe_path.read_text(encoding="utf-8", errors="replace")
            lines = content.splitlines()
            total_lines = len(lines)

            if total_lines == 0:
                return f"File '{path}' is empty."

            start = max(1, int(start_line))
            end = min(total_lines, int(end_line))

            if start > total_lines:
                return f"Error: start_line ({start}) exceeds total lines in file ({total_lines})."
            if start > end:
                return f"Error: start_line ({start}) cannot be greater than end_line ({end})."

            output_lines: list[str] = []
            for line_no in range(start, end + 1):
                raw_line = lines[line_no - 1]
                redacted = redact_secrets(raw_line)
                output_lines.append(f"{line_no}: {redacted}")

            return self._truncate("\n".join(output_lines))
        except Exception as exc:  # noqa: BLE001
            return f"Error reading file '{path}': {exc}"

    def search_code(self, pattern: str) -> str:
        """Search across text files using regex, redacting secrets and capping at 100 matches."""
        try:
            if not pattern:
                return "Error: Search pattern cannot be empty."

            try:
                compiled_re = re.compile(pattern, re.IGNORECASE)
            except re.error as exc:
                return f"Error: Invalid regular expression '{pattern}': {exc}"

            matches: list[str] = []
            for dirpath, dirnames, filenames in os.walk(self.root):
                dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
                for filename in filenames:
                    full_path = Path(dirpath) / filename
                    if full_path.suffix.lower() in BINARY_EXTENSIONS:
                        continue

                    # Read a small binary sample to check for null bytes
                    try:
                        with full_path.open("rb") as f:
                            sample = f.read(1024)
                            if b"\x00" in sample:
                                continue
                    except OSError:
                        continue

                    rel_path = full_path.relative_to(self.root).as_posix()
                    try:
                        content = full_path.read_text(
                            encoding="utf-8", errors="replace"
                        )
                    except OSError:
                        continue

                    for idx, line in enumerate(content.splitlines(), start=1):
                        if compiled_re.search(line):
                            redacted_line = redact_secrets(line)
                            matches.append(f"{rel_path}:{idx}: {redacted_line}")
                            if len(matches) >= 100:
                                return self._truncate("\n".join(matches))

            if not matches:
                return f"No matches found for pattern: '{pattern}'"
            return self._truncate("\n".join(matches))
        except Exception as exc:  # noqa: BLE001
            return f"Error searching code: {exc}"

    def git_log(self, max_commits: int = 20) -> str:
        """Run git log -n <max_commits> --oneline --stat inside the repo."""
        try:
            limit = max(1, int(max_commits))
            res = subprocess.run(
                ["git", "log", f"-n{limit}", "--oneline", "--stat"],
                cwd=str(self.root),
                capture_output=True,
                check=False,
                text=True,
                timeout=10,
            )
            if res.returncode != 0:
                err = res.stderr.strip() or res.stdout.strip()
                return f"Error running git log: {err}"
            output = res.stdout.strip()
            if not output:
                return "No commit history found."
            return self._truncate(output)
        except subprocess.TimeoutExpired:
            return "Error: git log timed out after 10 seconds."
        except Exception as exc:  # noqa: BLE001
            return f"Error running git log: {exc}"

    def git_status(self) -> str:
        """Run git ls-files to inspect tracked files in the repository."""
        try:
            res = subprocess.run(
                ["git", "ls-files"],
                cwd=str(self.root),
                capture_output=True,
                check=False,
                text=True,
                timeout=10,
            )
            if res.returncode != 0:
                err = res.stderr.strip() or res.stdout.strip()
                return f"Error running git ls-files: {err}"
            output = res.stdout.strip()
            if not output:
                return "No tracked files found."
            return self._truncate(output)
        except subprocess.TimeoutExpired:
            return "Error: git ls-files timed out after 10 seconds."
        except Exception as exc:  # noqa: BLE001
            return f"Error running git ls-files: {exc}"

    def run_ruff(self) -> str:
        """Run sys.executable -m ruff check . --output-format=concise inside repo root."""
        try:
            res = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "ruff",
                    "check",
                    ".",
                    "--output-format=concise",
                ],
                cwd=str(self.root),
                capture_output=True,
                check=False,
                text=True,
                timeout=15,
            )
            output = res.stdout.strip()
            if not output and res.stderr.strip():
                output = res.stderr.strip()
            if not output and res.returncode == 0:
                return "All checks passed! No ruff errors or warnings found."
            return self._truncate(
                output
                or f"Ruff completed with exit code {res.returncode} and no output."
            )
        except subprocess.TimeoutExpired:
            return "Error: ruff check timed out after 15 seconds."
        except Exception as exc:  # noqa: BLE001
            return f"Error running ruff: {exc}"

    def execute_tool(self, tool_name: str, arguments: dict[str, Any] | None = None) -> str:
        """Dispatch a tool by name with arguments."""
        args = arguments or {}
        tool_map = {
            "list_files": lambda: self.list_files(),
            "read_file": lambda: self.read_file(**args),
            "search_code": lambda: self.search_code(**args),
            "git_log": lambda: self.git_log(**args),
            "git_status": lambda: self.git_status(),
            "run_ruff": lambda: self.run_ruff(),
        }
        handler = tool_map.get(tool_name)
        if not handler:
            return f"Error: Unknown tool '{tool_name}'."
        try:
            return handler()
        except TypeError as exc:
            return f"Error: Invalid arguments for tool '{tool_name}': {exc}"
        except Exception as exc:  # noqa: BLE001
            return f"Error executing tool '{tool_name}': {exc}"


TOOL_SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "list_files",
            "description": (
                "List all file paths in the repository relative to the root directory, "
                "excluding internal virtual environments and git directories, while showing "
                "any tracked .env, __pycache__, .DS_Store, or log files."
            ),
            "parameters": {
                "type": "object",
                "properties": {},
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_file",
            "description": (
                "Read lines from a specific file within the repository, prefixing each line "
                "with its 1-based line number. Any detected inline secrets are automatically redacted."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Relative path to the file within the repository.",
                    },
                    "start_line": {
                        "type": "integer",
                        "description": "1-based starting line number to read (default is 1).",
                        "default": 1,
                    },
                    "end_line": {
                        "type": "integer",
                        "description": "1-based ending line number to read (default is 250).",
                        "default": 250,
                    },
                },
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "search_code",
            "description": (
                "Search across all text files in the repository using a regular expression pattern. "
                "Returns matching lines formatted as 'relative/path:line_num: matched_line' with secrets redacted."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "pattern": {
                        "type": "string",
                        "description": "Regular expression pattern to search for (case-insensitive).",
                    },
                },
                "required": ["pattern"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "git_log",
            "description": (
                "Retrieve recent git commit logs (one-line summary with file stats) from the repository."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "max_commits": {
                        "type": "integer",
                        "description": "Maximum number of recent commits to return (default is 20).",
                        "default": 20,
                    },
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "git_status",
            "description": (
                "Run 'git ls-files' to inspect all tracked files in the Git index, useful for verifying "
                "whether sensitive files (.env), caches (__pycache__), or build artifacts were committed."
            ),
            "parameters": {
                "type": "object",
                "properties": {},
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_ruff",
            "description": (
                "Execute Ruff static analysis checks across the repository in concise output format "
                "without executing untrusted code."
            ),
            "parameters": {
                "type": "object",
                "properties": {},
                "required": [],
            },
        },
    },
]
