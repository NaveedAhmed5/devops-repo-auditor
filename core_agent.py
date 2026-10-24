"""Core autonomous agent loop for DevOps Repo Auditor.

Orchestrates repository cloning, tool execution, LLM conversation management,
and report validation in pure Python without third-party agent frameworks.
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any

from cerebras.cloud.sdk import Cerebras
from dotenv import load_dotenv

from prompts import SYSTEM_PROMPT, make_user_prompt
from schemas import parse_and_validate_report, redact_secrets
from tools import TOOL_SCHEMAS, RepoInspector, clone_repo

# Load environment variables from .env if present
load_dotenv()


def execute_tool_call(
    inspector: RepoInspector, tool_name: str, args: dict[str, Any] | None = None
) -> str:
    """Dispatch a tool call to RepoInspector and ensure output is secret-redacted."""
    arguments = args or {}
    tool_map = {
        "list_files": lambda: inspector.list_files(),
        "read_file": lambda: inspector.read_file(**arguments),
        "search_code": lambda: inspector.search_code(**arguments),
        "git_log": lambda: inspector.git_log(**arguments),
        "git_status": lambda: inspector.git_status(),
        "run_ruff": lambda: inspector.run_ruff(),
    }
    handler = tool_map.get(tool_name)
    if not handler:
        raw_output = f"Error: Unknown tool '{tool_name}'."
    else:
        try:
            raw_output = handler()
        except TypeError as exc:
            raw_output = f"Error: Invalid arguments for tool '{tool_name}': {exc}"
        except Exception as exc:  # noqa: BLE001
            raw_output = f"Error executing tool '{tool_name}': {exc}"

    return redact_secrets(raw_output)


def run_agent_audit(
    repo_url: str,
    max_turns: int = 15,
    verbose: bool = True,
    client: Any | None = None,
) -> dict[str, Any]:
    """Execute the autonomous repository audit agent loop.

    Args:
        repo_url: HTTP or HTTPS GitHub repository URL to audit.
        max_turns: Maximum conversation turns before forcing final synthesis.
        verbose: Whether to log step-by-step agent actions.
        client: Optional Cerebras client instance (for testing/mocking).

    Returns:
        Validated audit report dictionary matching AuditReport schema.

    Raises:
        RuntimeError: If CEREBRAS_API_KEY is not set or repo cloning fails.
        ValueError: If repository URL is invalid or JSON parsing fails.
    """
    if client is None:
        api_key = os.environ.get("CEREBRAS_API_KEY")
        if not api_key:
            raise RuntimeError(
                "Missing required environment variable 'CEREBRAS_API_KEY'. "
                "Please configure it in your .env file or environment."
            )
        client = Cerebras(api_key=api_key)

    model = os.environ.get("CEREBRAS_MODEL", "qwen-3.8-27b")

    if verbose:
        sys.stdout.write(f"[*] Starting audit for repository: {repo_url}\n")
        sys.stdout.write(f"[*] Using model: {model} (max turns: {max_turns})\n")
        sys.stdout.flush()

    # Clone repository into a temporary directory with guaranteed cleanup
    temp_dir = clone_repo(repo_url)
    try:
        inspector = RepoInspector(temp_dir.name)
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": make_user_prompt(repo_url)},
        ]

        for turn in range(max_turns):
            if verbose:
                sys.stdout.write(f"\n[Turn {turn + 1}/{max_turns}] Querying LLM...\n")
                sys.stdout.flush()

            response = client.chat.completions.create(
                model=model,
                messages=messages,
                tools=TOOL_SCHEMAS,
                temperature=0.1,
            )

            assistant_msg = response.choices[0].message
            tool_calls = getattr(assistant_msg, "tool_calls", None)

            # If model requested tool executions
            if tool_calls:
                # Format assistant message with tool calls
                tool_calls_payload = []
                for tc in tool_calls:
                    tool_calls_payload.append(
                        {
                            "id": tc.id,
                            "type": "function",
                            "function": {
                                "name": tc.function.name,
                                "arguments": tc.function.arguments,
                            },
                        }
                    )

                messages.append(
                    {
                        "role": "assistant",
                        "content": assistant_msg.content or "",
                        "tool_calls": tool_calls_payload,
                    }
                )

                for tc in tool_calls:
                    fn_name = tc.function.name
                    raw_args = tc.function.arguments or "{}"
                    try:
                        parsed_args = json.loads(raw_args)
                    except json.JSONDecodeError:
                        parsed_args = {}

                    if verbose:
                        sys.stdout.write(f"  -> Invoking tool: {fn_name}({parsed_args})\n")
                        sys.stdout.flush()

                    tool_result = execute_tool_call(inspector, fn_name, parsed_args)

                    if verbose:
                        preview = tool_result[:120].replace("\n", " ")
                        sys.stdout.write(f"     [Result: {len(tool_result)} chars] {preview}...\n")
                        sys.stdout.flush()

                    messages.append(
                        {
                            "role": "tool",
                            "tool_call_id": tc.id,
                            "content": tool_result,
                        }
                    )
            else:
                # No tool calls requested: Model produced final report
                final_content = assistant_msg.content or ""
                if verbose:
                    sys.stdout.write("[*] Final report received from model. Validating output...\n")
                    sys.stdout.flush()
                return parse_and_validate_report(final_content, repo_url)

        # If loop finishes without returning, force synthesis without tools
        if verbose:
            sys.stdout.write(
                f"\n[*] Reached maximum turns ({max_turns}). Requesting final report synthesis...\n"
            )
            sys.stdout.flush()

        messages.append(
            {
                "role": "user",
                "content": (
                    "Maximum tool execution turns reached. Do not call any further tools. "
                    "Immediately synthesize all your observations and output the final audit report "
                    "strictly formatted as the requested JSON object."
                ),
            }
        )

        final_response = client.chat.completions.create(
            model=model,
            messages=messages,
            temperature=0.1,
        )
        final_content = final_response.choices[0].message.content or ""
        return parse_and_validate_report(final_content, repo_url)

    finally:
        temp_dir.cleanup()
