"""Command-line interface for autonomous DevOps Repository Auditing Agent.

Supports unattended execution:
    python agent.py --repo <github_repository_url> --output report.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from core_agent import run_agent_audit


def build_parser() -> argparse.ArgumentParser:
    """Construct argument parser for the agent CLI."""
    parser = argparse.ArgumentParser(
        description="Autonomous DevOps Repository Auditing Agent in pure Python.",
    )
    parser.add_argument(
        "--repo",
        required=True,
        help="GitHub repository HTTP or HTTPS URL to clone and audit.",
    )
    parser.add_argument(
        "--output",
        default="report.json",
        help="Destination file path for the output JSON audit report (default: report.json).",
    )
    parser.add_argument(
        "--max-turns",
        type=int,
        default=15,
        help="Maximum agent turns before forcing final synthesis (default: 15).",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress real-time progress messages during audit.",
    )
    return parser


def main() -> None:
    """Execute the CLI application."""
    parser = build_parser()
    args = parser.parse_args()

    try:
        report = run_agent_audit(
            repo_url=args.repo,
            max_turns=args.max_turns,
            verbose=not args.quiet,
        )

        output_path = Path(args.output).resolve()
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with output_path.open("w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)

        violation_count = len(report.get("violations", []))
        sys.stdout.write(
            f"\n[+] Audit completed successfully. {violation_count} violation(s) written to: {output_path}\n"
        )
    except Exception as exc:  # noqa: BLE001
        sys.stderr.write(f"Error: {exc}\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
