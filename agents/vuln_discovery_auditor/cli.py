"""Command-line entry point for structural vulnerability discovery."""

import argparse
import json
import sys
from pathlib import Path

from dotenv import load_dotenv
from openai import OpenAIError

from .agent import create_vulnerability_discovery_agent


APPLICATION_ROOT = Path(__file__).resolve().parents[2]


def build_parser() -> argparse.ArgumentParser:
  parser = argparse.ArgumentParser(
    prog="vuln-discovery-auditor",
    description=(
      "Perform evidence-backed attack-surface and taint-flow vulnerability "
      "discovery on a source project."
    ),
  )
  parser.add_argument("project", type=Path, help="target project's root path")
  parser.add_argument(
    "--output-directory",
    type=Path,
    help="optional report directory; defaults to project/vuln_scan",
  )
  parser.add_argument(
    "--instruction",
    help="optional audit focus appended to the complete default workflow",
  )
  parser.add_argument(
    "--recursion-limit",
    type=int,
    default=200,
    help="maximum LangGraph steps (default: 200)",
  )
  parser.add_argument(
    "--completion-retries",
    type=int,
    default=1,
    help="re-prompts when the model stops before writing the report (default: 1)",
  )
  return parser


def main(argv: list[str] | None = None) -> int:
  load_dotenv(APPLICATION_ROOT / ".env")
  args = build_parser().parse_args(argv)
  if args.recursion_limit < 1 or args.completion_retries < 0:
    print(
      "Limits must be non-negative, and recursion-limit must be positive.",
      file=sys.stderr,
    )
    return 2
  try:
    agent = create_vulnerability_discovery_agent(
      args.project,
      output_directory=args.output_directory,
      recursion_limit=args.recursion_limit,
      completion_retries=args.completion_retries,
    )
    result = agent.invoke(args.instruction)
  except (OpenAIError, RuntimeError, ValueError) as exc:
    print(f"Vulnerability discovery failed: {exc}", file=sys.stderr)
    return 1
  print(
    json.dumps(
      {
        "status": "completed",
        "output_path": str(result.output_path),
        "agent_response": result.final_response,
      },
      ensure_ascii=False,
      indent=2,
    )
  )
  return 0


if __name__ == "__main__":
  raise SystemExit(main())
