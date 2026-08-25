"""Command-line entry point for preliminary vulnerability report verification."""

import argparse
import json
import sys
from pathlib import Path

from dotenv import load_dotenv
from openai import OpenAIError

from .agent import create_vulnerability_report_verifier_agent


APPLICATION_ROOT = Path(__file__).resolve().parents[2]


def build_parser() -> argparse.ArgumentParser:
  parser = argparse.ArgumentParser(
    prog="vuln-report-verifier",
    description=(
      "Verify a preliminary vulnerability report against the target project's "
      "global business and authorization paths."
    ),
  )
  parser.add_argument("project", type=Path, help="target project's root path")
  parser.add_argument("report", type=Path, help="preliminary vulnerability report")
  parser.add_argument(
    "--output-directory",
    type=Path,
    help="optional verification-report directory; defaults to project/vuln_scan",
  )
  parser.add_argument(
    "--instruction",
    help="optional verification focus appended to the complete workflow",
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
    agent = create_vulnerability_report_verifier_agent(
      args.project,
      args.report,
      output_directory=args.output_directory,
      recursion_limit=args.recursion_limit,
      completion_retries=args.completion_retries,
    )
    result = agent.invoke(args.instruction)
  except (OpenAIError, RuntimeError, ValueError) as exc:
    print(f"Vulnerability report verification failed: {exc}", file=sys.stderr)
    return 1
  print(
    json.dumps(
      {
        "status": "completed",
        "preliminary_report_path": str(result.preliminary_report_path),
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
