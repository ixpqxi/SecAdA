"""Command-line entry point for taint discovery and report verification."""

import argparse
import json
import sys
from pathlib import Path

from dotenv import load_dotenv
from openai import OpenAIError

from .agent import create_vulnerability_discovery_agent
from .pipeline import create_taint_audit_pipeline


APPLICATION_ROOT = Path(__file__).resolve().parents[2]


def build_parser() -> argparse.ArgumentParser:
  parser = argparse.ArgumentParser(
    prog="vuln-discovery-auditor",
    description=(
      "Run evidence-backed taint-flow vulnerability discovery, then pass the "
      "resulting report to vuln-report-verifier."
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
    "--verification-instruction",
    help="optional verification focus appended to the complete review workflow",
  )
  parser.add_argument(
    "--audit-only",
    action="store_true",
    help="run only vulnerability discovery without report verification",
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
    if args.audit_only:
      agent = create_vulnerability_discovery_agent(
        args.project,
        output_directory=args.output_directory,
        recursion_limit=args.recursion_limit,
        completion_retries=args.completion_retries,
      )
      result = agent.invoke(args.instruction)
      payload = {
        "status": "completed",
        "audit_report_path": str(result.output_path),
        "agent_response": result.final_response,
      }
    else:
      result = create_taint_audit_pipeline(
        args.project,
        output_directory=args.output_directory,
        recursion_limit=args.recursion_limit,
        completion_retries=args.completion_retries,
      ).invoke(
        audit_instruction=args.instruction,
        verification_instruction=args.verification_instruction,
      )
      payload = {
        "status": "completed",
        "audit_report_path": (
          str(result.audit_report_path) if result.audit_report_path else None
        ),
        "verification_report_path": (
          str(result.verification_report_path)
          if result.verification_report_path
          else None
        ),
        "summary": result.state["summary"],
      }
  except (OpenAIError, RuntimeError, ValueError) as exc:
    print(f"Taint audit pipeline failed: {exc}", file=sys.stderr)
    return 1
  print(json.dumps(payload, ensure_ascii=False, indent=2))
  return 0


if __name__ == "__main__":
  raise SystemExit(main())
