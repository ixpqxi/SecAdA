"""Command-line entry point for the LangGraph static BAC pipeline."""

import argparse
import json
import sys
from pathlib import Path

from dotenv import load_dotenv
from openai import OpenAIError

from .graph import create_bac_static_pipeline

APPLICATION_ROOT = Path(__file__).resolve().parents[2]


def build_parser() -> argparse.ArgumentParser:
  parser = argparse.ArgumentParser(
    prog="bac-static-pipeline",
    description="Run the boundary, BAC detection, and exploit-chain stages.",
  )
  parser.add_argument("project", type=Path, help="target project's root path")
  parser.add_argument(
    "--output-root",
    type=Path,
    help="artifact root; defaults to this SecAdA repository's output directory",
  )
  parser.add_argument(
    "--scope-hints",
    help="optional modules, route prefixes, or business domains to prioritize",
  )
  parser.add_argument("--recursion-limit", type=int, default=100)
  parser.add_argument("--completion-retries", type=int, default=1)
  return parser


def main(argv: list[str] | None = None) -> int:
  load_dotenv(APPLICATION_ROOT / ".env")
  args = build_parser().parse_args(argv)
  if args.recursion_limit < 1 or args.completion_retries < 0:
    print("Limits must be non-negative, and recursion-limit must be positive.", file=sys.stderr)
    return 2
  try:
    result = create_bac_static_pipeline(
      args.project,
      output_root=args.output_root,
      recursion_limit=args.recursion_limit,
      completion_retries=args.completion_retries,
    ).invoke(scope_hints=args.scope_hints)
  except (OpenAIError, RuntimeError, ValueError) as exc:
    print(f"BAC static pipeline failed: {exc}", file=sys.stderr)
    return 1
  print(json.dumps(result.state, ensure_ascii=False, indent=2))
  return 0


if __name__ == "__main__":
  raise SystemExit(main())
