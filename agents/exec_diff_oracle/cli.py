"""CLI for runtime differential verification."""

import argparse
import json
import sys
from pathlib import Path

from dotenv import load_dotenv
from openai import OpenAIError

from .agent import create_exec_diff_oracle_agent


def build_parser() -> argparse.ArgumentParser:
  parser = argparse.ArgumentParser(description="Execute planned BAC differential chains.")
  parser.add_argument("project", type=Path)
  parser.add_argument("--base-url", required=True)
  parser.add_argument("--victim-token")
  parser.add_argument("--attacker-token")
  parser.add_argument("--victim-cookie")
  parser.add_argument("--attacker-cookie")
  parser.add_argument("--endpoint-inventory", type=Path)
  parser.add_argument("--vulnerable-targets", type=Path)
  parser.add_argument("--exploit-chains", type=Path)
  parser.add_argument("--output-root", type=Path)
  parser.add_argument("--instruction")
  parser.add_argument("--recursion-limit", type=int, default=200)
  parser.add_argument("--completion-retries", type=int, default=1)
  return parser


def main(argv: list[str] | None = None) -> int:
  load_dotenv(Path(__file__).resolve().parents[2] / ".env")
  args = build_parser().parse_args(argv)
  environment = {
    "base_url": args.base_url, "victim_token": args.victim_token,
    "attacker_token": args.attacker_token, "victim_cookie": args.victim_cookie,
    "attacker_cookie": args.attacker_cookie,
  }
  try:
    result = create_exec_diff_oracle_agent(
      args.project, environment, endpoint_inventory_path=args.endpoint_inventory,
      vulnerable_targets_path=args.vulnerable_targets,
      exploit_chains_path=args.exploit_chains, output_root=args.output_root,
      recursion_limit=args.recursion_limit, completion_retries=args.completion_retries,
    ).invoke(args.instruction)
  except (OpenAIError, RuntimeError, ValueError) as exc:
    print(f"Execution failed: {exc}", file=sys.stderr)
    return 1
  print(json.dumps({"status": "completed", "manifest_path": str(result.manifest_path)}, ensure_ascii=False, indent=2))
  return 0


if __name__ == "__main__":
  raise SystemExit(main())
