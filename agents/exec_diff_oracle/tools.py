"""Safe, project-scoped tools for executing planned BAC differential chains."""

from __future__ import annotations

import difflib
import json
import re
import subprocess
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Any
from urllib.parse import urljoin, urlparse

from langchain_core.tools import BaseTool, StructuredTool, ToolException
from pydantic import ValidationError

from agents.boundary_analysis.schemas import EndpointInventory
from agents.detect_bac_vuln.schemas import VulnerableTargetsMap
from agents.generate_exploit_chain.schemas import (
  ExploitChain,
  ExploitChainsPlan,
)

from .schemas import ExecutionManifest, RuntimeEnvironment
from .skill import read_skill_file

MAX_RESPONSE_BYTES = 2_000_000
VARIABLE_PATTERN = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")
NOISE_KEYS = {
  "created_at", "updated_at", "timestamp", "trace_id", "request_id",
  "message", "msg",
}


@dataclass
class ExecDiffOracleToolkit:
  """Bind execution to validated artifacts and one explicit environment."""

  project_root: Path
  environment: RuntimeEnvironment | dict[str, Any]
  endpoint_inventory_path: str | Path | None = None
  vulnerable_targets_path: str | Path | None = None
  exploit_chains_path: str | Path | None = None
  output_root: str | Path | None = None
  written_paths: list[Path] = field(default_factory=list)
  _tools: list[BaseTool] = field(init=False, repr=False)
  _inventory_path: Path = field(init=False, repr=False)
  _targets_path: Path = field(init=False, repr=False)
  _chains_path: Path = field(init=False, repr=False)
  _environment: RuntimeEnvironment = field(init=False, repr=False)
  _chains: dict[str, ExploitChain] = field(init=False, repr=False)

  def __post_init__(self) -> None:
    self.project_root = Path(self.project_root).expanduser().resolve()
    if not self.project_root.is_dir():
      raise ValueError(f"Project root is not a directory: {self.project_root}")
    self._environment = RuntimeEnvironment.model_validate(self.environment)
    self._inventory_path = self._find_artifact(
      self.endpoint_inventory_path, "Endpoint_Inventory_*.json", "Endpoint inventory"
    )
    self._targets_path = self._find_artifact(
      self.vulnerable_targets_path,
      "Vulnerable_Targets_Map_*.json",
      "Vulnerable targets map",
    )
    self._chains_path = self._find_artifact(
      self.exploit_chains_path,
      "Exploit_Chains_Plan_*.json",
      "Exploit chains plan",
    )
    self._chains = self._read_chains()
    self._validate_references()
    self._tools = self._build_tools()

  @property
  def tools(self) -> list[BaseTool]:
    return list(self._tools)

  @property
  def selected_inventory_path(self) -> Path:
    return self._inventory_path

  @property
  def selected_targets_path(self) -> Path:
    return self._targets_path

  @property
  def selected_chains_path(self) -> Path:
    return self._chains_path

  def _find_artifact(
    self,
    requested: str | Path | None,
    pattern: str,
    label: str,
  ) -> Path:
    directory = (self.project_root / "vuln_scan").resolve()
    if requested is None:
      candidates = sorted(
        directory.glob(pattern),
        key=lambda path: (path.stat().st_mtime_ns, path.name),
      ) if directory.is_dir() else []
      if not candidates:
        raise ValueError(f"No {pattern} found in {directory}")
      candidate = candidates[-1]
    else:
      candidate = (self.project_root / requested).resolve()
    try:
      relative = candidate.relative_to(directory)
    except ValueError as exc:
      raise ValueError(f"{label} must be inside vuln_scan") from exc
    if (
      not candidate.is_file()
      or candidate.is_symlink()
      or len(relative.parts) != 1
      or candidate.suffix != ".json"
      or not candidate.match(pattern)
    ):
      raise ValueError(f"{label} must be a regular vuln_scan/{pattern} file")
    return candidate

  def _read_chains(self) -> dict[str, ExploitChain]:
    try:
      parsed = ExploitChainsPlan.model_validate_json(
        self._chains_path.read_text(encoding="utf-8")
      )
    except (OSError, ValueError, ValidationError) as exc:
      raise ValueError(f"Exploit chains plan could not be validated: {exc}") from exc
    chains: dict[str, ExploitChain] = {}
    for chain in parsed.root:
      if chain.chain_id in chains:
        raise ValueError(f"Duplicate chain_id in plan: {chain.chain_id}")
      chains[chain.chain_id] = chain
    return chains

  def _validate_references(self) -> None:
    """Ensure the execution plan is grounded in the preceding artifacts."""
    try:
      inventory = EndpointInventory.model_validate_json(
        self._inventory_path.read_text(encoding="utf-8")
      )
      targets = VulnerableTargetsMap.model_validate_json(
        self._targets_path.read_text(encoding="utf-8")
      )
    except (OSError, ValueError, ValidationError) as exc:
      raise ValueError(f"Execution input artifact could not be validated: {exc}") from exc
    inventory_endpoints = {
      (item.http_method, _canonical_path(item.url_path))
      for item in inventory.api_inventory
    }
    target_endpoints = set()
    target_refs = set()
    for target in targets.root:
      endpoint = (
        target.target_endpoint.http_method,
        _canonical_path(target.target_endpoint.url_path),
      )
      target_endpoints.add(endpoint)
      target_refs.add((*endpoint, target.vulnerability_type))
      if target.bound_read_endpoint:
        target_endpoints.add((
          target.bound_read_endpoint.http_method,
          _canonical_path(target.bound_read_endpoint.url_path),
        ))
    for chain in self._chains.values():
      target_ref = (
        chain.target_vuln_reference.http_method,
        _canonical_path(chain.target_vuln_reference.url_path),
        chain.target_vuln_reference.vulnerability_type,
      )
      if target_ref not in target_refs:
        raise ValueError(
          f"Chain {chain.chain_id} is not grounded in Vulnerable_Targets_Map"
        )
      for step in chain.exploit_chain:
        endpoint = (step.endpoint.http_method, _canonical_path(step.endpoint.url_path))
        if endpoint not in inventory_endpoints and endpoint not in target_endpoints:
          raise ValueError(
            f"Chain {chain.chain_id} references endpoint outside input artifacts: "
            f"{step.endpoint.http_method} {step.endpoint.url_path}"
          )
      exploit_step = chain.exploit_chain[2]
      exploit_endpoint = (
        exploit_step.endpoint.http_method,
        _canonical_path(exploit_step.endpoint.url_path),
      )
      expected_endpoint = (target_ref[0], target_ref[1])
      if exploit_endpoint != expected_endpoint:
        raise ValueError(
          f"Chain {chain.chain_id} step 3 must target the vulnerability endpoint"
        )

  def _build_tools(self) -> list[BaseTool]:
    def load_endpoint_inventory(offset: int = 0, limit: int = 100) -> str:
      """Read a validated page of the endpoint inventory."""
      if offset < 0:
        raise ToolException("offset cannot be negative")
      try:
        parsed = EndpointInventory.model_validate_json(
          self._inventory_path.read_text(encoding="utf-8")
        )
      except (OSError, ValueError, ValidationError) as exc:
        raise ToolException(f"Endpoint inventory could not be validated: {exc}") from exc
      size = min(max(limit, 1), 100)
      return json.dumps({
        "inventory_path": str(self._inventory_path),
        "total": len(parsed.api_inventory),
        "offset": offset,
        "items": [
          item.model_dump(by_alias=True, exclude_none=True)
          for item in parsed.api_inventory[offset:offset + size]
        ],
      }, ensure_ascii=False)

    def load_vulnerable_targets(offset: int = 0, limit: int = 100) -> str:
      """Read a validated page of the vulnerable targets map."""
      if offset < 0:
        raise ToolException("offset cannot be negative")
      try:
        parsed = VulnerableTargetsMap.model_validate_json(
          self._targets_path.read_text(encoding="utf-8")
        )
      except (OSError, ValueError, ValidationError) as exc:
        raise ToolException(f"Vulnerable targets map could not be validated: {exc}") from exc
      size = min(max(limit, 1), 100)
      return json.dumps({
        "targets_path": str(self._targets_path),
        "total": len(parsed.root),
        "offset": offset,
        "items": [item.model_dump(exclude_none=True)
                  for item in parsed.root[offset:offset + size]],
      }, ensure_ascii=False)

    def load_exploit_chains_plan(offset: int = 0, limit: int = 100) -> str:
      """Read a validated page of the exploit chain plan."""
      if offset < 0:
        raise ToolException("offset cannot be negative")
      values = list(self._chains.values())
      size = min(max(limit, 1), 100)
      return json.dumps({
        "chains_path": str(self._chains_path),
        "total": len(values),
        "offset": offset,
        "items": [item.model_dump(exclude_none=True)
                  for item in values[offset:offset + size]],
      }, ensure_ascii=False)

    def preflight_environment() -> str:
      """Probe BASE_URL with a lightweight victim request."""
      victim = self._curl("GET", "/", "victim", None)
      attacker = self._curl("GET", "/", "attacker", None)
      return json.dumps({
        "base_url": self._environment.base_url,
        "reachable": victim["curl_error"] is None and attacker["curl_error"] is None,
        "victim": {"http_code": victim["http_code"], "error": victim["curl_error"]},
        "attacker": {"http_code": attacker["http_code"], "error": attacker["curl_error"]},
      }, ensure_ascii=False)

    def load_skill_reference(resource_name: str) -> str:
      """Load a packaged PoC/report methodology or output template."""
      allowed = {
        "poc-bash-methodology": "references/poc-bash-methodology.md",
        "typst-report-methodology": "references/typst-report-methodology.md",
        "poc-script-template": "examples/poc_script_template.sh",
        "output-report-template": "examples/output_report.typ",
      }
      relative_path = allowed.get(resource_name)
      if relative_path is None:
        raise ToolException(
          "Unknown reference. Use one of: " + ", ".join(sorted(allowed))
        )
      return read_skill_file(relative_path)

    def execute_exploit_chain(chain_id: str) -> str:
      """Execute one validated chain and create paired proof artifacts."""
      try:
        result = self._execute_chain(chain_id)
      except (OSError, ValueError, ToolException) as exc:
        raise ToolException(str(exc)) from exc
      return result.model_dump_json(exclude_none=True)

    def write_execution_manifest(results: list[dict[str, Any]]) -> str:
      """Validate and atomically write the execution manifest."""
      if self.written_paths:
        raise ToolException(f"Manifest already finalized at {self.written_paths[-1]}")
      try:
        manifest = ExecutionManifest.model_validate(results)
      except ValidationError as exc:
        raise ToolException(f"Execution manifest validation failed: {exc}") from exc
      directory = self.project_root / "vuln_scan"
      directory.mkdir(parents=True, exist_ok=True)
      path = directory / (
        f"Exec_Diff_Oracle_Manifest_{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}.json"
      )
      with NamedTemporaryFile("w", encoding="utf-8", dir=directory,
                             prefix=".exec_diff_", suffix=".tmp", delete=False) as temp:
        temp.write(manifest.model_dump_json(indent=2))
        temp.write("\n")
        temp_path = Path(temp.name)
      temp_path.replace(path)
      self.written_paths.append(path)
      return json.dumps({"status": "written", "path": str(path),
                         "chain_count": len(manifest.root)}, ensure_ascii=False)

    return [
      StructuredTool.from_function(load_endpoint_inventory, handle_tool_error=True),
      StructuredTool.from_function(load_vulnerable_targets, handle_tool_error=True),
      StructuredTool.from_function(load_exploit_chains_plan, handle_tool_error=True),
      StructuredTool.from_function(load_skill_reference, handle_tool_error=True),
      StructuredTool.from_function(preflight_environment, handle_tool_error=True),
      StructuredTool.from_function(execute_exploit_chain, handle_tool_error=True),
      StructuredTool.from_function(write_execution_manifest, handle_tool_error=True),
    ]

  def _execute_chain(self, chain_id: str):
    chain = self._chains.get(chain_id)
    if chain is None:
      raise ToolException(f"Unknown chain_id: {chain_id}")
    state: dict[str, Any] = {}
    responses: dict[int, dict[str, Any]] = {}
    output_dir = self._output_directory(chain_id)
    try:
      for step in chain.exploit_chain:
        rendered_url = self._render(step.endpoint.url_path, state)
        rendered_payload = self._render_value(step.payload_template, state)
        response = self._curl(
          step.endpoint.http_method, rendered_url, step.executor_role.lower(),
          rendered_payload,
        )
        responses[step.step_index] = response
        if response["curl_error"]:
          raise ToolException(response["curl_error"])
        if step.step_index == 1 and not 200 <= response["http_code"] < 300:
          raise ToolException(f"Precondition returned HTTP {response['http_code']}")
        for rule in step.data_extraction_rules:
          value = _json_path(response["json"], rule.param_source)
          state[rule.extract_to_variable] = str(value)
        self._write_step(output_dir, step.step_index, response)
      pre = _stable(responses[2]["json"] if responses[2]["json"] is not None
                    else responses[2]["body"])
      post = _stable(responses[4]["json"] if responses[4]["json"] is not None
                     else responses[4]["body"])
      diff = "\n".join(difflib.unified_diff(
        pre.splitlines(), post.splitlines(), fromfile="pre.txt", tofile="post.txt",
        lineterm="",
      ))
      attack = responses[3]
      changed = pre != post
      successful_attack = 200 <= attack["http_code"] < 300
      verdict = "VULNERABLE" if successful_attack else "SAFE"
      explanation = (
        "Attacker request succeeded against the planned vulnerable endpoint; "
        + ("the victim-visible stable fields changed." if changed else
           "the endpoint success is runtime evidence even though the stable diff was weak.")
        if verdict == "VULNERABLE" else
        "Attacker request was rejected and no exploitable state change was observed."
      )
      result = {
        "chain_id": chain_id, "verdict": verdict,
        "attack_http_code": attack["http_code"],
        "attack_response": attack["json"] or attack["body"],
        "pre_snapshot": responses[2]["json"] or responses[2]["body"],
        "post_snapshot": responses[4]["json"] or responses[4]["body"],
        "diff": diff, "explanation": explanation,
        "artifacts_dir": str(output_dir),
      }
    except Exception as exc:
      result = {
        "chain_id": chain_id, "verdict": "ERROR", "diff": "",
        "explanation": f"Execution stopped before a reliable verdict: {exc}",
        "artifacts_dir": str(output_dir), "error": str(exc),
      }
    script_path = self._write_script(output_dir, chain)
    report_path = self._write_report(output_dir, chain, result)
    result["script_path"] = str(script_path)
    result["report_path"] = str(report_path)
    from .schemas import ChainExecutionResult
    return ChainExecutionResult.model_validate(result)

  def _curl(self, method: str, path: str, role: str,
            payload: dict[str, Any] | None) -> dict[str, Any]:
    base = self._environment.base_url.rstrip("/") + "/"
    parsed = urlparse(path)
    if parsed.scheme or parsed.netloc or not path.startswith("/"):
      raise ToolException("Planned endpoint must be an absolute path under BASE_URL")
    url = urljoin(base, path.lstrip("/"))
    token = (self._environment.victim_token if role == "victim"
             else self._environment.attacker_token)
    cookie = (self._environment.victim_cookie if role == "victim"
              else self._environment.attacker_cookie)
    if role == "victim" and not (token or cookie):
      raise ToolException("Victim authentication material is required")
    if role == "attacker" and not (token or cookie):
      raise ToolException("Attacker authentication material is required")
    args = ["curl", "-sS", "--max-time", "30", "-o", "-", "-w", "\n%{http_code}",
            "-X", method.upper()]
    if token:
      args.extend(["-H", f"Authorization: Bearer {token}"])
    if cookie:
      args.extend(["-H", f"Cookie: {cookie}"])
    if payload is not None:
      args.extend(["-H", "Content-Type: application/json",
                   "--data-raw", json.dumps(payload, ensure_ascii=False)])
    args.append(url)
    completed = subprocess.run(args, capture_output=True, text=True,
                               timeout=35, check=False)
    if completed.returncode != 0:
      return {"http_code": 0, "body": completed.stdout,
              "json": None, "curl_error": completed.stderr.strip() or
              f"curl exited {completed.returncode}"}
    body, _, code_text = completed.stdout.rpartition("\n")
    if len(body.encode("utf-8", errors="replace")) > MAX_RESPONSE_BYTES:
      body = body[:MAX_RESPONSE_BYTES]
    try:
      code = int(code_text)
    except ValueError:
      code = 0
    try:
      parsed_body = json.loads(body)
    except (ValueError, TypeError):
      parsed_body = None
    return {"http_code": code, "body": body[:MAX_RESPONSE_BYTES],
            "json": parsed_body, "curl_error": None}

  def _output_directory(self, chain_id: str) -> Path:
    base = Path(self.output_root) if self.output_root else self.project_root / "vuln_scan" / "exec_diff_oracle"
    directory = (self.project_root / base).resolve() if not base.is_absolute() else base.resolve()
    try:
      directory.relative_to(self.project_root)
    except ValueError as exc:
      raise ToolException("output_root must stay inside the target project") from exc
    safe_id = re.sub(r"[^A-Za-z0-9_.-]+", "_", chain_id)
    result = directory / safe_id
    result.mkdir(parents=True, exist_ok=True)
    return result

  @staticmethod
  def _render(value: str, state: dict[str, Any]) -> str:
    def replace(match: re.Match[str]) -> str:
      name = match.group(1)
      if name not in state:
        raise ToolException(f"Missing runtime variable: {name}")
      return str(state[name])
    return VARIABLE_PATTERN.sub(replace, value)

  def _render_value(self, value: Any, state: dict[str, Any]) -> Any:
    if isinstance(value, str):
      return self._render(value, state)
    if isinstance(value, dict):
      return {key: self._render_value(item, state) for key, item in value.items()}
    if isinstance(value, list):
      return [self._render_value(item, state) for item in value]
    return value

  @staticmethod
  def _write_step(directory: Path, index: int, response: dict[str, Any]) -> None:
    (directory / f"step_{index}.json").write_text(
      json.dumps({"http_code": response["http_code"],
                  "body": response["json"] or response["body"]},
                 ensure_ascii=False, indent=2), encoding="utf-8"
    )

  def _write_script(self, directory: Path, chain: ExploitChain) -> Path:
    name = re.sub(r"[^A-Za-z0-9_.-]+", "_", chain.chain_id)
    path = directory / f"poc_{name}.sh"
    lines = ["#!/usr/bin/env bash", "set -euo pipefail", "",
             'BASE_URL="${BASE_URL:-http://127.0.0.1:8000}"',
             'VICTIM_TOKEN="${VICTIM_TOKEN:-REPLACE_ME}"',
             'ATTACKER_TOKEN="${ATTACKER_TOKEN:-REPLACE_ME}"',
             'WORKDIR="${WORKDIR:-$(mktemp -d -p . poc_' + name + '_XXXXXX)}"',
             "mkdir -p \"${WORKDIR}\"", "",
             "stable() {",
             "  if jq empty \"$1\" >/dev/null 2>&1; then",
             "    jq 'walk(if type == \"object\" then with_entries(select(.key |",
             "      test(\"^(created_at|updated_at|timestamp|trace_id|request_id|message|msg)$\") | not)) else . end)' \"$1\"",
             "  else",
             "    cat \"$1\"",
             "  fi",
             "}", ""]
    for step in chain.exploit_chain:
      body = f'${{WORKDIR}}/step_{step.step_index}_body.txt'
      code = f'${{WORKDIR}}/step_{step.step_index}_code.txt'
      role_var = "VICTIM_TOKEN" if step.executor_role == "VICTIM" else "ATTACKER_TOKEN"
      url = self._shell_url(step.endpoint.url_path)
      payload = self._shell_payload(step.payload_template)
      lines.extend([
        f"# Step {step.step_index}: {step.step_intent}",
        f"http_code=\"$(curl -sS -o \"{body}\" -w '%{{http_code}}' -X {step.endpoint.http_method.upper()} \\",
        f"  -H \"Authorization: Bearer ${{{role_var}}}\" \\",
      ])
      if payload is not None:
        lines.extend([
          "  -H 'Content-Type: application/json' \\",
          f"  --data-raw {payload} \\",
        ])
      lines.extend([f"  \"${{BASE_URL}}{url}\")\"", f"printf '%s' \"${{http_code}}\" > \"{code}\"", ""])
      if step.step_index == 1:
        lines.append(f"cp \"{body}\" \"${{WORKDIR}}/precondition_body.json\"")
        lines.append(
          'if [[ "${http_code}" != 2* ]]; then echo "precondition failed: ${http_code}" >&2; exit 1; fi'
        )
      elif step.step_index == 2:
        lines.append(f"stable \"{body}\" > \"${{WORKDIR}}/pre.txt\"")
      elif step.step_index == 3:
        lines.append(f"cp \"{body}\" \"${{WORKDIR}}/attack_body.json\"")
        lines.append(f"cat \"{body}\" | tee \"${{WORKDIR}}/attack.txt\"")
      elif step.step_index == 4:
        lines.extend([
          f"stable \"{body}\" > \"${{WORKDIR}}/post.txt\"",
          "echo", 'echo "==========Diff Result===================="',
          'diff -u "${WORKDIR}/pre.txt" "${WORKDIR}/post.txt" || true',
        ])
      for rule in step.data_extraction_rules:
        variable = re.sub(r"[^A-Za-z0-9_]", "_", rule.extract_to_variable)
        expression = rule.param_source.removeprefix("json_body.")
        jq_path = "." + ".".join(
          f"[{int(part)}]" if part.isdigit() else part
          for part in expression.split(".")
        )
        lines.append(
          f"{variable}=\"$(jq -r '{jq_path} // empty' \"{body}\")\""
        )
      lines.append("")
    lines.extend([
      'echo "==========Attack Result===================="',
      'cat "${WORKDIR}/attack.txt"',
      'echo "artifacts dir: ${WORKDIR}"',
      'echo "pre snapshot: ${WORKDIR}/pre.txt"',
      'echo "post snapshot: ${WORKDIR}/post.txt"',
    ])
    path.write_text("\n".join(lines), encoding="utf-8")
    path.chmod(0o750)
    return path

  @staticmethod
  def _shell_url(path: str) -> str:
    """Render plan variables as shell expansions in a quoted URL."""
    return path.replace('"', '\\"')

  @staticmethod
  def _shell_payload(payload: dict[str, Any] | None) -> str | None:
    if payload is None:
      return None
    raw = json.dumps(payload, ensure_ascii=False)
    return '"' + raw.replace('\\', '\\\\').replace('"', '\\"') + '"'

  def _write_report(self, directory: Path, chain: ExploitChain,
                    result: dict[str, Any]) -> Path:
    name = re.sub(r"[^A-Za-z0-9_.-]+", "_", chain.chain_id)
    path = directory / f"poc_{name}.typ"
    script = f"./poc_{name}.sh"
    attack = json.dumps(result.get("attack_response"), ensure_ascii=False, indent=2)
    diff = result.get("diff") or "No stable-field difference observed."
    text = f"""#set page(margin: 1in)
#set text(size: 10pt)

= Broken Access Control - {chain.chain_id}

- *Name of software:* {self._environment.software_name}
- *Project Link:* {self._environment.project_link or "Not provided"}
- *Affected Version:* {self._environment.affected_version}
- *Vulnerability Type:* {chain.target_vuln_reference.vulnerability_type}

== 1 Vulnerability Code Analysis

The planned chain targets `{chain.target_vuln_reference.http_method} {chain.target_vuln_reference.url_path}`.
The runtime verifier followed the supplied four-step plan and did not substitute a different endpoint.

== 2 Proof of Concept

The paired script is `{script}` and its artifacts are stored under `{directory}`.

=== Attacker response

```json
{attack}
```

=== Stable snapshot diff

```diff
{diff}
```

== 3 Conclusion

*Verdict:* {result.get("verdict", "ERROR")}

{result.get("explanation", "No explanation available.")}
"""
    path.write_text(text, encoding="utf-8")
    return path


def _json_path(value: Any, expression: str) -> Any:
  expression = expression.removeprefix("json_body.")
  current = value
  for part in expression.split("."):
    if part.startswith("[") and part.endswith("]"):
      current = current[int(part[1:-1])]
    elif isinstance(current, dict) and part in current:
      current = current[part]
    else:
      raise ToolException(f"Could not extract JSON path: {expression}")
  return current


def _canonical_path(value: str) -> str:
  """Compare artifact paths while ignoring runtime template values."""
  value = VARIABLE_PATTERN.sub("{runtime}", value)
  value = re.sub(r"\{[^/{}]+\}", "{runtime}", value)
  return value.rstrip("/") or "/"


def _stable(value: Any) -> str:
  if isinstance(value, dict):
    return json.dumps({key: value[key] for key in sorted(value)
                       if key.lower() not in NOISE_KEYS},
                      ensure_ascii=False, indent=2, sort_keys=True)
  if isinstance(value, list):
    return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True)
  return str(value)
