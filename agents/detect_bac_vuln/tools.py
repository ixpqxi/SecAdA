"""Project-scoped tools for the detect-bac-vuln agent."""

from __future__ import annotations

import fnmatch
import json
import os
import re
import subprocess
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path, PurePosixPath
from tempfile import NamedTemporaryFile
from typing import Any

from langchain_core.tools import BaseTool, StructuredTool, ToolException
from pydantic import ValidationError

from agents.boundary_analysis.schemas import EndpointInventory

from .schemas import VulnerableTargetsMap
from .skill import read_skill_file

EXCLUDED_DIRECTORIES = {
  ".git",
  ".idea",
  ".next",
  ".pytest_cache",
  ".tox",
  ".venv",
  "__pycache__",
  "build",
  "coverage",
  "dist",
  "node_modules",
  "target",
  "vendor",
  "vuln_scan",
}
SENSITIVE_FILENAMES = {".env", ".env.local", ".env.production"}
SENSITIVE_SUFFIXES = {".key", ".p12", ".pem"}
KNOWLEDGE_PATHS = {
  "generic_access_control_philosophy": (
    "resources/intended_inference/generic_access_control_philosophy.md"
  ),
  "bfla_rbac": "resources/intended_inference/model_bfla_rbac.md",
  "bola_ownership": "resources/intended_inference/model_bola_ownership.md",
  "generic_policies": "resources/actual_extraction/auth_generic_policies.md",
  "laravel_policies": "resources/actual_extraction/auth_laravel_policies.md",
}
MAX_READ_LINES = 800
MAX_TOOL_OUTPUT_CHARS = 60_000


def _is_sensitive(path: Path) -> bool:
  return path.name in SENSITIVE_FILENAMES or path.suffix.lower() in (
    SENSITIVE_SUFFIXES
  )


def _matches(relative_path: str, pattern: str) -> bool:
  if pattern in {"", "*", "**", "**/*"}:
    return True
  path = PurePosixPath(relative_path)
  return path.match(pattern) or fnmatch.fnmatch(relative_path, pattern)


@dataclass
class DetectBacToolkit:
  """Create stateful tools bound to one source project and one inventory."""

  project_root: Path
  inventory_path: str | Path | None = None
  output_directory: str | Path | None = None
  written_paths: list[Path] = field(default_factory=list)
  _resolved_inventory_path: Path = field(init=False, repr=False)
  _tools: list[BaseTool] = field(init=False, repr=False)

  def __post_init__(self) -> None:
    self.project_root = self.project_root.expanduser().resolve()
    if not self.project_root.is_dir():
      raise ValueError(f"Project root is not a directory: {self.project_root}")
    uses_default_output = self.output_directory is None
    self.output_directory = (
      (self.project_root / "vuln_scan")
      if self.output_directory is None
      else Path(self.output_directory).expanduser().resolve()
    )
    self._uses_default_output_directory = uses_default_output
    self._resolved_inventory_path = self._find_inventory(self.inventory_path)
    self._tools = self._build_tools()

  @property
  def tools(self) -> list[BaseTool]:
    return list(self._tools)

  @property
  def selected_inventory_path(self) -> Path:
    return self._resolved_inventory_path

  def _find_inventory(self, requested: str | Path | None) -> Path:
    inventory_directory = Path(self.output_directory)
    if requested is None:
      candidates = sorted(
        inventory_directory.glob("Endpoint_Inventory_*.json"),
        key=lambda path: (path.stat().st_mtime_ns, path.name),
      ) if inventory_directory.is_dir() else []
      if not candidates:
        raise ValueError(
          "No Endpoint_Inventory_*.json found in the target project's vuln_scan"
        )
      candidate = candidates[-1]
    else:
      candidate = (self.project_root / requested).resolve()
    try:
      relative = candidate.relative_to(inventory_directory.resolve())
    except ValueError as exc:
      message = (
        "Endpoint inventory must be inside vuln_scan"
        if self._uses_default_output_directory
        else "Endpoint inventory must be inside the configured output directory"
      )
      raise ValueError(message) from exc
    if (
      not candidate.is_file()
      or candidate.is_symlink()
      or len(relative.parts) != 1
      or not candidate.name.startswith("Endpoint_Inventory_")
      or candidate.suffix != ".json"
    ):
      message = (
        "Inventory must be a regular vuln_scan/Endpoint_Inventory_*.json file"
        if self._uses_default_output_directory
        else "Inventory must be a regular Endpoint_Inventory_*.json file in "
        "the configured output directory"
      )
      raise ValueError(message)
    return candidate

  def _resolve_source_path(self, relative_path: str) -> Path:
    candidate = (self.project_root / relative_path).resolve()
    try:
      relative = candidate.relative_to(self.project_root)
    except ValueError as exc:
      raise ToolException("Path must stay inside the target project") from exc
    if any(part in EXCLUDED_DIRECTORIES for part in relative.parts):
      raise ToolException("Path points into an excluded directory")
    if _is_sensitive(candidate):
      raise ToolException("Reading secret or key files is not allowed")
    return candidate

  def _iter_project_files(self):
    for current_root, directory_names, file_names in os.walk(
      self.project_root,
      followlinks=False,
    ):
      directory_names[:] = sorted(
        name
        for name in directory_names
        if name not in EXCLUDED_DIRECTORIES
        and not (Path(current_root) / name).is_symlink()
      )
      for file_name in sorted(file_names):
        path = Path(current_root) / file_name
        if path.is_symlink() or _is_sensitive(path):
          continue
        yield path

  def _build_tools(self) -> list[BaseTool]:
    def load_endpoint_inventory(
      offset: int = 0,
      limit: int = 100,
    ) -> str:
      """Read a validated page of the selected Endpoint_Inventory JSON.

      Call with increasing offsets until the returned offset plus page length
      reaches total. The response includes the selected input path and total.
      """
      if offset < 0:
        raise ToolException("offset cannot be negative")
      page_size = min(max(limit, 1), 100)
      try:
        inventory = EndpointInventory.model_validate_json(
          self._resolved_inventory_path.read_text(encoding="utf-8")
        )
      except (OSError, ValueError, ValidationError) as exc:
        raise ToolException(f"Endpoint inventory could not be validated: {exc}") from exc
      items = inventory.api_inventory[offset : offset + page_size]
      return json.dumps(
        {
          "inventory_path": str(self._resolved_inventory_path),
          "total": len(inventory.api_inventory),
          "offset": offset,
          "items": [item.model_dump(by_alias=True, exclude_none=True) for item in items],
        },
        ensure_ascii=False,
      )

    def list_project_files(
      pattern: str = "**/*",
      max_results: int = 500,
    ) -> str:
      """List source files matching a glob, excluding generated/dependency files."""
      limit = min(max(max_results, 1), 2_000)
      matches: list[str] = []
      for path in self._iter_project_files():
        relative = path.relative_to(self.project_root).as_posix()
        if _matches(relative, pattern):
          matches.append(relative)
          if len(matches) > limit:
            break
      if not matches:
        return "No matching files."
      content = "\n".join(matches[:limit])
      if len(matches) > limit:
        content += "\n[results truncated; use a narrower glob]"
      return content

    def read_source_file(
      path: str,
      start_line: int = 1,
      end_line: int = 400,
    ) -> str:
      """Read a numbered source range for authorization evidence."""
      source_path = self._resolve_source_path(path)
      if not source_path.is_file():
        raise ToolException(f"Source file does not exist: {path}")
      if start_line < 1 or end_line < start_line:
        raise ToolException("Line range must satisfy 1 <= start_line <= end_line")
      if end_line - start_line + 1 > MAX_READ_LINES:
        raise ToolException(f"A read is limited to {MAX_READ_LINES} lines")
      raw = source_path.read_bytes()
      if b"\x00" in raw[:8_192]:
        raise ToolException("Binary files cannot be read")
      lines = raw.decode("utf-8", errors="replace").splitlines()
      selected = lines[start_line - 1 : end_line]
      if not selected:
        return f"{path}: no lines in requested range (file has {len(lines)} lines)"
      return "\n".join(
        f"{number:>6}: {line}"
        for number, line in enumerate(selected, start=start_line)
      )

    def search_code(
      query: str,
      file_glob: str = "**/*",
      is_regex: bool = False,
      max_results: int = 200,
    ) -> str:
      """Search source code for route, identity, policy, and query evidence."""
      if not query:
        raise ToolException("Search query cannot be empty")
      if len(query) > 1_000:
        raise ToolException("Search query is too long")
      limit = min(max(max_results, 1), 1_000)
      return self._search_with_rg(query, file_glob, is_regex, limit)

    def load_security_knowledge(resource_name: str) -> str:
      """Load one packaged BAC inference or authorization-extraction guide."""
      relative_path = KNOWLEDGE_PATHS.get(resource_name.lower())
      if relative_path is None:
        valid = ", ".join(sorted(KNOWLEDGE_PATHS))
        raise ToolException(f"Unknown knowledge resource. Valid names: {valid}")
      return read_skill_file(relative_path)

    def write_vulnerable_targets(findings: list[dict[str, Any]]) -> str:
      """Validate and atomically write the final Vulnerable Targets Map array."""
      if self.written_paths:
        raise ToolException(
          "The vulnerability map was already finalized at "
          f"{self.written_paths[-1]}"
        )
      try:
        validated = VulnerableTargetsMap.model_validate(findings)
      except ValidationError as exc:
        raise ToolException(f"Vulnerable targets validation failed:\n{exc}") from exc
      output_directory = Path(self.output_directory)
      output_directory.mkdir(parents=True, exist_ok=True)
      timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
      output_path = output_directory / f"Vulnerable_Targets_Map_{timestamp}.json"
      payload = validated.model_dump_json(indent=2)
      with NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        dir=output_directory,
        prefix=".vulnerable_targets_",
        suffix=".tmp",
        delete=False,
      ) as temporary_file:
        temporary_file.write(payload)
        temporary_file.write("\n")
        temporary_path = Path(temporary_file.name)
      temporary_path.replace(output_path)
      self.written_paths.append(output_path)
      return json.dumps(
        {
          "status": "written",
          "finding_count": len(validated.root),
          "path": str(output_path),
        },
        ensure_ascii=False,
      )

    return [
      StructuredTool.from_function(load_endpoint_inventory, handle_tool_error=True),
      StructuredTool.from_function(list_project_files, handle_tool_error=True),
      StructuredTool.from_function(read_source_file, handle_tool_error=True),
      StructuredTool.from_function(search_code, handle_tool_error=True),
      StructuredTool.from_function(load_security_knowledge, handle_tool_error=True),
      StructuredTool.from_function(write_vulnerable_targets, handle_tool_error=True),
    ]

  def _search_with_rg(
    self,
    query: str,
    file_glob: str,
    is_regex: bool,
    limit: int,
  ) -> str:
    command = [
      "rg", "--line-number", "--no-heading", "--color=never", "--hidden"
    ]
    if not is_regex:
      command.append("--fixed-strings")
    if file_glob not in {"", "*", "**", "**/*"}:
      command.extend(["--glob", file_glob])
    for directory in sorted(EXCLUDED_DIRECTORIES):
      command.extend(["--glob", f"!{directory}/**"])
    for file_name in sorted(SENSITIVE_FILENAMES):
      command.extend(["--glob", f"!{file_name}"])
    for suffix in sorted(SENSITIVE_SUFFIXES):
      command.extend(["--glob", f"!*{suffix}"])
    command.extend(["--", query, "."])
    try:
      completed = subprocess.run(
        command,
        cwd=self.project_root,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
      )
    except FileNotFoundError:
      return self._search_with_python(query, file_glob, is_regex, limit)
    except subprocess.TimeoutExpired:
      return "Search timed out; use a narrower file_glob or query."
    if completed.returncode == 1:
      return "No matches."
    if completed.returncode not in {0, 1}:
      return f"Search failed: {(completed.stderr.strip() or 'unknown error')[:2_000]}"
    return self._limit_search_output(completed.stdout.splitlines(), limit)

  def _search_with_python(
    self,
    query: str,
    file_glob: str,
    is_regex: bool,
    limit: int,
  ) -> str:
    try:
      expression = re.compile(query if is_regex else re.escape(query))
    except re.error as exc:
      return f"Invalid regular expression: {exc}"
    matches: list[str] = []
    for path in self._iter_project_files():
      relative = path.relative_to(self.project_root).as_posix()
      if not _matches(relative, file_glob):
        continue
      try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
      except OSError:
        continue
      for line_number, line in enumerate(lines, start=1):
        if expression.search(line):
          matches.append(f"{relative}:{line_number}:{line}")
          if len(matches) >= limit:
            return self._limit_search_output(matches, limit, truncated=True)
    return self._limit_search_output(matches, limit)

  @staticmethod
  def _limit_search_output(
    lines: list[str],
    limit: int,
    truncated: bool = False,
  ) -> str:
    content = "\n".join(lines[:limit])
    if len(content) > MAX_TOOL_OUTPUT_CHARS:
      content = content[:MAX_TOOL_OUTPUT_CHARS]
      truncated = True
    if len(lines) > limit:
      truncated = True
    if not content:
      return "No matches."
    if truncated:
      content += "\n[results truncated; use a narrower query or file_glob]"
    return content
