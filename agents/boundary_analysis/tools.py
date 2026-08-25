"""Filesystem tools exposed to the boundary-analysis agent."""

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

from .schemas import EndpointInventory
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
GUIDE_PATHS = {
  "java": "resources/parse_java_ecosystem.md",
  "php": "resources/parse_php_ecosystem.md",
  "output_format": "examples/output_format.json",
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
class BoundaryAnalysisToolkit:
  """Create stateful, project-scoped tools for one analysis run."""

  project_root: Path
  output_directory: str | Path | None = None
  written_paths: list[Path] = field(default_factory=list)
  _tools: list[BaseTool] = field(init=False, repr=False)

  def __post_init__(self) -> None:
    self.project_root = self.project_root.expanduser().resolve()
    if not self.project_root.is_dir():
      raise ValueError(f"Project root is not a directory: {self.project_root}")
    self.output_directory = (
      (self.project_root / "vuln_scan")
      if self.output_directory is None
      else Path(self.output_directory).expanduser().resolve()
    )
    self._tools = self._build_tools()

  @property
  def tools(self) -> list[BaseTool]:
    return list(self._tools)

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
    def list_project_files(
      pattern: str = "**/*",
      max_results: int = 500,
    ) -> str:
      """List target-project files matching a glob, excluding dependencies.

      Use patterns such as **/*.java, **/*.php, pom.xml, or package.json.
      Results are relative paths. Paginate by using a narrower pattern if the
      result is truncated.
      """
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
      truncated = len(matches) > limit
      content = "\n".join(matches[:limit])
      if truncated:
        content += "\n[results truncated; use a narrower glob]"
      return content

    def read_source_file(
      path: str,
      start_line: int = 1,
      end_line: int = 400,
    ) -> str:
      """Read a line-numbered range from a target-project source file.

      At most 800 lines can be returned per call. Use additional calls to
      paginate large files.
      """
      source_path = self._resolve_source_path(path)
      if not source_path.is_file():
        raise ToolException(f"Source file does not exist: {path}")
      if start_line < 1 or end_line < start_line:
        raise ToolException(
          "Line range must satisfy 1 <= start_line <= end_line"
        )
      if end_line - start_line + 1 > MAX_READ_LINES:
        raise ToolException(f"A read is limited to {MAX_READ_LINES} lines")
      raw = source_path.read_bytes()
      if b"\x00" in raw[:8_192]:
        raise ToolException("Binary files cannot be read")
      text = raw.decode("utf-8", errors="replace")
      lines = text.splitlines()
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
      """Search source text in the target project and return file:line hits.

      Set is_regex only when a regular expression is needed. Use file_glob to
      focus on a language or file family, for example **/*.java.
      """
      if not query:
        raise ToolException("Search query cannot be empty")
      if len(query) > 1_000:
        raise ToolException("Search query is too long")
      limit = min(max(max_results, 1), 1_000)
      return self._search_with_rg(query, file_glob, is_regex, limit)

    def load_analysis_guide(resource_name: str) -> str:
      """Load a packaged extraction guide or the output example.

      Valid resource names are java, php, and output_format. Select the guide
      only after identifying the target project's technology stack.
      """
      relative_path = GUIDE_PATHS.get(resource_name.lower())
      if relative_path is None:
        valid = ", ".join(sorted(GUIDE_PATHS))
        raise ToolException(f"Unknown guide. Valid names: {valid}")
      return read_skill_file(relative_path)

    def write_endpoint_inventory(inventory: dict[str, Any]) -> str:
      """Validate and atomically write the final endpoint inventory.

      Call this exactly once after the complete project has been analyzed.
      The object must follow the packaged output format and contain the
      api_inventory top-level array.
      """
      if self.written_paths:
        raise ToolException(
          "The inventory was already finalized at "
          f"{self.written_paths[-1]}"
        )
      try:
        validated = EndpointInventory.model_validate(inventory)
      except ValidationError as exc:
        raise ToolException(
          f"Endpoint inventory validation failed:\n{exc}"
        ) from exc

      output_directory = Path(self.output_directory)
      output_directory.mkdir(parents=True, exist_ok=True)
      timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
      output_path = output_directory / f"Endpoint_Inventory_{timestamp}.json"
      payload = validated.model_dump_json(
        by_alias=True,
        exclude_none=True,
        indent=2,
      )
      with NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        dir=output_directory,
        prefix=".endpoint_inventory_",
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
          "endpoint_count": len(validated.api_inventory),
          "path": str(output_path),
        },
        ensure_ascii=False,
      )

    return [
      StructuredTool.from_function(list_project_files, handle_tool_error=True),
      StructuredTool.from_function(read_source_file, handle_tool_error=True),
      StructuredTool.from_function(search_code, handle_tool_error=True),
      StructuredTool.from_function(load_analysis_guide, handle_tool_error=True),
      StructuredTool.from_function(
        write_endpoint_inventory,
        handle_tool_error=True,
      ),
    ]

  def _search_with_rg(
    self,
    query: str,
    file_glob: str,
    is_regex: bool,
    limit: int,
  ) -> str:
    command = [
      "rg",
      "--line-number",
      "--no-heading",
      "--color=never",
      "--hidden",
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
      error = completed.stderr.strip() or "unknown ripgrep error"
      return f"Search failed: {error[:2_000]}"
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
    selected = lines[:limit]
    content = "\n".join(selected)
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
