"""Project-scoped tools for skeptical preliminary-report verification."""

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

from langchain_core.tools import BaseTool, StructuredTool, ToolException
from pydantic import ValidationError

from .schemas import VerificationReport


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
MAX_READ_LINES = 800
MAX_REPORT_BYTES = 20 * 1024 * 1024
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
class VulnerabilityReportVerifierToolkit:
  """Bind one untrusted report and one project to read-only audit tools."""

  project_root: Path
  preliminary_report_path: str | Path
  output_directory: str | Path | None = None
  written_paths: list[Path] = field(default_factory=list)
  _report_path: Path = field(init=False, repr=False)
  _tools: list[BaseTool] = field(init=False, repr=False)

  def __post_init__(self) -> None:
    self.project_root = Path(self.project_root).expanduser().resolve()
    if not self.project_root.is_dir():
      raise ValueError(f"Project root is not a directory: {self.project_root}")
    requested = Path(self.preliminary_report_path).expanduser()
    self._report_path = (
      requested if requested.is_absolute()
      else self.project_root / requested
    ).resolve()
    if (
      not self._report_path.is_file()
      or self._report_path.is_symlink()
      or self._report_path.stat().st_size > MAX_REPORT_BYTES
    ):
      raise ValueError(
        "Preliminary report must be a regular file no larger than 20 MiB"
      )
    self.output_directory = (
      self.project_root / "vuln_scan"
      if self.output_directory is None
      else Path(self.output_directory).expanduser().resolve()
    )
    self._tools = self._build_tools()

  @property
  def tools(self) -> list[BaseTool]:
    return list(self._tools)

  @property
  def selected_report_path(self) -> Path:
    return self._report_path

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
    def load_preliminary_report(offset: int = 0, limit: int = 400) -> str:
      """Read a bounded line page from the untrusted preliminary report."""
      if offset < 0:
        raise ToolException("offset cannot be negative")
      page_size = min(max(limit, 1), 400)
      try:
        lines = self._report_path.read_text(
          encoding="utf-8", errors="replace"
        ).splitlines()
      except OSError as exc:
        raise ToolException(f"Could not read preliminary report: {exc}") from exc
      return json.dumps(
        {
          "report_path": str(self._report_path),
          "total_lines": len(lines),
          "offset": offset,
          "lines": lines[offset : offset + page_size],
        },
        ensure_ascii=False,
      )

    def list_project_files(
      pattern: str = "**/*",
      max_results: int = 500,
    ) -> str:
      """List project files while excluding dependencies, outputs and secrets."""
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
      """Read a numbered source range from the target project."""
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
      """Search source text and return bounded file:line evidence hits."""
      if not query:
        raise ToolException("Search query cannot be empty")
      if len(query) > 1_000:
        raise ToolException("Search query is too long")
      limit = min(max(max_results, 1), 1_000)
      return self._search_with_rg(query, file_glob, is_regex, limit)

    def write_verification_report(report: VerificationReport) -> str:
      """Validate and atomically write one final verification report."""
      if self.written_paths:
        raise ToolException(
          f"The verification report was already finalized at {self.written_paths[-1]}"
        )
      try:
        validated = VerificationReport.model_validate(report)
      except ValidationError as exc:
        raise ToolException(f"Verification report validation failed:\n{exc}") from exc
      output_directory = Path(self.output_directory)
      output_directory.mkdir(parents=True, exist_ok=True)
      timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
      output_path = output_directory / (
        f"Security_Verification_Report_{timestamp}.md"
      )
      with NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        dir=output_directory,
        prefix=".security_verification_",
        suffix=".tmp",
        delete=False,
      ) as temporary_file:
        temporary_file.write(self._render_report(validated))
        temporary_file.write("\n")
        temporary_path = Path(temporary_file.name)
      temporary_path.replace(output_path)
      self.written_paths.append(output_path)
      return json.dumps(
        {
          "status": "written",
          "verdict": validated.verdict,
          "path": str(output_path),
        },
        ensure_ascii=False,
      )

    return [
      StructuredTool.from_function(
        load_preliminary_report,
        handle_tool_error=True,
      ),
      StructuredTool.from_function(list_project_files, handle_tool_error=True),
      StructuredTool.from_function(read_source_file, handle_tool_error=True),
      StructuredTool.from_function(search_code, handle_tool_error=True),
      StructuredTool.from_function(
        write_verification_report,
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
          if len(matches) > limit:
            return self._limit_search_output(matches, limit)
    return self._limit_search_output(matches, limit)

  @staticmethod
  def _limit_search_output(lines: list[str], limit: int) -> str:
    if not lines:
      return "No matches."
    selected = lines[:limit]
    content = "\n".join(selected)
    truncated = len(lines) > limit or len(content) > MAX_TOOL_OUTPUT_CHARS
    if len(content) > MAX_TOOL_OUTPUT_CHARS:
      content = content[:MAX_TOOL_OUTPUT_CHARS]
    if truncated:
      content += "\n[results truncated; narrow the query or file_glob]"
    return content

  def _render_report(self, report: VerificationReport) -> str:
    verdict_labels = {
      "CONFIRMED": "确认漏洞 (Confirmed)",
      "FALSE_POSITIVE": "误报 (False Positive)",
      "NEEDS_MANUAL_REVIEW": "需人工介入 (Needs Manual Review)",
    }
    lines = [
      "# 漏洞复核验证报告 (Vulnerability Verification Report)",
      "",
      f"**目标项目**：`{self.project_root}`",
      f"**初筛报告**：`{self._report_path}`",
      "",
      "## 最终复核结论 (Verification Verdict)",
      "",
      f"**{verdict_labels[report.verdict]}**",
      "",
      report.verdict_rationale,
      "",
      "## 1. 原始报告主张回顾 (Original Claim Summary)",
      "",
      report.original_claim_summary,
      "",
      "## 2. 核心阻断分析与证伪 (Blocker & Refutation Analysis)",
      "",
    ]
    for index, blocker in enumerate(report.blocker_analysis, start=1):
      location = (
        f" ({self._format_location(blocker.location)})"
        if blocker.location else ""
      )
      lines.extend([
        f"### 阻断观察 {index}：{blocker.category}",
        "",
        f"- **状态**：{blocker.status}",
        f"- **证据位置**：{location or '未提供'}",
        f"- **分析**：{blocker.description}",
        "",
      ])
    lines.extend([
      "## 3. 真实的调用栈还原 (Corrected Call Chain)",
      "",
    ])
    for index, step in enumerate(report.corrected_call_chain, start=1):
      location = (
        f" ({self._format_location(step.location)})"
        if step.location else ""
      )
      lines.append(
        f"{index}. **[{step.stage}]** `{step.outcome}`{location}："
        f"{step.description}"
      )
    lines.extend([
      "",
      "## 4. 误报原因诊断 (False-Positive Pattern)",
      "",
      report.false_positive_pattern,
      "",
      "## 5. 残余不确定性 (Residual Uncertainties)",
      "",
    ])
    lines.extend(
      (f"- {item}" for item in report.residual_uncertainties)
    )
    if not report.residual_uncertainties:
      lines.append("- 无")
    lines.extend([
      "",
      "## 6. 最终处理建议 (Final Recommendation)",
      "",
      report.final_recommendation,
    ])
    return "\n".join(lines)

  @staticmethod
  def _format_location(location) -> str:
    line_range = (
      str(location.start_line)
      if location.start_line == location.end_line
      else f"{location.start_line}-{location.end_line}"
    )
    symbol = f" `{location.symbol}`" if location.symbol else ""
    return f"`{location.path}:{line_range}`{symbol}"
