"""Project-scoped tools for structural vulnerability discovery."""

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

from .schemas import SecurityAuditReport, VulnerabilityFinding


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
class VulnerabilityDiscoveryToolkit:
  """Create stateful read-only audit tools and one final report writer."""

  project_root: Path
  output_directory: str | Path | None = None
  written_paths: list[Path] = field(default_factory=list)
  _tools: list[BaseTool] = field(init=False, repr=False)

  def __post_init__(self) -> None:
    self.project_root = self.project_root.expanduser().resolve()
    if not self.project_root.is_dir():
      raise ValueError(f"Project root is not a directory: {self.project_root}")
    self.output_directory = (
      self.project_root / "vuln_scan"
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
      """List target-project files matching a glob.

      Dependencies, generated output, symlinks, secrets, and key files are
      excluded. Narrow the glob when the response reports truncation.
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
      content = "\n".join(matches[:limit])
      if len(matches) > limit:
        content += "\n[results truncated; use a narrower glob]"
      return content

    def read_source_file(
      path: str,
      start_line: int = 1,
      end_line: int = 400,
    ) -> str:
      """Read a line-numbered source range, limited to 800 lines per call."""
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
      """Search source text and return bounded file:line hits."""
      if not query:
        raise ToolException("Search query cannot be empty")
      if len(query) > 1_000:
        raise ToolException("Search query is too long")
      limit = min(max(max_results, 1), 1_000)
      return self._search_with_rg(query, file_glob, is_regex, limit)

    def write_security_audit_report(
      scope_summary: str,
      coverage: list[str],
      findings: list[VulnerabilityFinding],
      incomplete_flows: list[str],
      conclusion: str,
    ) -> str:
      """Validate and atomically write the final Markdown security report.

      Call exactly once after completing attack-surface discovery and taint
      analysis. Findings require source-to-sink evidence; unresolved paths
      belong in incomplete_flows instead.
      """
      if self.written_paths:
        raise ToolException(
          f"The security report was already finalized at {self.written_paths[-1]}"
        )
      try:
        report = SecurityAuditReport(
          scope_summary=scope_summary,
          coverage=coverage,
          findings=findings,
          incomplete_flows=incomplete_flows,
          conclusion=conclusion,
        )
      except ValidationError as exc:
        raise ToolException(f"Security report validation failed:\n{exc}") from exc

      output_directory = Path(self.output_directory)
      output_directory.mkdir(parents=True, exist_ok=True)
      timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
      output_path = output_directory / f"Security_Audit_Report_{timestamp}.md"
      with NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        dir=output_directory,
        prefix=".security_audit_",
        suffix=".tmp",
        delete=False,
      ) as temporary_file:
        temporary_file.write(self._render_report(report))
        temporary_file.write("\n")
        temporary_path = Path(temporary_file.name)
      temporary_path.replace(output_path)
      self.written_paths.append(output_path)
      return json.dumps(
        {
          "status": "written",
          "finding_count": len(report.findings),
          "incomplete_flow_count": len(report.incomplete_flows),
          "path": str(output_path),
        },
        ensure_ascii=False,
      )

    return [
      StructuredTool.from_function(list_project_files, handle_tool_error=True),
      StructuredTool.from_function(read_source_file, handle_tool_error=True),
      StructuredTool.from_function(search_code, handle_tool_error=True),
      StructuredTool.from_function(
        write_security_audit_report,
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

  def _render_report(self, report: SecurityAuditReport) -> str:
    lines = [
      "# 代码安全审计报告 (Security Audit Report)",
      "",
      f"**目标项目**：`{self.project_root}`",
      f"**漏洞数量**：{len(report.findings)}",
      "",
      "## 审计范围与覆盖情况",
      "",
      report.scope_summary,
      "",
    ]
    lines.extend(f"- {item}" for item in report.coverage)
    for index, finding in enumerate(report.findings, start=1):
      locations = ", ".join(
        self._format_location(location)
        for location in finding.affected_locations
      )
      lines.extend([
        "",
        "---",
        "",
        f"## 漏洞 {index}：{finding.title}",
        "",
        "### 1. 漏洞概要 (Vulnerability Summary)",
        "",
        f"- **漏洞类型**：{finding.vulnerability_type}",
        f"- **风险等级**：{finding.severity}",
        f"- **置信度**：{finding.confidence}",
        f"- **受影响位置**：{locations}",
        f"- **漏洞说明**：{finding.summary}",
        f"- **业务影响**：{finding.business_impact}",
        "",
        "### 2. 污点数据流分析 (Attack Path)",
        "",
      ])
      for step_index, step in enumerate(finding.attack_path, start=1):
        lines.append(
          f"{step_index}. **[{step.stage}]** "
          f"{self._format_location(step.location)}：{step.description}"
        )
      lines.extend([
        "",
        "### 3. PoC 概念构造 (Concept Payload)",
        "",
        "~~~text",
        finding.concept_payload,
        "~~~",
        "",
        "### 4. 修复建议 (Remediation)",
        "",
        finding.remediation,
        "",
        "**存在漏洞的代码 (Vulnerable Code)：**",
        f"~~~{finding.code_language}",
        finding.vulnerable_code,
        "~~~",
        "",
        "**修复后的代码 (Fixed Code)：**",
        f"~~~{finding.code_language}",
        finding.fixed_code,
        "~~~",
      ])
    lines.extend([
      "",
      "---",
      "",
      "## 未闭合数据流 (Incomplete Flows)",
      "",
    ])
    lines.extend(
      (f"- {item}" for item in report.incomplete_flows),
    )
    if not report.incomplete_flows:
      lines.append("- 无")
    lines.extend([
      "",
      "## 审计结论与下一步建议 (Conclusion & Next Steps)",
      "",
      report.conclusion,
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
