"""LangGraph orchestration for taint discovery followed by report verification."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, TypedDict

from langchain_core.language_models import BaseChatModel
from langgraph.graph import END, START, StateGraph

from agents.vuln_report_verifier import (
  create_vulnerability_report_verifier_agent,
)

from .agent import create_vulnerability_discovery_agent


MAX_AUDIT_REPORT_BYTES = 20 * 1024 * 1024


class TaintAuditPipelineState(TypedDict, total=False):
  """Serializable state passed between taint-audit pipeline nodes."""

  target_codebase: str
  output_directory: str
  audit_instruction: str | None
  verification_instruction: str | None
  audit_report_path: str | None
  verification_report_path: str | None
  audit_report_ready: bool
  audit_report_size: int
  stage_status: dict[str, str]
  summary: dict[str, Any]


@dataclass(frozen=True)
class TaintAuditPipelineResult:
  """Result returned after the discovery and verification graph completes."""

  state: TaintAuditPipelineState

  @property
  def audit_report_path(self) -> Path | None:
    return _optional_path(self.state.get("audit_report_path"))

  @property
  def verification_report_path(self) -> Path | None:
    return _optional_path(self.state.get("verification_report_path"))

  @property
  def output_directory(self) -> Path:
    return Path(self.state["output_directory"])


AgentFactory = Callable[..., Any]


class TaintAuditPipeline:
  """Run vulnerability discovery and pass its report to the verifier."""

  def __init__(
    self,
    project_root: str | Path,
    model: BaseChatModel | None = None,
    *,
    output_directory: str | Path | None = None,
    recursion_limit: int = 200,
    completion_retries: int = 1,
    discovery_agent_factory: AgentFactory = (
      create_vulnerability_discovery_agent
    ),
    verifier_agent_factory: AgentFactory = (
      create_vulnerability_report_verifier_agent
    ),
  ) -> None:
    if recursion_limit < 1:
      raise ValueError("recursion_limit must be positive")
    if completion_retries < 0:
      raise ValueError("completion_retries cannot be negative")
    self.project_root = Path(project_root).expanduser().resolve()
    if not self.project_root.is_dir():
      raise ValueError(f"Project root is not a directory: {self.project_root}")
    self.output_directory = (
      self.project_root / "vuln_scan"
      if output_directory is None
      else Path(output_directory).expanduser().resolve()
    )
    self.model = model
    self.recursion_limit = recursion_limit
    self.completion_retries = completion_retries
    self.discovery_agent_factory = discovery_agent_factory
    self.verifier_agent_factory = verifier_agent_factory
    self.graph = self._build_graph()

  def invoke(
    self,
    *,
    audit_instruction: str | None = None,
    verification_instruction: str | None = None,
  ) -> TaintAuditPipelineResult:
    """Run discovery, validate its report, and verify that report."""
    self.output_directory.mkdir(parents=True, exist_ok=True)
    state: TaintAuditPipelineState = {
      "target_codebase": str(self.project_root),
      "output_directory": str(self.output_directory),
      "audit_instruction": audit_instruction,
      "verification_instruction": verification_instruction,
      "stage_status": {},
    }
    result = self.graph.invoke(
      state,
      config={"recursion_limit": self.recursion_limit},
    )
    return TaintAuditPipelineResult(state=result)

  def _build_graph(self):
    workflow = StateGraph(TaintAuditPipelineState)
    workflow.add_node(
      "vuln_discovery_auditor",
      self._run_discovery,
    )
    workflow.add_node(
      "check_audit_report",
      self._check_audit_report,
    )
    workflow.add_node(
      "vuln_report_verifier",
      self._run_verifier,
    )
    workflow.add_node("summary", self._build_summary)

    workflow.add_edge(START, "vuln_discovery_auditor")
    workflow.add_edge("vuln_discovery_auditor", "check_audit_report")
    workflow.add_conditional_edges(
      "check_audit_report",
      self._route_after_audit,
      {"continue": "vuln_report_verifier", "stop": "summary"},
    )
    workflow.add_edge("vuln_report_verifier", "summary")
    workflow.add_edge("summary", END)
    return workflow.compile()

  def _run_discovery(
    self,
    state: TaintAuditPipelineState,
  ) -> dict[str, Any]:
    agent = self.discovery_agent_factory(
      state["target_codebase"],
      model=self.model,
      output_directory=state["output_directory"],
      recursion_limit=self.recursion_limit,
      completion_retries=self.completion_retries,
    )
    result = agent.invoke(state.get("audit_instruction"))
    return {
      "audit_report_path": str(result.output_path),
      "stage_status": _status_update(
        state,
        "vuln_discovery_auditor",
        "completed",
      ),
    }

  def _check_audit_report(
    self,
    state: TaintAuditPipelineState,
  ) -> dict[str, Any]:
    path = _required_path(state, "audit_report_path")
    try:
      size = path.stat().st_size if path.is_file() else 0
    except OSError as exc:
      raise RuntimeError(
        f"Audit report could not be inspected: {path}"
      ) from exc
    ready = (
      size > 0 and size <= MAX_AUDIT_REPORT_BYTES and not path.is_symlink()
    )
    status = "completed" if ready else "stopped_invalid_audit_report"
    return {
      "audit_report_ready": ready,
      "audit_report_size": size,
      "stage_status": _status_update(state, "audit_report_gate", status),
    }

  def _route_after_audit(self, state: TaintAuditPipelineState) -> str:
    return "continue" if state.get("audit_report_ready") else "stop"

  def _run_verifier(
    self,
    state: TaintAuditPipelineState,
  ) -> dict[str, Any]:
    audit_report_path = _required_path(state, "audit_report_path")
    agent = self.verifier_agent_factory(
      state["target_codebase"],
      audit_report_path,
      model=self.model,
      output_directory=state["output_directory"],
      recursion_limit=self.recursion_limit,
      completion_retries=self.completion_retries,
    )
    result = agent.invoke(state.get("verification_instruction"))
    return {
      "verification_report_path": str(result.output_path),
      "stage_status": _status_update(
        state,
        "vuln_report_verifier",
        "completed",
      ),
    }

  def _build_summary(
    self,
    state: TaintAuditPipelineState,
  ) -> dict[str, Any]:
    if not state.get("audit_report_path"):
      conclusion = "未生成污点审计初筛报告"
    elif not state.get("audit_report_ready"):
      conclusion = "初筛报告缺失、为空或超过复核大小限制，未进入报告复核"
    elif not state.get("verification_report_path"):
      conclusion = "初筛报告已生成，但未生成复核报告"
    else:
      conclusion = "污点发现与报告复核已完成"
    statuses = dict(state.get("stage_status", {}))
    summary = {
      "conclusion": conclusion,
      "output_directory": state["output_directory"],
      "audit_report_size": state.get("audit_report_size", 0),
      "artifacts": {
        key: state[key]
        for key in ("audit_report_path", "verification_report_path")
        if state.get(key)
      },
      "stage_status": statuses,
    }
    return {"summary": summary, "stage_status": statuses}


def create_taint_audit_pipeline(
  project_root: str | Path,
  model: BaseChatModel | None = None,
  *,
  output_directory: str | Path | None = None,
  recursion_limit: int = 200,
  completion_retries: int = 1,
) -> TaintAuditPipeline:
  """Create the LangGraph taint discovery and verification pipeline."""
  return TaintAuditPipeline(
    project_root,
    model=model,
    output_directory=output_directory,
    recursion_limit=recursion_limit,
    completion_retries=completion_retries,
  )


def _required_path(state: TaintAuditPipelineState, key: str) -> Path:
  value = state.get(key)
  if not value:
    raise RuntimeError(f"Pipeline state is missing {key}")
  return Path(value)


def _optional_path(value: str | None) -> Path | None:
  return Path(value) if value else None


def _status_update(
  state: TaintAuditPipelineState,
  stage: str,
  status: str,
) -> dict[str, str]:
  statuses = dict(state.get("stage_status", {}))
  statuses[stage] = status
  return statuses
