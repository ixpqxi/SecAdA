"""LangGraph supervisor for the three-stage static BAC pipeline.

The stage agents remain responsible for their own analysis. This module owns
only orchestration: explicit artifact hand-off, stage gates, and the final
static-analysis summary.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, TypedDict

from langchain_core.language_models import BaseChatModel
from langgraph.graph import END, START, StateGraph

from agents.boundary_analysis import create_boundary_analysis_agent
from agents.boundary_analysis.schemas import EndpointInventory
from agents.detect_bac_vuln import create_detect_bac_vulnerability_agent
from agents.detect_bac_vuln.schemas import VulnerableTargetsMap
from agents.generate_exploit_chain import create_generate_exploit_chain_agent
from agents.generate_exploit_chain.schemas import ExploitChainsPlan

DEFAULT_OUTPUT_ROOT = Path(__file__).resolve().parents[2] / "output"


class PipelineState(TypedDict, total=False):
  """Serializable state passed between LangGraph pipeline nodes."""

  target_codebase: str
  scope_hints: str | None
  output_directory: str
  inventory_path: str | None
  vulnerable_targets_path: str | None
  exploit_chains_path: str | None
  stage_status: dict[str, str]
  endpoint_count: int
  finding_count: int
  mbac_count: int
  chain_count: int
  summary: dict[str, Any]


@dataclass(frozen=True)
class BacStaticPipelineResult:
  """Result returned after the graph reaches its summary or termination gate."""

  state: PipelineState

  @property
  def inventory_path(self) -> Path | None:
    return _optional_path(self.state.get("inventory_path"))

  @property
  def vulnerable_targets_path(self) -> Path | None:
    return _optional_path(self.state.get("vulnerable_targets_path"))

  @property
  def exploit_chains_path(self) -> Path | None:
    return _optional_path(self.state.get("exploit_chains_path"))

  @property
  def output_directory(self) -> Path:
    return Path(self.state["output_directory"])


AgentFactory = Callable[..., Any]


class BacStaticPipeline:
  """Build and run the boundary -> detection -> exploit-chain graph."""

  def __init__(
    self,
    project_root: str | Path,
    model: BaseChatModel | None = None,
    *,
    output_root: str | Path | None = None,
    recursion_limit: int = 100,
    completion_retries: int = 1,
    boundary_agent_factory: AgentFactory = create_boundary_analysis_agent,
    detect_agent_factory: AgentFactory = create_detect_bac_vulnerability_agent,
    chain_agent_factory: AgentFactory = create_generate_exploit_chain_agent,
  ) -> None:
    if recursion_limit < 1:
      raise ValueError("recursion_limit must be positive")
    if completion_retries < 0:
      raise ValueError("completion_retries cannot be negative")
    self.project_root = Path(project_root).expanduser().resolve()
    if not self.project_root.is_dir():
      raise ValueError(f"Project root is not a directory: {self.project_root}")
    self.output_root = Path(output_root or DEFAULT_OUTPUT_ROOT).expanduser().resolve()
    self.model = model
    self.recursion_limit = recursion_limit
    self.completion_retries = completion_retries
    self.boundary_agent_factory = boundary_agent_factory
    self.detect_agent_factory = detect_agent_factory
    self.chain_agent_factory = chain_agent_factory
    self.graph = self._build_graph()

  def invoke(
    self,
    *,
    scope_hints: str | None = None,
    target_codebase: str | Path | None = None,
  ) -> BacStaticPipelineResult:
    """Run the graph and return its explicit artifact paths and summary."""
    codebase = Path(target_codebase or self.project_root).expanduser().resolve()
    if not codebase.is_dir():
      raise ValueError(f"Target codebase is not a directory: {codebase}")
    output_directory = self.output_root / codebase.name
    output_directory.mkdir(parents=True, exist_ok=True)
    state: PipelineState = {
      "target_codebase": str(codebase),
      "scope_hints": scope_hints,
      "output_directory": str(output_directory),
      "stage_status": {},
    }
    result = self.graph.invoke(
      state,
      config={"recursion_limit": self.recursion_limit},
    )
    return BacStaticPipelineResult(state=result)

  def _build_graph(self):
    workflow = StateGraph(PipelineState)
    workflow.add_node("boundary_analysis", self._run_boundary_analysis)
    workflow.add_node("check_endpoint_inventory", self._check_endpoint_inventory)
    workflow.add_node("detect_bac_vuln", self._run_detect_bac_vuln)
    workflow.add_node("check_vulnerable_targets", self._check_vulnerable_targets)
    workflow.add_node("generate_exploit_chain", self._run_generate_exploit_chain)
    workflow.add_node("summary", self._build_summary)

    workflow.add_edge(START, "boundary_analysis")
    workflow.add_edge("boundary_analysis", "check_endpoint_inventory")
    workflow.add_conditional_edges(
      "check_endpoint_inventory",
      self._route_after_inventory,
      {"continue": "detect_bac_vuln", "stop": "summary"},
    )
    workflow.add_edge("detect_bac_vuln", "check_vulnerable_targets")
    workflow.add_conditional_edges(
      "check_vulnerable_targets",
      self._route_after_targets,
      {"generate": "generate_exploit_chain", "stop": "summary"},
    )
    workflow.add_edge("generate_exploit_chain", "summary")
    workflow.add_edge("summary", END)
    return workflow.compile()

  def _run_boundary_analysis(self, state: PipelineState) -> dict[str, Any]:
    instruction = None
    if state.get("scope_hints"):
      instruction = (
        "完成默认的 boundary-analysis 任务，并将以下范围提示作为分析重点，"
        f"但不要跳过范围之外的必要边界：{state['scope_hints']}"
      )
    agent = self.boundary_agent_factory(
      state["target_codebase"],
      model=self.model,
      output_directory=state["output_directory"],
      recursion_limit=self.recursion_limit,
      completion_retries=self.completion_retries,
    )
    result = agent.invoke(instruction)
    return {
      "inventory_path": str(result.output_path),
      "stage_status": _status_update(state, "boundary_analysis", "completed"),
    }

  def _check_endpoint_inventory(self, state: PipelineState) -> dict[str, Any]:
    path = _required_path(state, "inventory_path")
    try:
      inventory = EndpointInventory.model_validate_json(
        path.read_text(encoding="utf-8")
      )
    except (OSError, ValueError) as exc:
      raise RuntimeError(f"Endpoint inventory could not be validated: {path}") from exc
    count = len(inventory.api_inventory)
    status = "completed" if count else "stopped_no_endpoints"
    return {
      "endpoint_count": count,
      "stage_status": _status_update(state, "endpoint_gate", status),
    }

  def _route_after_inventory(self, state: PipelineState) -> str:
    return "continue" if state.get("endpoint_count", 0) > 0 else "stop"

  def _run_detect_bac_vuln(self, state: PipelineState) -> dict[str, Any]:
    inventory_path = _required_path(state, "inventory_path")
    agent = self.detect_agent_factory(
      state["target_codebase"],
      model=self.model,
      inventory_path=inventory_path,
      output_directory=state["output_directory"],
      recursion_limit=self.recursion_limit,
      completion_retries=self.completion_retries,
    )
    result = agent.invoke()
    return {
      "vulnerable_targets_path": str(result.output_path),
      "stage_status": _status_update(state, "detect_bac_vuln", "completed"),
    }

  def _check_vulnerable_targets(self, state: PipelineState) -> dict[str, Any]:
    path = _required_path(state, "vulnerable_targets_path")
    try:
      targets = VulnerableTargetsMap.model_validate_json(
        path.read_text(encoding="utf-8")
      )
    except (OSError, ValueError) as exc:
      raise RuntimeError(
        f"Vulnerable targets map could not be validated: {path}"
      ) from exc
    mbac_count = sum(item.vulnerability_type.startswith("MBAC_") for item in targets.root)
    status = (
      "completed" if targets.root and mbac_count else
      "stopped_no_vulnerabilities" if not targets.root else
      "stopped_read_only_findings"
    )
    return {
      "finding_count": len(targets.root),
      "mbac_count": mbac_count,
      "stage_status": _status_update(state, "target_gate", status),
    }

  def _route_after_targets(self, state: PipelineState) -> str:
    return "generate" if state.get("mbac_count", 0) > 0 else "stop"

  def _run_generate_exploit_chain(self, state: PipelineState) -> dict[str, Any]:
    targets_path = _required_path(state, "vulnerable_targets_path")
    inventory_path = _required_path(state, "inventory_path")
    agent = self.chain_agent_factory(
      state["target_codebase"],
      model=self.model,
      vulnerable_targets_path=targets_path,
      inventory_path=inventory_path,
      output_directory=state["output_directory"],
      recursion_limit=self.recursion_limit,
      completion_retries=self.completion_retries,
    )
    result = agent.invoke()
    try:
      plan = ExploitChainsPlan.model_validate_json(
        Path(result.output_path).read_text(encoding="utf-8")
      )
    except (OSError, ValueError) as exc:
      raise RuntimeError(
        f"Exploit chains plan could not be validated: {result.output_path}"
      ) from exc
    return {
      "exploit_chains_path": str(result.output_path),
      "chain_count": len(plan.root),
      "stage_status": _status_update(state, "generate_exploit_chain", "completed"),
    }

  def _build_summary(self, state: PipelineState) -> dict[str, Any]:
    statuses = dict(state.get("stage_status", {}))
    if state.get("endpoint_count", 0) == 0:
      conclusion = "未发现可审计接口边界"
    elif state.get("finding_count", 0) == 0:
      conclusion = "未发现可确认的 BAC 风险目标"
    elif state.get("mbac_count", 0) == 0:
      conclusion = "发现只读型 BAC 候选，未进入攻击链生成"
    elif state.get("chain_count") == 0 and state.get("exploit_chains_path"):
      conclusion = "存在风险候选，但缺少可执行链路"
    else:
      conclusion = "发现可生成静态攻击链的 BAC 高风险候选"
    summary = {
      "conclusion": conclusion,
      "output_directory": state["output_directory"],
      "endpoint_count": state.get("endpoint_count", 0),
      "finding_count": state.get("finding_count", 0),
      "mbac_count": state.get("mbac_count", 0),
      "chain_count": state.get("chain_count", 0),
      "artifacts": {
        key: state[key]
        for key in (
          "inventory_path",
          "vulnerable_targets_path",
          "exploit_chains_path",
        )
        if state.get(key)
      },
      "stage_status": statuses,
    }
    return {"summary": summary, "stage_status": statuses}


def create_bac_static_pipeline(
  project_root: str | Path,
  model: BaseChatModel | None = None,
  *,
  output_root: str | Path | None = None,
  recursion_limit: int = 100,
  completion_retries: int = 1,
) -> BacStaticPipeline:
  """Create the LangGraph static BAC pipeline."""
  return BacStaticPipeline(
    project_root,
    model=model,
    output_root=output_root,
    recursion_limit=recursion_limit,
    completion_retries=completion_retries,
  )


def _required_path(state: PipelineState, key: str) -> Path:
  value = state.get(key)
  if not value:
    raise RuntimeError(f"Pipeline state is missing {key}")
  return Path(value)


def _optional_path(value: str | None) -> Path | None:
  return Path(value) if value else None


def _status_update(
  state: PipelineState,
  stage: str,
  status: str,
) -> dict[str, str]:
  statuses = dict(state.get("stage_status", {}))
  statuses[stage] = status
  return statuses
