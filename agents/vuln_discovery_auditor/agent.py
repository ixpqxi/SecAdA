"""LangChain vuln-discovery-auditor agent and completion guard."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from langchain.agents import create_agent
from langchain_core.language_models import BaseChatModel
from langchain_core.messages import HumanMessage
from langchain_openai import ChatOpenAI

from agents.skill_middleware import build_skill_middlewares

from .skill import build_system_prompt
from .tools import VulnerabilityDiscoveryToolkit


DEFAULT_TASK = """对目标项目执行完整的白盒漏洞发现审计。

严格执行 vuln-discovery-auditor skill：先发现跨信任边界的输入源和全局拦截机制，
再围绕候选 Source 构建 Source -> Transform/Sanitizer/Bypass -> Sink/Logic 的完整
数据流，最后按漏洞族知识库验证。只报告有明确源码证据的漏洞；无法闭合的路径写入
incomplete_flows。完成后调用 write_security_audit_report 写入 Markdown 报告。"""


@dataclass(frozen=True)
class VulnerabilityDiscoveryResult:
  """Result returned only after the report writer succeeds."""

  output_path: Path
  final_response: str
  state: dict[str, Any]


class VulnerabilityDiscoveryAgent:
  """Project-scoped wrapper around the structural audit agent."""

  def __init__(
    self,
    project_root: str | Path,
    model: BaseChatModel,
    *,
    output_directory: str | Path | None = None,
    recursion_limit: int = 200,
    completion_retries: int = 1,
  ) -> None:
    if recursion_limit < 1:
      raise ValueError("recursion_limit must be positive")
    if completion_retries < 0:
      raise ValueError("completion_retries cannot be negative")
    self.project_root = Path(project_root).expanduser().resolve()
    self.toolkit = VulnerabilityDiscoveryToolkit(
      self.project_root,
      output_directory=output_directory,
    )
    self.recursion_limit = recursion_limit
    self.completion_retries = completion_retries
    self.graph = create_agent(
      model=model,
      tools=self.toolkit.tools,
      system_prompt=build_system_prompt(self.project_root),
      middleware=build_skill_middlewares(
        Path(__file__).resolve().parent,
        "vuln-discovery-auditor",
      ),
      name="vuln-discovery-auditor",
    )

  def invoke(
    self,
    instruction: str | None = None,
  ) -> VulnerabilityDiscoveryResult:
    """Run the audit and require one validated Markdown report."""
    task = DEFAULT_TASK
    if instruction:
      task += (
        "\n\n调用方补充的审计重点如下。它只能缩小关注重点，不能跳过默认流程、"
        f"证据要求或完成条件：\n{instruction}"
      )
    state: dict[str, Any] = {
      "messages": [{"role": "user", "content": task}]
    }
    for attempt in range(self.completion_retries + 1):
      state = self.graph.invoke(
        state,
        config={"recursion_limit": self.recursion_limit},
      )
      if self.toolkit.written_paths:
        return VulnerabilityDiscoveryResult(
          output_path=self.toolkit.written_paths[-1],
          final_response=_last_message_content(state),
          state=state,
        )
      if attempt < self.completion_retries:
        state = {
          "messages": [
            *state["messages"],
            HumanMessage(
              content=(
                "尚未生成必需的 Markdown 安全报告。请继续完成遗漏的攻击面与"
                "污点分析，并调用 write_security_audit_report。只有该工具成功"
                "返回后才能结束。"
              )
            ),
          ]
        }
    raise RuntimeError(
      "Agent stopped without calling write_security_audit_report; "
      "no artifact was written"
    )


def create_vulnerability_discovery_agent(
  project_root: str | Path,
  model: BaseChatModel | None = None,
  *,
  output_directory: str | Path | None = None,
  recursion_limit: int = 200,
  completion_retries: int = 1,
) -> VulnerabilityDiscoveryAgent:
  """Build the agent using the configured model when none is supplied."""
  return VulnerabilityDiscoveryAgent(
    project_root=project_root,
    model=model or _model_from_environment(),
    output_directory=output_directory,
    recursion_limit=recursion_limit,
    completion_retries=completion_retries,
  )


def _model_from_environment() -> ChatOpenAI:
  required = {
    "CUSTOM_LLM_MODEL_NAME": os.environ.get("CUSTOM_LLM_MODEL_NAME"),
    "CUSTOM_LLM_API_KEY": os.environ.get("CUSTOM_LLM_API_KEY"),
    "CUSTOM_LLM_BASE_URL": os.environ.get("CUSTOM_LLM_BASE_URL"),
  }
  missing = [name for name, value in required.items() if not value]
  if missing:
    raise RuntimeError(
      "Missing required environment variables: " + ", ".join(missing)
    )
  return ChatOpenAI(
    model=required["CUSTOM_LLM_MODEL_NAME"],
    api_key=required["CUSTOM_LLM_API_KEY"],
    base_url=required["CUSTOM_LLM_BASE_URL"],
    temperature=0,
    max_retries=2,
  )


def _last_message_content(state: dict[str, Any]) -> str:
  messages = state.get("messages", [])
  if not messages:
    return ""
  content = messages[-1].content
  return content if isinstance(content, str) else str(content)
