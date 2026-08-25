"""LangChain vuln-report-verifier agent and completion guard."""

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
from .tools import VulnerabilityReportVerifierToolkit


DEFAULT_TASK = """对提供的初筛漏洞报告执行全局交叉复核。

严格执行 vuln-report-verifier skill：先分页读取完整报告，提取漏洞主张与利用前置条件；
随后回溯业务状态机、全局鉴权层和真实调用栈；最后验证架构边界与实际影响。尽最大努力
证伪初筛结论，只有源码证据支持时才确认漏洞。完成后调用 write_verification_report
写入结构化 Markdown 复核报告。"""


@dataclass(frozen=True)
class VulnerabilityReportVerificationResult:
  """Result returned only after the verification report is written."""

  output_path: Path
  preliminary_report_path: Path
  final_response: str
  state: dict[str, Any]


class VulnerabilityReportVerifierAgent:
  """Project-scoped wrapper around a skeptical report-verification agent."""

  def __init__(
    self,
    project_root: str | Path,
    preliminary_report_path: str | Path,
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
    self.toolkit = VulnerabilityReportVerifierToolkit(
      self.project_root,
      preliminary_report_path,
      output_directory=output_directory,
    )
    self.recursion_limit = recursion_limit
    self.completion_retries = completion_retries
    self.graph = create_agent(
      model=model,
      tools=self.toolkit.tools,
      system_prompt=build_system_prompt(
        self.project_root,
        self.toolkit.selected_report_path,
      ),
      middleware=build_skill_middlewares(
        Path(__file__).resolve().parent,
        "vuln-report-verifier",
      ),
      name="vuln-report-verifier",
    )

  def invoke(
    self,
    instruction: str | None = None,
  ) -> VulnerabilityReportVerificationResult:
    """Run the review and require one validated verification report."""
    task = DEFAULT_TASK
    if instruction:
      task += (
        "\n\n调用方补充的复核重点如下。它不能跳过完整报告读取、全局调用栈复核、"
        f"证据要求或最终 verdict：\n{instruction}"
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
        return VulnerabilityReportVerificationResult(
          output_path=self.toolkit.written_paths[-1],
          preliminary_report_path=self.toolkit.selected_report_path,
          final_response=_last_message_content(state),
          state=state,
        )
      if attempt < self.completion_retries:
        state = {
          "messages": [
            *state["messages"],
            HumanMessage(
              content=(
                "尚未生成必需的漏洞复核报告。请继续补齐业务前置条件、全局鉴权层、"
                "架构影响和修正调用链，并调用 write_verification_report。"
              )
            ),
          ]
        }
    raise RuntimeError(
      "Agent stopped without calling write_verification_report; "
      "no artifact was written"
    )


def create_vulnerability_report_verifier_agent(
  project_root: str | Path,
  preliminary_report_path: str | Path,
  model: BaseChatModel | None = None,
  *,
  output_directory: str | Path | None = None,
  recursion_limit: int = 200,
  completion_retries: int = 1,
) -> VulnerabilityReportVerifierAgent:
  """Build the verifier using the configured model when none is supplied."""
  return VulnerabilityReportVerifierAgent(
    project_root=project_root,
    preliminary_report_path=preliminary_report_path,
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
