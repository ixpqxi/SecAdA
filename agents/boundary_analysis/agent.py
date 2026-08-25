"""LangChain boundary-analysis agent and its completion guard."""

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
from .tools import BoundaryAnalysisToolkit

DEFAULT_TASK = """完整分析目标项目的外部 Web/API 边界。

严格执行 boundary-analysis skill 的全部步骤，系统搜集路由并追踪输入 DTO、
实体、验证器和必要的业务方法。不要进行漏洞分析。完成后调用
write_endpoint_inventory 写入规范化 JSON 产物。"""


@dataclass(frozen=True)
class BoundaryAnalysisResult:
  """Result returned only after an inventory artifact has been written."""

  output_path: Path
  final_response: str
  state: dict[str, Any]


class BoundaryAnalysisAgent:
  """Project-scoped wrapper around a LangChain tool-calling agent."""

  def __init__(
    self,
    project_root: str | Path,
    model: BaseChatModel,
    *,
    output_directory: str | Path | None = None,
    recursion_limit: int = 100,
    completion_retries: int = 1,
  ) -> None:
    if recursion_limit < 1:
      raise ValueError("recursion_limit must be positive")
    if completion_retries < 0:
      raise ValueError("completion_retries cannot be negative")
    self.project_root = Path(project_root).expanduser().resolve()
    self.toolkit = BoundaryAnalysisToolkit(
      self.project_root,
      output_directory=output_directory,
    )
    self.recursion_limit = recursion_limit
    self.completion_retries = completion_retries
    self.graph = create_agent(
      model=model,
      tools=self.toolkit.tools,
      system_prompt=build_system_prompt(
        self.project_root,
        Path(self.toolkit.output_directory),
      ),
      middleware=build_skill_middlewares(
        Path(__file__).resolve().parent,
        "boundary-analysis",
      ),
      name="boundary-analysis",
    )

  def invoke(self, instruction: str | None = None) -> BoundaryAnalysisResult:
    """Run the analysis and require the validated output tool to be called."""
    state: dict[str, Any] = {
      "messages": [
        {"role": "user", "content": instruction or DEFAULT_TASK},
      ]
    }
    for attempt in range(self.completion_retries + 1):
      state = self.graph.invoke(
        state,
        config={"recursion_limit": self.recursion_limit},
      )
      if self.toolkit.written_paths:
        return BoundaryAnalysisResult(
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
                "尚未生成必需的 JSON 产物。请继续完成遗漏的分析，并调用 "
                "write_endpoint_inventory。只有该工具成功返回后才能结束。"
              )
            ),
          ]
        }
    raise RuntimeError(
      "Agent stopped without calling write_endpoint_inventory; no artifact was written"
    )


def create_boundary_analysis_agent(
  project_root: str | Path,
  model: BaseChatModel | None = None,
  *,
  output_directory: str | Path | None = None,
  recursion_limit: int = 100,
  completion_retries: int = 1,
) -> BoundaryAnalysisAgent:
  """Build an agent, using the configured OpenAI-compatible model by default."""
  if model is None:
    model = _model_from_environment()
  return BoundaryAnalysisAgent(
    project_root=project_root, 
    model=model,
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
  if isinstance(content, str):
    return content
  return str(content)
