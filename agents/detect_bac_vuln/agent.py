"""LangChain detect-bac-vuln agent and completion guard."""

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
from .tools import DetectBacToolkit

DEFAULT_TASK = """基于已生成的 Endpoint_Inventory JSON，对目标项目进行访问控制漏洞识别。

严格执行 detect-bac-vuln skill 的全部步骤：先加载专家知识库，分页读取完整端点清单，
再逐端点对比理论最小授权需求与代码中的实际授权实现。只输出有明确代码证据的
IDOR/BFLA 目标。完成后调用 write_vulnerable_targets 写入规范化 JSON 产物。"""


@dataclass(frozen=True)
class DetectBacVulnerabilityResult:
  """Result returned only after a vulnerability map artifact is written."""

  output_path: Path
  inventory_path: Path
  final_response: str
  state: dict[str, Any]


class DetectBacVulnerabilityAgent:
  """Project-scoped wrapper around a LangChain BAC detection agent."""

  def __init__(
    self,
    project_root: str | Path,
    model: BaseChatModel,
    *,
    inventory_path: str | Path | None = None,
    output_directory: str | Path | None = None,
    recursion_limit: int = 100,
    completion_retries: int = 1,
  ) -> None:
    if recursion_limit < 1:
      raise ValueError("recursion_limit must be positive")
    if completion_retries < 0:
      raise ValueError("completion_retries cannot be negative")
    self.project_root = Path(project_root).expanduser().resolve()
    self.toolkit = DetectBacToolkit(
      self.project_root,
      inventory_path=inventory_path,
      output_directory=output_directory,
    )
    self.recursion_limit = recursion_limit
    self.completion_retries = completion_retries
    self.graph = create_agent(
      model=model,
      tools=self.toolkit.tools,
      system_prompt=build_system_prompt(
        self.project_root,
        self.toolkit.selected_inventory_path,
        Path(self.toolkit.output_directory),
      ),
      middleware=build_skill_middlewares(
        Path(__file__).resolve().parent,
        "detect-bac-vuln",
      ),
      name="detect-bac-vuln",
    )

  def invoke(self, instruction: str | None = None) -> DetectBacVulnerabilityResult:
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
        return DetectBacVulnerabilityResult(
          output_path=self.toolkit.written_paths[-1],
          inventory_path=self.toolkit.selected_inventory_path,
          final_response=_last_message_content(state),
          state=state,
        )
      if attempt < self.completion_retries:
        state = {
          "messages": [
            *state["messages"],
            HumanMessage(
              content=(
                "尚未生成必需的 JSON 产物。请继续完成遗漏的 BAC 分析，并调用 "
                "write_vulnerable_targets。只有该工具成功返回后才能结束。"
              )
            ),
          ]
        }
    raise RuntimeError(
      "Agent stopped without calling write_vulnerable_targets; no artifact was written"
    )


def create_detect_bac_vulnerability_agent(
  project_root: str | Path,
  model: BaseChatModel | None = None,
  *,
  inventory_path: str | Path | None = None,
  output_directory: str | Path | None = None,
  recursion_limit: int = 100,
  completion_retries: int = 1,
) -> DetectBacVulnerabilityAgent:
  """Build an agent, using the configured OpenAI-compatible model by default."""
  if model is None:
    model = _model_from_environment()
  return DetectBacVulnerabilityAgent(
    project_root=project_root,
    model=model,
    inventory_path=inventory_path,
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
