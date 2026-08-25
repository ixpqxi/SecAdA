"""LangChain runtime verifier for planned BAC exploit chains."""

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
from .tools import ExecDiffOracleToolkit

DEFAULT_TASK = """执行 Exploit_Chains_Plan 中的全部 chain_id，严格按计划进行环境预检、
受害者前置构造、攻击前快照、攻击者调用和攻击后快照。对每条链生成可重跑 Bash PoC、
Typst 报告和基于运行证据的 VULNERABLE/SAFE/ERROR 结论，完成后写入 execution manifest。"""


@dataclass(frozen=True)
class ExecDiffOracleResult:
  manifest_path: Path
  inventory_path: Path
  targets_path: Path
  chains_path: Path
  final_response: str
  state: dict[str, Any]


class ExecDiffOracleAgent:
  def __init__(self, project_root: str | Path, environment: dict[str, Any],
               model: BaseChatModel, *, endpoint_inventory_path: str | Path | None = None,
               vulnerable_targets_path: str | Path | None = None,
               exploit_chains_path: str | Path | None = None,
               output_root: str | Path | None = None, recursion_limit: int = 200,
               completion_retries: int = 1) -> None:
    if recursion_limit < 1 or completion_retries < 0:
      raise ValueError("recursion_limit must be positive and retries non-negative")
    self.toolkit = ExecDiffOracleToolkit(
      Path(project_root), environment, endpoint_inventory_path,
      vulnerable_targets_path, exploit_chains_path, output_root,
    )
    self.recursion_limit = recursion_limit
    self.completion_retries = completion_retries
    self.graph = create_agent(
      model=model, tools=self.toolkit.tools,
      system_prompt=build_system_prompt(
        self.toolkit.project_root, "runtime environment", self.toolkit.selected_inventory_path,
        self.toolkit.selected_targets_path, self.toolkit.selected_chains_path,
      ),
      middleware=build_skill_middlewares(
        Path(__file__).resolve().parent,
        "exec-diff-oracle",
      ),
      name="exec-diff-oracle",
    )

  def invoke(self, instruction: str | None = None) -> ExecDiffOracleResult:
    state: dict[str, Any] = {"messages": [{"role": "user", "content": instruction or DEFAULT_TASK}]}
    for attempt in range(self.completion_retries + 1):
      state = self.graph.invoke(state, config={"recursion_limit": self.recursion_limit})
      if self.toolkit.written_paths:
        return ExecDiffOracleResult(
          manifest_path=self.toolkit.written_paths[-1],
          inventory_path=self.toolkit.selected_inventory_path,
          targets_path=self.toolkit.selected_targets_path,
          chains_path=self.toolkit.selected_chains_path,
          final_response=_last_message_content(state), state=state,
        )
      if attempt < self.completion_retries:
        state = {"messages": [*state["messages"], HumanMessage(
          content="尚未写入 execution manifest。请继续执行所有 chain_id，并调用 write_execution_manifest。"
        )]}
    raise RuntimeError("Agent stopped without writing execution manifest")


def create_exec_diff_oracle_agent(project_root: str | Path,
                                  environment: dict[str, Any],
                                  model: BaseChatModel | None = None, **kwargs: Any) -> ExecDiffOracleAgent:
  return ExecDiffOracleAgent(project_root, environment, model or _model_from_environment(), **kwargs)


def _model_from_environment() -> ChatOpenAI:
  names = ("CUSTOM_LLM_MODEL_NAME", "CUSTOM_LLM_API_KEY", "CUSTOM_LLM_BASE_URL")
  values = {name: os.environ.get(name) for name in names}
  missing = [name for name in names if not values[name]]
  if missing:
    raise RuntimeError("Missing required environment variables: " + ", ".join(missing))
  return ChatOpenAI(model=values[names[0]], api_key=values[names[1]],
                    base_url=values[names[2]], temperature=0, max_retries=2)


def _last_message_content(state: dict[str, Any]) -> str:
  messages = state.get("messages", [])
  return str(messages[-1].content) if messages else ""
