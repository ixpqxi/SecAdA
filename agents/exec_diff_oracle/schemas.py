"""Schemas for runtime BAC differential verification."""

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel, field_validator


class RuntimeEnvironment(BaseModel):
  """Credentials and metadata needed to exercise a victim/attacker chain."""

  model_config = ConfigDict(extra="forbid")

  base_url: str = Field(min_length=1)
  victim_token: str | None = None
  attacker_token: str | None = None
  victim_cookie: str | None = None
  attacker_cookie: str | None = None
  software_name: str = "Target application"
  project_link: str = ""
  affected_version: str = "Observed on tested instance"

  @field_validator("base_url")
  @classmethod
  def validate_base_url(cls, value: str) -> str:
    if not value.startswith(("http://", "https://")):
      raise ValueError("base_url must use http:// or https://")
    return value.rstrip("/")


class ChainExecutionResult(BaseModel):
  """Runtime proof and verdict for one exploit chain."""

  model_config = ConfigDict(extra="forbid")

  chain_id: str = Field(min_length=1)
  verdict: Literal["VULNERABLE", "SAFE", "ERROR"]
  attack_http_code: int | None = None
  attack_response: Any | None = None
  pre_snapshot: Any | None = None
  post_snapshot: Any | None = None
  diff: str = ""
  explanation: str = Field(min_length=1)
  artifacts_dir: str | None = None
  script_path: str | None = None
  report_path: str | None = None
  error: str | None = None


class ExecutionManifest(RootModel[list[ChainExecutionResult]]):
  """Top-level execution manifest written after all chains finish."""
