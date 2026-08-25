"""Validated report contract for structural vulnerability discovery."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class CodeLocation(BaseModel):
  """One source-code location supporting an audit conclusion."""

  model_config = ConfigDict(extra="forbid")

  path: str = Field(min_length=1)
  start_line: int = Field(ge=1)
  end_line: int = Field(ge=1)
  symbol: str | None = None
  excerpt: str = Field(min_length=1)

  @field_validator("path")
  @classmethod
  def validate_relative_path(cls, value: str) -> str:
    normalized = value.replace("\\", "/")
    parts = normalized.split("/")
    if normalized.startswith("/") or ".." in parts:
      raise ValueError("path must be relative and cannot contain '..'")
    return normalized

  @model_validator(mode="after")
  def validate_line_range(self) -> "CodeLocation":
    if self.end_line < self.start_line:
      raise ValueError("end_line must be greater than or equal to start_line")
    return self


class TaintStep(BaseModel):
  """One evidence-backed step in a source-to-sink path."""

  model_config = ConfigDict(extra="forbid")

  stage: Literal[
    "SOURCE",
    "TRANSFORM",
    "SANITIZER",
    "BYPASS",
    "SINK",
    "LOGIC",
  ]
  description: str = Field(min_length=1)
  location: CodeLocation


class VulnerabilityFinding(BaseModel):
  """One vulnerability with a reproducible static evidence chain."""

  model_config = ConfigDict(extra="forbid")

  title: str = Field(min_length=1)
  vulnerability_type: str = Field(min_length=1)
  severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
  confidence: Literal["CONFIRMED", "HIGH", "MEDIUM", "LOW"]
  summary: str = Field(min_length=1)
  business_impact: str = Field(min_length=1)
  affected_locations: list[CodeLocation] = Field(min_length=1)
  attack_path: list[TaintStep] = Field(min_length=2)
  concept_payload: str = Field(min_length=1)
  remediation: str = Field(min_length=1)
  code_language: str = Field(min_length=1)
  vulnerable_code: str = Field(min_length=1)
  fixed_code: str = Field(min_length=1)

  @model_validator(mode="after")
  def validate_taint_boundaries(self) -> "VulnerabilityFinding":
    stages = {step.stage for step in self.attack_path}
    if "SOURCE" not in stages or not ({"SINK", "LOGIC"} & stages):
      raise ValueError("attack_path must include SOURCE and SINK or LOGIC")
    return self


class SecurityAuditReport(BaseModel):
  """Top-level structured input rendered as the final Markdown report."""

  model_config = ConfigDict(extra="forbid")

  scope_summary: str = Field(min_length=1)
  coverage: list[str] = Field(min_length=1)
  findings: list[VulnerabilityFinding]
  incomplete_flows: list[str] = Field(default_factory=list)
  conclusion: str = Field(min_length=1)
