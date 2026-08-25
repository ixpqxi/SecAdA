"""Validated contract for vulnerability-report verification results."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class CodeLocation(BaseModel):
  """A project-relative source location used as verification evidence."""

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
    if normalized.startswith("/") or ".." in normalized.split("/"):
      raise ValueError("path must be relative and cannot contain '..'")
    return normalized

  @model_validator(mode="after")
  def validate_line_range(self) -> "CodeLocation":
    if self.end_line < self.start_line:
      raise ValueError("end_line must be greater than or equal to start_line")
    return self


class VerificationBlocker(BaseModel):
  """One blocking, non-blocking, or unresolved verification observation."""

  model_config = ConfigDict(extra="forbid")

  category: Literal[
    "BUSINESS_PRECONDITION",
    "GLOBAL_AUTH",
    "ARCHITECTURE",
    "LOCALIZED_LOGIC",
    "NONE",
    "OTHER",
  ]
  status: Literal["BLOCKING", "NON_BLOCKING", "UNCERTAIN"]
  description: str = Field(min_length=1)
  location: CodeLocation | None = None


class CallChainStep(BaseModel):
  """One step in the corrected call chain reconstructed from source."""

  model_config = ConfigDict(extra="forbid")

  stage: str = Field(min_length=1)
  outcome: Literal["ALLOWED", "BLOCKED", "UNCERTAIN"]
  description: str = Field(min_length=1)
  location: CodeLocation | None = None


class VerificationReport(BaseModel):
  """Top-level structured result rendered as the final Markdown report."""

  model_config = ConfigDict(extra="forbid")

  original_claim_summary: str = Field(min_length=1)
  verdict: Literal["CONFIRMED", "FALSE_POSITIVE", "NEEDS_MANUAL_REVIEW"]
  verdict_rationale: str = Field(min_length=1)
  blocker_analysis: list[VerificationBlocker] = Field(min_length=1)
  corrected_call_chain: list[CallChainStep] = Field(min_length=1)
  false_positive_pattern: str = Field(min_length=1)
  residual_uncertainties: list[str] = Field(default_factory=list)
  final_recommendation: str = Field(min_length=1)
