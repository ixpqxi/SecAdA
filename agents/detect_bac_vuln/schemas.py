"""Output contract for detected broken-access-control targets."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel, field_validator


class AuthorizationAnalysis(BaseModel):
  """Evidence-backed comparison of intended and actual authorization."""

  model_config = ConfigDict(extra="forbid")

  actual_implementation: str = Field(min_length=1)
  intended_requirement: str = Field(min_length=1)
  gap_and_determination: str = Field(min_length=1)


class EndpointReference(BaseModel):
  """A minimal reference to an endpoint from the input inventory."""

  model_config = ConfigDict(extra="forbid")

  http_method: str = Field(min_length=1)
  url_path: str = Field(min_length=1)

  @field_validator("http_method")
  @classmethod
  def normalize_http_method(cls, value: str) -> str:
    return value.upper()


class BoundReadEndpoint(EndpointReference):
  """A read endpoint that can observe the vulnerable operation's outcome."""

  description: str = Field(min_length=1)


class VulnerableTarget(BaseModel):
  """One evidence-backed BAC finding for downstream exploit-chain planning."""

  model_config = ConfigDict(extra="forbid")

  authorization_analysis: AuthorizationAnalysis
  target_endpoint: EndpointReference
  action_predicate: str = Field(min_length=1)
  parameter_constraints: dict[str, str]
  vulnerability_type: Literal[
    "RBAC_IDOR",
    "RBAC_BFLA",
    "MBAC_IDOR",
    "MBAC_BFLA",
  ]
  bound_read_endpoint: BoundReadEndpoint | None


class VulnerableTargetsMap(RootModel[list[VulnerableTarget]]):
  """The top-level JSON array written by the detect-bac-vuln agent."""
