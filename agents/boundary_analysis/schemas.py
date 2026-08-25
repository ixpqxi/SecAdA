"""Output contract for endpoint inventories."""

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class EndpointParameter(BaseModel):
  """A single externally controlled endpoint parameter."""

  model_config = ConfigDict(extra="forbid", populate_by_name=True)

  name: str = Field(min_length=1)
  location: str = Field(alias="in", min_length=1)
  type: str = Field(min_length=1)
  is_required: bool
  constraints: str | list[str] | dict[str, Any] | None = None


class ApiEndpoint(BaseModel):
  """Normalized endpoint description used by downstream audit stages."""

  model_config = ConfigDict(extra="forbid")

  url_path: str = Field(min_length=1)
  http_method: str = Field(min_length=1)
  operation_category: Literal["CREATE", "READ", "UPDATE", "DELETE"]
  action_predicate: str = Field(min_length=1)
  parameters: list[EndpointParameter] = Field(default_factory=list)

  @field_validator("http_method")
  @classmethod
  def normalize_http_method(cls, value: str) -> str:
    return value.upper()


class EndpointInventory(BaseModel):
  """Top-level artifact written by the boundary-analysis agent."""

  model_config = ConfigDict(extra="forbid")

  api_inventory: list[ApiEndpoint]
