import os
import sys
from pathlib import Path

from dotenv import load_dotenv
from langchain.agents import create_agent
from langchain.messages import AIMessage, HumanMessage
from langchain_openai import ChatOpenAI
from openai import AuthenticationError, OpenAIError

PROJECT_ROOT = Path(__file__).resolve().parent
load_dotenv(PROJECT_ROOT / ".env")

REQUIRED_ENV_VARS = (
  "CUSTOM_LLM_MODEL_NAME",
  "CUSTOM_LLM_API_KEY",
  "CUSTOM_LLM_BASE_URL",
)


def get_weather(city: str) -> str:
  """Get weather for a given city."""
  return f"It's always sunny in {city}!"


def require_env(name: str) -> str:
  value = os.environ.get(name)
  if not value:
    raise RuntimeError(f"Missing required environment variable: {name}")
  return value


def build_agent():
  model = ChatOpenAI(
    model=require_env("CUSTOM_LLM_MODEL_NAME"),
    api_key=require_env("CUSTOM_LLM_API_KEY"),
    base_url=require_env("CUSTOM_LLM_BASE_URL"),
    temperature=0.7,
  )

  return create_agent(
    model=model,
    tools=[get_weather],
    system_prompt="You are a helpful assistant",
  )


def main() -> int:
  missing_env_vars = [
    name for name in REQUIRED_ENV_VARS if not os.environ.get(name)
  ]
  if missing_env_vars:
    print(
      "Missing required environment variables: " + ", ".join(missing_env_vars),
      file=sys.stderr,
    )
    return 1

  try:
    stream = build_agent().stream_events(
      {
        "messages": [
          {
            "role": "user",
            "content": "What's the weather in San Francisco?",
          }
        ]
      },
      version="v3",
    )
    for snapshot in stream.values:
      latest_message = snapshot["messages"][-1]
    if latest_message.content:
      if isinstance(latest_message, HumanMessage):
        print(f"User: {latest_message.content}")
      elif isinstance(latest_message, AIMessage):
        print(f"Agent: {latest_message.content}")
    elif latest_message.tool_calls:
      print(
        f"Calling tools: {[tc['name'] for tc in latest_message.tool_calls]}"
      )
  except AuthenticationError:
    print(
      "Authentication failed. Check CUSTOM_LLM_API_KEY in .env; the current "
      "key was rejected by the configured API provider.",
      file=sys.stderr,
    )
    return 1
  except OpenAIError as exc:
    print(f"LLM request failed: {exc}", file=sys.stderr)
    return 1

  # print(result["messages"][-1].content_blocks)
  return 0


if __name__ == "__main__":
  raise SystemExit(main())
