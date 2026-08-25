# SecAdA

本项目包含使用 LangChain 实现的审计 agent：

- `boundary-analysis`：复刻 Codex skill 的边界分析流程，识别技术栈、搜集
  Web/API 路由、追踪 DTO/Entity 及验证约束，并生成供后续审计使用的规范化
  接口清单。本阶段不会判断漏洞。
- `detect-bac-vuln`：复刻 Codex skill 的访问控制漏洞识别流程，读取阶段一的
  `Endpoint_Inventory`，结合项目源码和专家知识库推断 IDOR/BFLA 目标，并写入
  结构化漏洞目标图。
- `generate-exploit-chain`：复刻 Codex skill 的利用链规划流程，读取漏洞目标图和
  完整端点清单，为可满足前置依赖的目标生成严格四步的受害者/攻击者差分计划。
  该阶段只生成 JSON 计划，不执行真实 HTTP 请求。
- `bac-static-pipeline`：使用 LangGraph 编排以上三个静态分析阶段，显式传递阶段产物，
  在无接口、无漏洞或只有只读漏洞候选时按门控条件终止，并输出统一汇总。
- `exec-diff-oracle`：复刻 Codex skill 的运行时验证流程，严格执行利用链计划，
  记录攻击响应、前后稳定字段快照和 diff，并为每条链生成可重跑 Bash PoC 与
  Typst 报告。该阶段需要显式提供测试环境地址和身份凭证。
- `vuln-discovery-auditor`：复刻 Codex skill 的白盒漏洞发现流程，先识别攻击面，
  再追踪 Source -> Sanitizer/Bypass -> Sink 数据流，并输出带代码证据、概念 PoC
  和修复代码对比的 Markdown 安全审计报告。
- `vuln-report-verifier`：复刻 Codex skill 的漏洞报告复核流程，读取初筛报告并从
  业务前置条件、全局鉴权调用栈和架构影响三个层面证伪误报，输出带 verdict 和修正
  调用链的 Markdown 复核报告。

各阶段 agent 均通过 Deep Agents 的 `SkillsMiddleware` 加载各自的打包 skill。
初始化 system prompt 只包含运行上下文与安全约束；中间件向模型披露 skill 的名称、
描述和虚拟路径，模型再通过只读 `read_file` 按需加载完整 `SKILL.md`、示例和参考资料。
这种渐进披露方式避免在每次模型调用中预先拼接完整 skill 内容。

## 运行

在项目根目录的 `.env` 中配置 OpenAI 兼容接口：

```dotenv
CUSTOM_LLM_MODEL_NAME=your-model
CUSTOM_LLM_API_KEY=your-key
CUSTOM_LLM_BASE_URL=https://your-provider.example/v1
```

执行：

```bash
uv run python -m agents.boundary_analysis /absolute/path/to/target-project
uv run python -m agents.detect_bac_vuln /absolute/path/to/target-project
uv run python -m agents.generate_exploit_chain /absolute/path/to/target-project
uv run python -m agents.bac_static_pipeline /absolute/path/to/target-project \
  --scope-hints "orders,admin APIs"
uv run python -m agents.exec_diff_oracle /absolute/path/to/target-project \
  --base-url http://127.0.0.1:8000 \
  --victim-token victim-token \
  --attacker-token attacker-token
uv run python -m agents.vuln_discovery_auditor /absolute/path/to/target-project
uv run python -m agents.vuln_report_verifier /absolute/path/to/target-project \
  /absolute/path/to/target-project/vuln_scan/Security_Audit_Report_<timestamp>.md
```

通过 `bac-static-pipeline` 运行时，产物统一写入当前 SecAdA 项目的中央目录，
并按目标项目名称隔离：

```text
output/<project-name>/Endpoint_Inventory_<timestamp>.json
output/<project-name>/Vulnerable_Targets_Map_<timestamp>.json
output/<project-name>/Exploit_Chains_Plan_<timestamp>.json
```

三个独立阶段 agent 默认仍写入目标项目的 `vuln_scan/`，也可以通过各自的
`--output-directory` 参数改为指定目录。流水线可以通过 `--output-root`
覆盖中央输出根目录。

运行 `exec-diff-oracle` 时，运行时验证产物仍遵循该 agent 自身的输出配置：

```text
vuln_scan/Exec_Diff_Oracle_Manifest_<timestamp>.json
```

可用参数：

```bash
uv run python -m agents.boundary_analysis --help
uv run python -m agents.detect_bac_vuln --help
uv run python -m agents.generate_exploit_chain --help
uv run python -m agents.bac_static_pipeline --help
uv run python -m agents.exec_diff_oracle --help
uv run python -m agents.vuln_discovery_auditor --help
uv run python -m agents.vuln_report_verifier --help
```

## 代码调用

```python
from agents.boundary_analysis import create_boundary_analysis_agent
from agents.bac_static_pipeline import create_bac_static_pipeline
from agents.detect_bac_vuln import create_detect_bac_vulnerability_agent
from agents.generate_exploit_chain import create_generate_exploit_chain_agent
from agents.exec_diff_oracle import create_exec_diff_oracle_agent
from agents.vuln_discovery_auditor import create_vulnerability_discovery_agent
from agents.vuln_report_verifier import create_vulnerability_report_verifier_agent

agent = create_boundary_analysis_agent("/path/to/target-project")
result = agent.invoke()
print(result.output_path)

bac_agent = create_detect_bac_vulnerability_agent("/path/to/target-project")
bac_result = bac_agent.invoke()
print(bac_result.output_path)

chain_agent = create_generate_exploit_chain_agent("/path/to/target-project")
chain_result = chain_agent.invoke()
print(chain_result.output_path)

pipeline_result = create_bac_static_pipeline("/path/to/target-project").invoke()
print(pipeline_result.output_directory)
print(pipeline_result.state["summary"])

oracle_agent = create_exec_diff_oracle_agent(
    "/path/to/target-project",
    {
        "base_url": "http://127.0.0.1:8000",
        "victim_token": "victim-token",
        "attacker_token": "attacker-token",
    },
)
oracle_result = oracle_agent.invoke()
print(oracle_result.manifest_path)

audit_agent = create_vulnerability_discovery_agent("/path/to/target-project")
audit_result = audit_agent.invoke()
print(audit_result.output_path)

verifier_agent = create_vulnerability_report_verifier_agent(
    "/path/to/target-project",
    audit_result.output_path,
)
verification_result = verifier_agent.invoke()
print(verification_result.output_path)
```

也可以向 `create_boundary_analysis_agent(..., model=your_chat_model)` 注入任意支持
tool calling 的 LangChain `BaseChatModel`，用于测试或切换模型供应商。

## 组成

- `agents/skill_middleware.py`：共享的 `SkillsMiddleware`、只读文件 middleware
  和规范化虚拟 skill 路径配置。
- `skill/`：原 Codex `SKILL.md`、提取指南、方法论、输出示例和报告模板；
  由 middleware 渐进加载，不直接拼入 agent 的 system prompt。
- `tools.py`：限定在目标项目内的文件枚举、检索、分页读取、指南加载和产物写入工具。
- `schemas.py`：端点清单的 Pydantic 输出协议。
- `agent.py`：LangChain agent、完成条件检查与模型配置。
- `cli.py`：命令行入口。

运行单元测试：

```bash
uv run python -m unittest discover -v
```


```Mermaid
graph TD
      START --> boundary_analysis
      boundary_analysis --> check_endpoint_inventory
      check_endpoint_inventory -->|continue| detect_bac_vuln
      check_endpoint_inventory -->|stop| summary
      detect_bac_vuln --> check_vulnerable_targets
      check_vulnerable_targets -->|generate| generate_exploit_chain
      check_vulnerable_targets -->|stop| summary
      generate_exploit_chain --> summary
      summary --> END
```
