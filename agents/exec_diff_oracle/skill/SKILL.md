---
name: exec-diff-oracle
description: >
  Execute and validate BAC exploit chains with victim/attacker differential observation, especially when given environment base information plus Endpoint_Inventory, Vulnerable_Targets_Map, and Exploit_Chains_Plan artifacts. Use when Codex must reproduce IDOR/BFLA/MBAC findings with curl, generate paired Bash PoC scripts and Typst vulnerability reports for each exploit chain, capture pre/post snapshots, diff stable evidence, and produce runtime-proof-driven deliverables rather than JSON result objects.
---

## 1. 角色
扮演严谨的漏洞验证员与差分取证执行器。按请求链复现，不擅自更换攻击路径，不跳过关键观测点，不把“接口返回 200”直接当成唯一成功标准。

## 2. 适用输入

期望同时具备以下输入：

- 环境基础信息
  - `base_url`
  - 认证材料，例如 Bearer Token、Cookie、账号密码
  - 受害者与攻击者身份语义
- `Endpoint_Inventory_*.json`
- `Vulnerable_Targets_Map_*.json`
- `Exploit_Chains_Plan_*.json`

若用户只给了单条请求链，也可以执行验证；但只要存在 `Endpoint_Inventory` 和 `Vulnerable_Targets_Map`，就必须利用它们补全参数结构、权限边界和目标确认。

## 3. 不可妥协的规则

- 以 `Exploit_Chains_Plan` 为执行顺序的唯一来源。
- 以 `Endpoint_Inventory` 为请求结构、参数类型、声明权限边界的基线。
- 以 `Vulnerable_Targets_Map` 确认该链确实对应目标漏洞端点。
- 一条 `chain_id` 默认同时产出一对同基名文件：一个 Bash PoC 脚本和一个 Typst 漏洞报告。
- 优先使用 `curl` 发包，使用 `jq` 提取稳定字段，使用 `diff` 展示前后差异。
- 固定可固定的请求内容；仅对环境地址、认证信息、易冲突资源 ID 预留环境变量覆盖。
- 保留攻击证据和状态证据两类材料，不因其中一类较弱就直接放弃结论。
- 对后置快照做裁剪后再差分，避免时间戳、排序、消息文本等噪音干扰结论。
- 当用户要求“漏洞报告”“复现报告”“Typst 报告”时，输出 Typst 漏洞报告而不是 JSON 结果对象。

## 4. 先读哪些材料

- 当任务包含“输出漏洞报告”或“生成 Typst 报告”时，读取 `references/typst-report-methodology.md`。
- 读取 `examples/output_report.typ` 以保持 Typst 报告结构与风格一致。
- 当任务包含“生成 Bash 验证脚本”或“把复现流程固化成可重跑脚本”时，读取 `references/poc-bash-methodology.md`。
- 需要脚本骨架时，参考 `examples/poc_script_template.sh`。
- 当用户没有明确限制产物类型时，把 `.sh` 与 `.typ` 视为默认成对交付物。

## 5. 输入归一化

在发起任何请求前，先完成下面的归一化动作：

1. 识别认证方案。
   - Bearer：允许输入是完整 `Authorization: Bearer ...`，也允许是裸 token。
   - Cookie：保留原始 cookie 串，不要擅自拆分。
2. 识别哪些值需要作为环境变量暴露给脚本。
   - 必选：`BASE_URL`
   - 常见：`VICTIM_TOKEN`、`ATTACKER_TOKEN`、`VICTIM_COOKIE`、`ATTACKER_COOKIE`
   - 可选：`ECHO_ID`、`RESOURCE_ID` 等冲突敏感值
3. 识别 token 是否可能过期。
   - 先做轻量连通和鉴权探测。
   - 若显然失效，不要继续盲打；明确要求新凭证。

## 6. 标准执行流程

### 6.1 预检环境

先确认：

- `base_url` 可访问
- 目标服务在监听
- 受害者和攻击者凭证可正常访问各自应访问的接口

若环境不可达、服务未启动或凭证已过期，返回 `ERROR` 或要求补充条件，不要伪造验证结论。

### 6.2 解析链路并建立运行时状态字典

维护一个运行时状态字典，用于：

- 替换 URL 中的 `${VAR}`
- 替换 payload 中的 `${VAR}`
- 记录前置步骤里提取出的资源 ID、状态字段、时间戳等

优先策略：

- 若 `Endpoint_Inventory` 显示接口允许客户端显式指定资源 ID，优先固定一个可复用 ID。
- 只有接口不支持显式 ID 时，才依赖 `data_extraction_rules` 动态提取。

### 6.3 前置合法状态构造

对 `PRECONDITION_SETUP` 步骤：

- 使用 `executor_role` 对应身份发起请求。
- 保持请求顺序与计划一致。
- 请求体默认固定写死，除非必须依赖上游动态变量。
- 返回非成功状态时，立即停止后续利用链，标记为 `SETUP_FAILED` 或 `ERROR`。

### 6.4 攻击前快照

对 `PRE_ATTACK_SNAPSHOT` 步骤：

- 渲染 URL 和请求体中的动态变量。
- 使用受害者视角或计划要求的观测身份获取观测数据。
- 保存原始响应体。
- 用 `jq` 裁剪出稳定字段，保存为 `pre.txt`。

优先选择：

- 受害者合法可访问的详情接口
- 受害者合法可访问的列表接口
- 后台任务的状态接口

### 6.5 攻击执行

对 `EXPLOIT_EXECUTION` 步骤：

- 切换到攻击者身份。
- 发送目标越权请求。
- 记录：
  - URL
  - Method
  - 认证头或 Cookie 方案
  - 请求体
  - HTTP 状态码
  - 原始响应体

不要只因为这里返回 `200` 就立即宣告漏洞成立；它是强证据，但不是唯一判定依据。

### 6.6 攻击后快照

对 `POST_ATTACK_SNAPSHOT` 步骤：

- 回到受害者或计划要求的观测身份。
- 请求与攻击前同类的观测接口。
- 保存原始响应体。
- 裁剪稳定字段并保存为 `post.txt`。
- 使用 `diff -u pre.txt post.txt || true` 输出差异。

### 6.7 弱差异处理

若后置差异很弱或快照相同，不要立刻判安全。先检查是否存在以下环境因素：

- 目标功能未启用
- 异步任务过快结束
- 状态接口只暴露终态
- 观测窗口过短
- 攻击本身是“高权限动作被低权限放行”，但副作用被环境吞掉

这类场景下，应同时保留：

- 攻击证据：攻击者本不应成功却成功命中高权限接口
- 环境解释：为什么快照差异弱或不可见

## 7. 生成 Bash PoC 脚本的要求

当用户要求“输出验证脚本”或需要可重跑验证能力时，按以下规则产出：

- 一条链一个脚本。
- 脚本与 Typst 报告默认使用同一基名。
- 脚本头部使用：

```bash
#!/usr/bin/env bash
set -euo pipefail
```

- 默认通过环境变量接收：
  - `BASE_URL`
  - `VICTIM_*`
  - `ATTACKER_*`
  - 可选资源 ID
- 请求使用 `curl`。
- 证据裁剪使用 `jq`。
- 差异展示使用 `diff`。
- 运行时生成独立工件目录，至少保存：
  - `pre.txt`
  - `post.txt`
  - `attack.txt`
  - 如有前置构造，再保存 `create.txt` 或 `precondition.txt`
- 结尾打印工件目录与关键文件路径。

推荐输出段落：

```text
==========Attack Result====================
<攻击响应>

==========Diff Result====================
<diff 输出>

artifacts dir: ./poc_xxx_xxxxxx
pre snapshot: ...
post snapshot: ...
```

## 8. 判定矩阵

### 8.1 `VULNERABLE`

满足任一条件即可：

- 受害者视角的核心业务字段发生符合攻击意图的变化。
- 受害者原本可见的资源在 DELETE 类攻击后消失。
- 后置差异较弱，但攻击者成功命中本应受更强权限边界保护的接口，且能给出可信的环境解释说明为何副作用不可稳定观察。

### 8.2 `SAFE`

满足全部条件时判定为 `SAFE`：

- 攻击请求被后端正确拒绝，或
- 攻击前后稳定业务字段无变化，且
- 不存在可解释的弱差异环境因素，且
- 无其他补充证据表明动作被低权限成功执行。

### 8.3 `ERROR`

以下情况输出 `ERROR`：

- 环境不可达
- 服务未启动
- 凭证无效或已过期
- 前置构造失败
- 计划文件关键字段缺失，无法安全执行

## 9. 输出要求

默认同时产出 Typst 漏洞报告与 Bash PoC 脚本；只有当用户明确要求单一产物时才缩减。

### 9.1 Typst 漏洞报告

Typst 报告应与 `examples/output_report.typ` 保持一致的结构和语气，至少包含：

- 漏洞标题与目标端点
- 软件名称、项目链接、受影响版本、漏洞类型
- 漏洞描述与危害
- `1 Vulnerability Code Analysis`
- `2 Proof of Concept`
- `3 Conclusion`

在 `Proof of Concept` 中，必须尽量使用已经执行过的真实证据，包括：

- 已验证的 PoC 脚本路径
- 工件目录
- 攻击前快照
- 攻击请求示例
- 攻击响应
- 攻击后快照
- 关键 diff 或弱差异解释

若由于环境特性导致弱差异，必须在结论中明确写出：

- 攻击请求为何仍构成有效证据
- 为什么后置状态差异较弱
- 为什么这不影响漏洞成立

Typst 报告默认与对应脚本同基名，例如：

- `poc_embedding_reindex_start.sh`
- `poc_embedding_reindex_start.typ`

### 9.2 Bash 脚本交付信息

默认必须同时生成脚本，并报告：

- 脚本路径
- 对应 `chain_id`
- 是否已执行
- 关键输出位置

推荐命名是同基名配对：

- `poc_xxx.sh`
- `poc_xxx.typ`

### 9.3 成对产物约束

除非用户明确禁止，否则每条链都要同时交付：

- 一个可直接重跑的 `.sh`
- 一个基于真实运行证据写成的 `.typ`

两者必须满足：

- 同一 `chain_id`
- 同一基名
- Typst 报告引用同一脚本和同一工件目录
- Typst 中的 PoC 片段与脚本实际执行逻辑一致

## 10. 实战约束

- 复现逻辑必须优先忠于计划文件，而不是追求“更聪明的替代路径”。
- 结论必须优先基于运行态证据，而不是源码中声明的 `RequireScopes` / `RequireAudience`。
- 若源码声明和运行结果冲突，应以运行结果为最终验证依据，并把源码声明作为辅助上下文。
- 若用户只要求验证，不必额外扩展攻击面；只执行目标链路。
- 若用户要求交付脚本，默认也一并交付同基名 `.typ` 报告，除非用户明确不要。
- 若用户要求交付报告，默认也一并交付同基名 `.sh` 脚本，除非用户明确不要。
- 若用户没有指定产物类型，默认输出 `.sh + .typ` 成对文件，而不是只交付其中一种。
