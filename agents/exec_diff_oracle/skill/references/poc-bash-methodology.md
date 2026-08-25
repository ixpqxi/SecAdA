# PoC Bash Methodology

在 `exec-diff-oracle` 需要把请求链落地为 Bash 脚本时，使用本参考。默认假设该脚本会与同基名的 Typst 报告成对交付。

## 1. 输入职责

- `Exploit_Chains_Plan`
  - 作为执行顺序和步骤意图的唯一主线
- `Endpoint_Inventory`
  - 补充方法、参数位置、类型、认证边界、scope 和 audience
- `Vulnerable_Targets_Map`
  - 确认链路是否命中目标漏洞端点
- 环境基础信息
  - 提供 `base_url`、凭证、受害者与攻击者身份语义

## 2. 脚本生成原则

- 一条链一个脚本
- 固定可固定的请求内容
- 对 `BASE_URL`、认证信息和易冲突资源 ID 提供环境变量覆盖
- 使用 `curl`、`jq`、`diff`
- 生成独立工件目录
- 结尾打印工件目录和证据文件路径

推荐命名：

- `poc_<module>_<action>.sh`

并默认预留给 Typst 报告的同基名：

- `poc_<module>_<action>.typ`

## 3. 标准脚本结构

1. 头部与环境变量默认值
2. 创建工件目录
3. 前置构造
4. 攻击前快照并生成 `pre.txt`
5. 攻击请求并生成 `attack.txt`
6. 攻击后快照并生成 `post.txt`
7. `diff -u pre.txt post.txt || true`
8. 打印工件目录

脚本中的工件路径最终会被 Typst 报告引用，因此不要省略输出路径。

## 4. 稳定字段优先

不要直接对完整响应做 diff。优先只保留判定所需字段，例如：

- `http_code`
- `data.status`
- `data.started_at`
- `data.finished_at`
- `data.total`
- `data.items[*].id`
- `data.items[*].source`

这样可以降低时间戳、排序和消息文本噪音。

## 5. 动态变量策略

优先级如下：

1. 若接口支持客户端显式指定资源 ID，优先固定 ID
2. 否则按 `data_extraction_rules` 动态提取
3. 再将变量注入后续 URL 或 payload

## 6. 判定时同时看两类证据

### 6.1 攻击证据

- 攻击者低权限身份却成功命中高权限接口
- 返回 `200`、`201`、`204` 等成功码

### 6.2 状态证据

- 受害者视角下状态字段变化
- 列表总数变化
- 出现带攻击内容的新资源
- 资源被删除或不可见

若环境因素导致状态证据较弱，但攻击证据强，仍可判定为漏洞，只要说明环境原因。

## 7. 弱差异环境的常见原因

- 功能未启用
- 异步作业过快结束
- 状态接口只返回终态
- 观测窗口过短
- 后端放行动作，但副作用被环境吞掉

此时不要直接判安全，应在结论中保留攻击证据与环境解释。

## 8. 推荐输出段

```text
==========Attack Result====================
<攻击响应 JSON>

==========Diff Result====================
<diff 输出>

artifacts dir: ./poc_xxx_xxxxxx
pre snapshot: ...
post snapshot: ...
```

## 9. 示例骨架

另见 `examples/poc_script_template.sh`。

## 10. 成对交付要求

默认把脚本视为 Typst 报告的证据来源之一，因此脚本编写时要保证：

- 文件名适合作为报告同基名
- 输出中明确打印工件目录
- 关键请求和关键响应能够被报告直接摘录
- `pre.txt`、`post.txt`、`attack.txt` 等路径稳定可引用
