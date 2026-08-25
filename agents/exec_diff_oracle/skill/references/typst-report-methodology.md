# Typst Report Methodology

在 `exec-diff-oracle` 需要输出正式漏洞报告时，使用本参考。

## 1. 报告目标

输入：

- 环境基础信息
- `Endpoint_Inventory`
- `Vulnerable_Targets_Map`
- `Exploit_Chains_Plan`
- 已执行的 PoC 脚本及其工件

输出：

- 每条漏洞利用链默认对应一对交付物：
  - 一份独立的 `.typ` 漏洞分析与复现报告
  - 一份独立的 `.sh` 可重跑验证脚本

## 2. 文件命名

默认与 PoC 脚本保持同基名：

- `poc_embedding_reindex_start.sh` -> `poc_embedding_reindex_start.typ`
- `poc_comments_integration_bfla.sh` -> `poc_comments_integration_bfla.typ`

这样可以让脚本、工件目录、报告一一对应。

## 3. 报告结构

采用固定三段式：

1. 漏洞基本信息
2. `1 Vulnerability Code Analysis`
3. `2 Proof of Concept`
4. `3 Conclusion`

基础信息建议包含：

- 软件名称
- 项目链接
- 受影响版本
- 漏洞类型
- 漏洞描述与危害

## 4. 代码分析写法

代码分析必须同时回答三个问题：

1. 路由或入口原本声明了什么权限边界
2. 实际哪个中间件、控制器或服务逻辑使该边界失效
3. 敏感动作在绕过后如何继续执行

优先引用：

- 路由注册
- 中间件分支
- handler
- service / repository

如果源码声明和运行结果冲突，要明确写出“声明上要求更高权限，但运行态未生效”。

## 5. PoC 写法

`Proof of Concept` 必须基于已验证的真实结果，而不是抽象推演。

默认假设同基名 `.sh` 已存在或会同时生成。报告不是独立文本产物，而是脚本执行结果的正式表达。

建议顺序：

### a. 受害者前置构造或攻击前快照

- 放入真实 `pre.txt` 或前置响应的关键片段

### b. 攻击者请求

- 放入与 PoC 脚本一致的 `curl` 片段
- 放入真实攻击响应

### c. 受害者攻击后验证

- 放入真实 `post.txt`
- 若存在明显变化，再放入 `diff`

## 6. 弱差异场景

如果后置差异不明显，不要省略结论；要解释：

- 为什么状态变化窗口很短
- 为什么环境功能未启用或异步作业迅速终态
- 为什么攻击者成功命中高权限接口本身仍足以证明漏洞

这类说明通常出现在 `Proof of Concept` 尾部和 `Conclusion`。

## 7. 结论写法

结论必须明确：

- 漏洞是否确认存在
- 根因是什么
- 运行态证据是什么
- 若存在弱差异，为什么不影响漏洞成立

避免只写“接口返回 200 所以存在漏洞”。应写成：

- 路由声明的权限边界
- 中间件或业务逻辑失效
- 攻击者实际完成了什么敏感动作
- 受害者视角看到了什么结果

## 8. 风格要求

- 语气直接、客观、取证化
- 以真实证据为中心
- 不使用泛化占位描述替代真实结果
- 代码块和 JSON 片段保持紧凑，只保留关键内容

## 9. 推荐模板来源

优先参考：

- `examples/output_report.typ`
- `/root/Resources/vuln_report_template/dev-survey.do.typ`

前者用于掌握 skill 的目标输出形态，后者用于学习正式漏洞报告的版式与段落组织。

## 10. 成对产物约束

默认同时交付：

- `poc_xxx.sh`
- `poc_xxx.typ`

并保持以下一致性：

- Typst 报告中引用的脚本路径就是同基名 `.sh`
- Typst 报告中的工件目录来自该脚本实际运行结果
- Typst 报告中的 curl 片段与脚本逻辑一致
- Typst 报告中的快照片段来自该脚本输出的证据文件
