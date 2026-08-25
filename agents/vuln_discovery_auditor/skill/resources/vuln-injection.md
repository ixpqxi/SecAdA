# 注入与执行类漏洞审计指南 (Injection & Execution)

## 1. SQL 注入 (SQL Injection)
- **Sink 特征**：
  - PHP: `mysql_query`, `mysqli_query`, `PDO::query()`, `PDO::exec()`。
  - Java: `Statement.executeQuery()`, 拼接的 HQL/JPQL, MyBatis 中使用 `${}` 拼接的变量（非 `#{}`）。
- **Bypass / 绕过审计点**：
  - **宽字节注入**：如果数据库使用 GBK，前端输入 `%df'` -> `%df\'`，`\` 会被吃掉导致单引号逃逸。
  - **二次编码**：URL、Hex 编码绕过 WAF。
  - **盲注与报错**：在无回显场景，寻找是否输出了数据库错误信息（报错注入如 `updatexml`, `extractvalue`），或是否存在时间延迟逻辑。
- **安全规范**：必须强制使用预编译（PreparedStatement）或 ORM 的参数化查询。

## 2. 远程命令执行 (RCE)
- **Sink 特征**：
  - PHP: `system()`, `exec()`, `shell_exec()`, `passthru()`, `popen()`, `` ` `` (反引号)。
  - Java: `Runtime.getRuntime().exec()`, `ProcessBuilder.start()`。
  - Python: `os.system()`, `subprocess.Popen()`。
- **Bypass / 绕过审计点**：
  - 命令连接符：Windows (`|`, `||`, `&`, `&&`)，Linux (`;`, `|`, `&`, `&&`, `||`)。
  - 黑名单规避：空格绕过（如 `<` 重定向）、变量拼接（`a=l;b=s;$a$b`）、Base64 解码执行。
  - 长度限制绕过：通过 `>com` 配合 `ls -t>a` 组装长命令。

## 3. 动态代码执行 (Code Execution)
- **Sink 特征**：
  - PHP: `eval()`, `assert()`, `preg_replace('/e',...)`, `call_user_func()`, `create_function()`, `array_map()`。
- **审计策略**：如果回调函数名（如 `call_user_func` 的第一个参数）用户可控，即为高危。

## 4. XML 外部实体注入 (XXE)
- **Sink 特征**：
  - PHP: `DOMDocument::loadXML()`, `simplexml_load_string()` 且未调用 `libxml_disable_entity_loader(true)`（在老版本中）。
- **审计重点**：检查应用是否接收 XML 数据，以及解析器是否明确禁用了外部实体（DTD/Entity）与外部 DTD 引用。
