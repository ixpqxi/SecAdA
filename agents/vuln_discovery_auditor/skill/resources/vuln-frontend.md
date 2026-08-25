# 前端与交互类漏洞审计指南 (XSS & CSRF)

## 1. 跨站脚本攻击 (XSS)
- **Sink 特征**：
  - PHP: `echo`, `print`, `die()`, `<?= ?>` 直接输出用户输入。
  - 前端/DOM: `innerHTML`, `document.write()`, `eval()`, `setTimeout()` 第一个参数。
- **分类审计策略**：
  - **反射型**：输入立即回显在响应中。
  - **存储型**：数据先写入数据库，再在其他页面（或后台）输出（盲打 XSS）。
  - **DOM 型**：数据根本不经过后端处理，完全在前端 JS 中获取（如通过 `location.hash`）并渲染。
- **Bypass / 绕过审计点**：
  - 事件属性：利用 `onerror`, `onfocus`, `onclick`, `onload` 等 HTML 属性。
  - 伪协议：在 `<a>` 标签 `href` 中使用 `javascript:alert(1)`。
  - 编码绕过：10进制/16进制 HTML 实体编码、JS `String.fromCharCode()`。
- **安全规范**：输出是否经过 `htmlspecialchars()` 处理？前端框架（如 React/Vue）是否错误使用了 `dangerouslySetInnerHTML` 或 `v-html`？

## 2. 跨站请求伪造 (CSRF)
- **漏洞特征**：核心操作（如修改密码、转账、添加管理员）依赖 Cookie 认证，且未校验请求的来源或唯一随机性。
- **审计策略**：
  - 检查关键业务表单提交或 API 请求中，是否缺少 `Token` 字段。
  - 检查后端中间件是否校验了 `Referer` 或 `Origin` HTTP 头。
  - 如果允许 `GET` 请求进行敏感状态修改（如 `?action=delete&id=1`），极易遭受此攻击（如通过 `<img>` 标签加载）。
