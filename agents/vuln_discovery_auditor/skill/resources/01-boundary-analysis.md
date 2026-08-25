# 边界资产与攻击面分析指南 (Boundary & Attack Surface)

在代码审计的第一步，必须识别所有跨越信任边界的数据输入。不要仅仅局限于 HTTP GET/POST。

## 1. 广义输入源识别 (Sources)
请在代码中寻找以下几类数据的引入点：
- **常规 Web 路由输入**：`$_GET`, `$_POST`, `$_REQUEST`, `$_COOKIE`, HTTP Headers (如 `User-Agent`, `Referer`, `X-Forwarded-For`)。
- **框架级参数绑定**：Java Spring 的 `@RequestParam`, `@RequestBody`, `@PathVariable`；PHP 框架的 `request()->param()`。
- **异步与内部通信机制**：监听 Kafka、RabbitMQ 的消费者代码，gRPC/Dubbo 微服务暴露的接口（通常缺乏鉴权）。
- **二次输入源（重点关注）**：从数据库读取的记录、读取的本地配置文件、缓存数据（Redis）、第三方 API 回调（如支付成功回调）。开发者常对这类数据盲目信任，卸下防备。

## 2. 路由分发解析特性
- **文件系统映射**：直接访问 `.php` 脚本。注意未被正常路由保护的游离文件（如 `/api/test.php`）。
- **集中式路由表**：如 Laravel 的 `routes/web.php`。
- **注解与动态反射**：如 Spring 的 `@GetMapping`。注意框架的路径匹配差异（如 Tomcat 与 Spring 对 `%;` 或 `/` 结尾解析的不一致导致的鉴权绕过）。

## 3. 全局拦截与消毒审查 (Global Sanitizers)
在分析 Controller 之前，必须向上追溯全局配置：
- 是否存在全局的 `Filter` (Java) 或 `Middleware` (PHP)？
- 是否启用了全局的 `addslashes` (如老的魔术引号)？
- **上下文错位警告**：全局 WAF 或过滤器通常只防御一种上下文（如防 SQL 注入），但无法防御进入 `eval()` 或 DOM 的数据。
