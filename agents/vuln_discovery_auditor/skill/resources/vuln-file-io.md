# 文件IO与请求类漏洞验证指南

## 1. 文件上传 (File Upload)
- **Sink特征**：`move_uploaded_file()`, `$_FILES`。
- **Bypass点**：
  - 后缀黑名单校验：检查大小写、点绕过(`.php.`)、空格绕过、`::$DATA`绕过。
  - 解析漏洞利用：Apache `.htaccess` 覆盖、Nginx 畸形解析 (`xxx.jpg/1.php`)。
  - 00截断：检查白名单路径拼接时是否存在 `%00` 或 `0x00`。

## 2. SSRF (服务端请求伪造)
- **Sink特征**：`curl_exec()`, `file_get_contents()`, `fsockopen()`。
- **Bypass点 (绕过内网IP限制)**：
  - 进制转换绕过：如 `192.168.0.1` -> `0xC0.0xA8.0.1`。
  - DNS 重绑定 / `xip.io` 子域名指向。
  - 伪协议利用：`dict://`, `file://`, `php://filter` 读文件。
