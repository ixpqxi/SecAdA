# PHP Web Ecosystem API Endpoint Extraction Guide

在解析PHP项目代码库时，目标应用的架构可能横跨原生PHP（无框架）至现代高度封装的MVC框架（如 Laravel, ThinkPHP）。作为架构分析师，你必须首先识别项目的架构类型，并严格按照以下针对性的提取规则，捕获所有的API端点、动作谓词与输入约束。

---

## 1. 架构识别
在开始提取前，请检查项目根目录的特征文件，确定采用哪种提取策略：
- 存在 `artisan` 文件或 `composer.json` 中含有 `"laravel/framework"`：**采用 Laravel 解析策略**。
- 存在 `think` 文件或 `composer.json` 中含有 `"topthink/framework"`：**采用 ThinkPHP 解析策略**。
- 无上述特征，大量直接暴露的 `.php` 文件，且包含 `$_GET`, `$_POST`, `$_REQUEST`：**采用原生 PHP 解析策略**。

---

## 2. 现代框架路由解析

### A. Laravel提取方法
Laravel使用高度结构化的路由和请求验证机制，必须准确追踪：
1. **路由定义文件**：重点扫描 `routes/web.php` 和 `routes/api.php`。
   - 解析 `Route::get()`, `Route::post()`, `Route::any()` 等声明，提取 `url_path` 与 `http_method`。
   - 注意 `Route::group()` 或 `Route::controller()` 带来的**路径前缀（Prefix）与中间件（Middleware）级联**。
2. **控制器与动作谓词**：通过路由定义（如 `[OrderController::class, 'audit']`）追踪到具体的控制器类与方法。`action_predicate` 即为该方法名。
3. **参数与类型约束**：
   - 追踪控制器方法中的依赖注入（如 `public function audit(AuditRequest $request)`）。
   - 深入审查对应的 `FormRequest` 类（如 `AuditRequest.php`）中的 `rules()` 方法。
   - 将 `required`, `integer`, `boolean`, `in:APPROVED,REJECTED`, `exists:orders,id` 等验证规则，严格填写到输出规范的 `constraints` 字段。

### B. ThinkPHP提取方法
ThinkPHP其路由兼具配置化与自动映射特性：
1. **路由定义**：扫描 `route/` 目录下的 `.php` 文件（通常为 `route.php` 或 `app.php`）。
   - 解析 `Route::get()`, `Route::post()`, `Route::rule()`，提取明确声明的路由。
2. **自动路由（Pathinfo 模式）**：TP 默认支持按目录结构访问（如 `/index.php/模块/控制器/操作`）。如果在 `config/app.php` 中未关闭自动路由，需遍历 `app/` 目录下的所有控制器（Controller），将其公共方法（Public Methods）自动映射为端点。
3. **参数验证**：
   - 追踪控制器中使用的 `validate()` 助手函数或专用的验证器类（Validator，通常位于 `app/validate/`）。
   - 提取 `require`, `number`, `in`, `gt:0` 等强类型规则。

---

## 3. 原生PHP/混合系统解析

原生PHP缺乏统一的路由文件，页面即端点，参数获取高度散乱。对此必须采用**“文件级与全局变量级”**的双重扫描策略：

1. **入口端点识别**：
   - 将暴露在 Web 根目录（通常为 `public/`, `html/`, 或根目录）下的每一个 `.php` 文件视为一个潜在的 API 入口（例如 `/api/create_order.php`）。
2. **动作谓词提取**：
   - 由于没有明确的控制器方法，提取该文件执行的核心业务逻辑（通常在 `include/require` 依赖加载后，数据库操作前的业务判断注释或核心函数调用）作为 `action_predicate`。若存在类似 `if ($_GET['action'] == 'audit')` 的分发逻辑，需将 `action=audit` 视为端点的一部分进行分离。
3. **输入参数与松散约束提取**：
   - 全局搜索该文件内对超全局变量的使用：`$_GET`, `$_POST`, `$_REQUEST`, `$_FILES`。被获取的键名即为参数名。
   - **类型推断**：由于原生 PHP 是弱类型，必须追踪对参数的后续处理以推断隐式类型约束。例如：
     - 若经过 `intval($_GET['id'])` 或 `(int)$_GET['id']` 处理，提取 `type: "integer"`。
     - 若经过 `in_array($_POST['status'], [0, 1])` 判断，提取 `type: "enum", constraints: "[0, 1]"`。
     - 若直接用于 SQL 拼接且未做处理，标记 `type: "string", constraints: "None"`。

---

## 4. CRUD语义判断与标记

在确定了端点及其控制器/处理逻辑后，必须对操作的真实业务意图进行准确提取与分类。请审查对应逻辑内的数据库操作层（如 Eloquent ORM、DB Facade 或原生 PDO 语句），并依据以下规则进行 `operation_category` 的强制标记：

- **`CREATE`（资源创建）**：若包含 `create()`, `insert()`, `save()`（新建模式）或原生的 `INSERT INTO` 语句，必须将该端点标记为 `CREATE`。
- **`READ`（资源读取）**：若仅包含 `get()`, `find()`, `all()`, `select()` 或原生的 `SELECT` 语句，且无任何后续的状态修改，标记为 `READ`。
- **`UPDATE`（资源更新）**：若包含 `update()`, `save()`（更新模式）, `decrement()`, `increment()` 或原生的 `UPDATE` 语句，标记为 `UPDATE`。
- **`DELETE`（资源销毁）**：若包含 `delete()`, `destroy()`, `forceDelete()` 或原生的 `DELETE FROM` 语句，标记为 `DELETE`。注意区分软删除（Soft Delete，通常体现为执行 `UPDATE deleted_at`），在业务语义上仍应标记为 `DELETE`。

**【注意】**：若同一端点内包含多种操作（如先 `SELECT` 校验状态，再 `UPDATE` 修改数据），请以**产生实质性数据变更的最终写操作（CREATE/UPDATE/DELETE）**作为该接口的最高优先级分类标记。
