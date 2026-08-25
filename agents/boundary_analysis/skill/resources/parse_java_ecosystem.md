# Java Web Ecosystem API Endpoint Extraction Guide

在解析Java Web项目时，你需要超越单一的Spring Boot认知，严格按照以下基于“抽象语法树与数据流”的四维映射规则进行攻击面拓扑提取：

## 1. 多范式路由提取
Java Web 的入口定义不仅存在于现代注解中，还可能在传统配置文件中。你必须全面扫描以下五大常见框架的路由模式，并注意类级别与方法级别路径的拼接：
- **Spring 家族**：提取 `@RestController`, `@RequestMapping`, `@PostMapping`, `@GetMapping` 等注解。
- **JAX-RS (Javax-standard REST)**：提取 `@Path` (类/方法级) 结合 `@GET`, `@POST`, `@PUT`, `@DELETE`。
- **Struts2 框架**：解析 `struts.xml` 中的 `<action name="... ">` 标签，或扫描 `@Action`, `@Namespace` 注解。
- **原生 Servlet**：提取类头部的 `@WebServlet(urlPatterns="/...")` 注解，或解析 `WEB-INF/web.xml` 中的 `<servlet-mapping>`。
- **JSP 页面**：直接暴露于 Web 目录下的 `.jsp` 文件也应视作隐式路由入口。

## 2. 业务动作谓词归一化
`action_predicate` 应当反映该接口真实的业务意图，提取逻辑如下：
- 优先提取对应的方法名（如 `public Response auditOrder(...)` 提取为 `auditOrder`）。
- 若为 Struts2，提取 `<action>` 标签的 `method` 属性或默认的 `execute`。
- 将提取到的动词归一化为标准的 CRUD 语义（如 `add/insert/create` 统一标记为 `CREATE`）。

## 3. 参数源解析
【核心痛点】：Java 应用获取输入的方式高度异构。你更加实际情况使用以下两种方式来最终参数规范：
- **轨道 A：数据绑定参数**
  - 提取直接绑定在方法签名上的参数。
  - Spring：`@PathVariable` -> `in: path`, `@RequestParam` -> `in: query`, `@RequestBody` -> `in: body`。
  - JAX-RS：`@PathParam`, `@QueryParam`, `@FormParam`。
  - **深度解析**：若参数为复杂 Java Bean/DTO，必须追踪至该 Class 定义，基于 Java Bean 规范（Getter/Setter 或直接属性）提取全量嵌套字段。
- **轨道 B：运行时动态获取参数**
  - 必须扫描方法体内部的命令式调用。
  - 捕获 `HttpServletRequest.getParameter("key")` -> 映射为 `in: query/form`。
  - 捕获针对 JSON 对象的动态键值提取，如 `jsonObj.getString("target_id")` -> 映射为隐式 Body 参数。

## 4. 多维强约束与语义规则提取
【终极目标】：不仅要找参数，必须找出后端是如何对这些参数进行类型校验。你需要结合声明式与命令式代码，准确填写接口的 `constraints` 字段：
- **声明式类型与约束**：
  - 捕获 DTO/Entity 类上的 `javax.validation` 或 `jakarta.validation` 注解（如 `@NotNull`, `@Min`, `@Max`, `@Email`, `@Pattern`）。
  - 提取 Java 强类型定义（如 `Long`, `Boolean`, 或者是特定的 `Enum` 枚举类，必须枚举出所有合法值）。
- **命令式结构与值约束**：
  - **结构约束**：若方法内调用了 `JSON.parseObject(req, SysDept.class)`，推断输入必须是严格匹配 `SysDept` 结构的 JSON。
  - **类型转换约束**：捕获 `Integer.parseInt(req_id)` 或 `Long.valueOf()`，推断参数在运行时被强转，若输入非数字会导致 500/400 错误。
  - **值校验约束**：捕获如 `if ("open".equals(dept.getStatus()))`，将此硬编码条件作为该参数的绝对前置约束。
