# Laravel 框架实际鉴权逻辑提取指南

在审查 Laravel 项目时，真正的资源层鉴权通常不在Controller的业务代码中，必须追踪以下特征：

1. **路由级中间件 (Middleware)**：
   - 检查路由定义是否有 `->middleware('can:update,post')`。如果有，说明存在基于Policy的鉴权。
2. **控制器授权方法 (Controller Helpers)**：
   - 检索 Controller 方法内是否调用了 `$this->authorize('delete', $order);`。
   - 检索是否调用了 Gate Facade：`Gate::allows('update', $post)`。
3. **表单验证器中的授权 (FormRequest)**：
   - 追踪 Controller 注入的 `XxxRequest` 类，审查其 `authorize()` 方法。如果返回 `true`，则说明此处未做细粒度鉴权。
4. **模型观察者与全局作用域 (Global Scopes)**：
   - 检查查询时是否启用了 `where('user_id', Auth::id())` 的强制拼接。
