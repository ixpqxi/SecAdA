# 水平越权(BOLA/IDOR)与资源属主理论模型

在推断操作私有资源的理论鉴权需求时，必须遵循以下强制规则：

1. **直接属主校验规则**：
   - 对于 `UPDATE/DELETE /api/resource/{id}`。
   - **理论要求**：数据库查询必须具备双条件 `WHERE id = {id} AND owner_id = {current_user.id}`。仅查询 ID 是绝对不安全的。
2. **父子资源强绑定规则**：
   - 对于嵌套路由 `POST /api/project/{pid}/task/{tid}/delete`。
   - **理论要求**：不能仅校验用户是否有权操作 `tid`。必须验证：
     1. `tid` 确实属于 `pid`（防越界挂载）。
     2. `current_user` 是 `pid` 的所有者或管理员。
3. **状态敏感操作的权限收敛**：
   - 若操作引发核心状态变更（如 `approve_refund`），即使操作者是资源拥有者，也可能需要提升至系统级 RBAC 校验。属主校验不能替代状态扭转的权限校验。
