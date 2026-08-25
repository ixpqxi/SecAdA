# 垂直越权 (BFLA) 与基于角色的访问控制理论模型

在分析端点是否可能存在垂直越权（BFLA）即低权限越权访问高权限功能的风险时，请依据以下模型规则进行严格的理论需求推断：

## 1. 角色等级体系重构
在推断前，必须依据项目的常识或代码中的枚举（如`UserRole`），在心中构建一个层级梯队：
- **Level 0 (Unauthenticated)**：未登录访客（Guest）。
- **Level 1 (Authenticated/User)**：已登录普通用户、会员。
- **Level 2 (Manager/Editor)**：版主、运营、部门主管（具有部分特权，但不能操作其他用户）。
- **Level 3 (Admin/SuperAdmin)**：系统管理员、超级管理员（最高权限）。

## 2. 核心功能级访问控制推断规则
遇到以下特征的端点时，其理论鉴权需求必须被推断为需要较高等级（Level 2+ 或 Level 3）：

- **A. 用户与权限管理类**：
  - 接口特征：`create_user`, `ban_user`, `reset_password` (非自身), `assign_role`, `grant_permission`。
  - 理论需求：**必须校验 Level 3 (Admin)**。任何人不得越权操作系统级的身份标识。
- **B. 平台核心资产/状态干预类**：
  - 接口特征：`approve_order`, `refund`, `publish_global_notice`, `verify_kyc`。
  - 理论需求：此类操作涉及业务核心链路的流转，虽然是对普通用户产生的数据进行操作，但动作本身属于**平台方（Level 2+ 运营/管理人员）**。绝不能仅校验属主，必须执行严格的RBAC角色拦截。
- **C. 敏感数据与统计导出类**：
  - 接口特征：`get_financial_report`, `export_user_data`, `system_logs`。
  - 理论需求：即使是读操作，由于涉及平台全局敏感数据，必须推断为**Level 3 (Admin)**专属。

## 3. 垂直越权推断的防误报铁律
- **自我管理豁免**：如果动作是 `update_profile` 或 `change_password` 且操作的目标 ID 是当前 Session 的用户本人，这不是管理功能，只需 Level 1 结合属主校验（归属于 BOLA/IDOR 模型）。请务必精准区分！
- **鉴权底线描述**：在输出理论鉴权需求时，必须明确指出：不仅需要验证用户已登录，还必须在网关、路由层或 Controller 顶层显式校验当前用户的 Role 是否包含 `ADMIN` 或具备相应的特权标识。
