# rsp42 ← esim42 对接改造清单（反向差距分析）

> 输入：`../esim42/PLAN.md`（eSIM 综合运营平台规划，模块 A–E）与 `../esim42/todo/02-rsp42-api-gap-analysis.md` 的预期产出。
> 本文只回答一件事：**站在 rsp42 的角度，为了支撑 esim42，需要改什么、不需要改什么、以及接口契约长什么样**。
> 图例：`[P0]` 阻塞（不改则 esim42 无法安全/正确上线）；`[P1]` 重要（影响功能完整性或可运维性）；`[P2]` 可选/后续。
> 现状判定均以本仓库**当前代码**为准（附 `文件:行`）。

---

## 0. 结论摘要

### 0.1 边界原则与部署前提（先划边界，再列改动）

1. **rsp42 是 RSP 层（SM-DP+/SM-DS），不是 BSS 层。** 用户、账号、OAuth、运营商业务、商城、可见性、审批流、前端一律属于 esim42；rsp42 只多认一样东西：**租户（tenant/carrier）归属**，因为资源隔离、审计归属与配额必须落在持有资源的进程里。
2. **esim42 不需要新引入 SAIP 编解码栈。** rsp42 已有 Go 版 SAIP 解析/编码与个性化引擎（`internal/saip`、`internal/saip/personalization`）。正确做法是 rsp42 把模板能力（schema / validate / render / clone）以管理 API 外露，esim42 前端只做表单与编辑器 —— 这直接消解 `PLAN.md` §4.1 的“Go 主干 + Python 编解码微服务”选型风险，并满足“严禁造轮子”。
3. **订单生命周期走标准 ES2+，非标准的管理动作走 Admin API。** esim42 用 ES2+（mTLS）做 downloadOrder/confirmOrder/releaseProfile/cancelOrder，用 `/admin/api/v1` 做库存、模板、池、审计、看板。因此 **ES2+ 也必须具备租户归属、模板绑定、幂等与外部引用能力**，否则 esim42 只能退回“全部走 Admin API”或“一个运营商一套 rsp42 实例”。
4. **部署前提（已与 esim42 确认）：管理 API 保持无鉴权。** esim42 后端与 rsp42 管理 API **同机同网、内网直连**；esim42 前端只经 esim42 后端访问，绝不直连 rsp42。因此管理 API 不引入 Bearer/mTLS/scope，**安全边界由 esim42 承担**（esim42 必须保证该 API 不被反向代理、网关或前端暴露）。原初稿的 G1“管理 API 鉴权”据此**排除**，正式改动清单从 G2 起。
5. **SM-DS 启用（决策 6）**：esim42 走 ES12 事件注册/删除并以 `/events` 做透视，支撑模块 B 的“无激活码推送”。rsp42 需同时部署 `smds` 角色（`RSP42_ROLE=smds`），并补齐事件的时间/租户过滤与注册失败可观测（G20）。
6. **明确不做（决策 7–10，见 §8.4）**：**PostgreSQL/其他数据库后端**、**多副本部署**、**每运营商客户端证书**、**rsp42 侧限流/429**。这四项不在本项目范围内，也不是“以后再说”的备选项——相关配置与文档已按“仅支持当前形态”收敛。

### 0.2 必改项 Top 7

| # | 改动 | 对应 esim42 需求 | 优先级 |
|---|---|---|---|
| G2 | 租户维度贯穿 `upp_templates / profiles / iccid_pool / iccid_ranges / batches / personalization / audit_log` | §2.1 多租户、模块 C/D | **P0** |
| G3 | 模板/产品选择走标准 `profileType`（不再只靠 eUICC 版本 + 全局默认） | §3C“可视化模板创建/多运营商” | **P0** |
| G4 | 下载时回写 `profile.eid`（匿名领取无 EID，安装后无法设备归属） | 模块 B“我的 eSIM/设备” | **P0** |
| G5 | 幂等：实现 Table 24 NOTE 优雅重发 + （按需）`Idempotency-Key` HTTP 头 | 模块 A/B 一键领取、模块 C 看板 | **P0** |
| G6 | ICCID/IMSI 池：租户隔离、预留 TTL、失败回滚、与个性化解耦（凭据池） | §4.3 资源池管理 | **P0/P1** |
| G7 | SAIP 模板能力外露（`/schema`、`/validate`、`/render`、`/clone`、全局模板提升） | §3C/§3D、§4.1/§4.2 | P1 |
| G8 | 审计 `actor` 语义修复 + 租户维度 + 统计/看板接口 | 模块 C/D/E 审计透视 | P1 |

### 0.3 明确“不需要做”的部分（避免把 BSS 逻辑渗进 RSP 层）

| esim42 侧需求 | 归属 | 说明 |
|---|---|---|
| 用户/角色/配额 M（用户可激活上限） | esim42 | SGP.22 无“用户”概念（rsp42 只维护 Profile 库存/订单/安装状态，见 `TODO.md` §1） |
| OAuth 适配器、`dn42.active_mnt` 映射 | esim42 | rsp42 不引入身份体系 |
| Profile 市场可见性、匿名开关、Brand/Logo/APN 指引 | esim42 | 业务属性；rsp42 只提供 `tenant_id` 与稳定模板标识 |
| 运营商提交审批流（下发前人工审批） | esim42 | rsp42 现有语义已够：`Confirmed` 不参与下载，必须显式 `ReleaseProfile`（`service/cmae.go:197-201`，T6） |
| 用户名额扣减/回滚 | esim42 | 由 esim42 编排 `downloadOrder`/`cancelOrder`；rsp42 只保证幂等与状态机 |
| 二维码渲染/发送（短信、邮件） | esim42 | rsp42 返回 `activationCode`/`qrContent` 字符串即可（`api/admin/profiles.go:288-305`） |
| ICCID/IMSI/K/OPc 的**权威**数据管理与订户绑定 | esim42 | rsp42 只做**存储 + 校验 + 分配**（见 `TODO.md` §1） |

---

## 1. 阻塞级缺口 [P0]

> 编号沿用初稿：**G1（管理 API 鉴权）已按部署前提排除**，见 §0.1-4。

### G2. 租户（运营商）维度贯穿资源与审计

**需求**：`PLAN.md` §2.1 运营商配额、管理员“切换运营商上下文”、模块 C “名下 Profile 的领取用户列表/激活状态/消耗趋势”、模块 D “全站透视”。这些的前提是 rsp42 的资源能按运营商切分。

**现状**：全仓库无任何 `carrier`/`tenant`/`owner` 概念（`grep -rin` 无命中）。具体表现：
- `upp_templates.name` **全局唯一**（`internal/store/migrations/00003_upp_templates.sql:8`）→ 两个运营商不能各自有一个叫 `default` 的模板。
- `iccid_pool` 无归属，`Reserve` 取**全池最小可用号**（`internal/store/pool.go:107-126`）→ 多运营商时 A 运营商会领到 B 的号段。
- `profiles` 无归属（`00001_init.sql:6-27`），列表过滤只有 `state/eid/iccid/q/batch`（`internal/store/profile.go:125-131`），无“按运营商”维度。
- `audit_log` 无归属（`00001_init.sql:87-97`），审计无法按租户透视。
- `download_batches`、`personalization` 同样无归属（`00005`、`00004`）。

**建议改动**（最小侵入方案）：
- 新增表：

  ```sql
  CREATE TABLE tenants (
      id           TEXT PRIMARY KEY,          -- 直接复用 esim42 的 Carrier 主键（已定，见 §8-1）
      name         TEXT NOT NULL,
      status       TEXT NOT NULL DEFAULT 'active',
      template_quota INTEGER,                 -- NULL = 不限；对应 §3D “运营商 Profile 配额 N”
      profile_quota  INTEGER,
      created_at   INTEGER NOT NULL,
      updated_at   INTEGER NOT NULL
  );
  ```
- 归属列（`TEXT REFERENCES tenants(id)`，**`NULL` 表示平台全局**，正好承载模块 D 的“全局系统模板”）：
  `upp_templates.tenant_id`、`profiles.tenant_id`、`iccid_ranges.tenant_id`、`iccid_pool.tenant_id`、
  `download_batches.tenant_id`、`personalization.tenant_id`、`audit_log.tenant_id`。
- 唯一约束调整：`upp_templates` 改为 `UNIQUE(tenant_id, name)`（SQLite 中 `NULL` 不参与唯一性比较，正好允许“全局模板名”与“租户模板名”互不冲突）。
- **ES2+ 调用方 → 租户（决策 3，已定）**：以标准的 `header.functionRequesterIdentifier`（SGP.22 §6.5.1.3：type string，“identification of the function requester”，**无格式约束**）解析租户。新增配置
  `smdpp.es2p.requester_tenants: [{ requester: "<functionRequesterIdentifier>", tenant: "carrier-a" }]`。
  未映射时回落租户 `""`（平台默认）并在审计记 `unmapped`。**不新增 JSON body 字段**（依据见 §8.2）；**不采用每运营商客户端证书**（见 §8.3）。
  越权状态码用规范自带值：ICCID → `8.2.1/1.2`，Profile Type/模板 → `8.2.5/1.2`。
  配套：`internal/api/es2plus/clientlib.go` 目前把 `RequesterID` 设在 `Client` 上（`clientlib.go:20-30`，`Call` 读 `c.RequesterID`），esim42 要按运营商切换该值时，要么每运营商一个 `Client` 实例，要么给库加“按调用传入 requester”的入口（推荐后者，避免并发下改字段）。
- Admin API：所有列表/写接口接受并校验 `tenant` 参数；`Handler` 增加 `Tenants *store.TenantRepo`。
- 审计：ES2+ 与 Admin 写入均带 `tenant_id`；`GET /audit` 增加 `tenant` 过滤。
- 管理员“切换运营商上下文”= esim42 后端以 `?tenant=X` 调用管理 API 即可（无鉴权，主体由 esim42 自行约束，见 §0.1-4），rsp42 不需要“模拟登录”概念。

**验收**：租户 A 的模板名与租户 B 同名可共存；A 的池预留永不返回 B 的号段；`GET /profiles?tenant=a` 只返回 A；`GET /audit?tenant=a` 只返回 A 的动作。

---

### G3. 模板/产品必须能由订单选择（多运营商模板选择）

**需求**：`PLAN.md` §3C 每个运营商有自己的 Profile 模板（上传 SAIP 或 Web 创建）；`§4.2` 个性化后生成。下载时 rsp42 必须用**该订单所属运营商的模板**。

**现状**：模板解析顺序是 `profile.UPPTemplate → session.UPPTemplate → DefaultUPP → Any()`（`internal/service/download.go:227-250`），而 `session.UPPTemplate` 由 **eUICC 广播的 SAIP 版本**挑选（`internal/service/download.go:209-222` + `internal/service/cmae.go:161-171`）。问题：
- `ES2+.DownloadOrder` 请求体**没有模板字段**（`internal/api/es2plus/handlers.go:59-67`）。
- Admin `createProfileReq` **也没有模板字段**（`internal/api/admin/profiles.go:95-101`），只能建完之后 PATCH（`profiles.go:128-134`）。
- 结果：多个运营商 + 相同 SAIP 版本时，所有人拿到同一个模板（`Any()`/版本命中的那个），**这是阻塞性功能缺口**。

**建议改动**（**不新增 ES2+ JSON body 字段**，见 §8.2 与 §6 的规范依据）：
- **模板/产品选择走标准 `profileType`**：SGP.22 §6.5.2.1 的 JSON schema 明确该字段是 “content free information defined by the Operator”，Table 22 的 NOTE 进一步说明“Operator 可给出 ICCID 和/或 Profile Type，给出 Profile Type 时 SM-DP+ 可自由选择匹配该 Type 的 Profile”——这正是“租户+模板”选择器的规范落点。约定 rsp42 解释 `profileType` 为租户内的模板选择器（如 `"<tenant>/<template>"`）；无法解析 → `8.2.5/3.9`（Profile Type Unknown）。
- 归属校验用规范自带的状态码：
  - 越权使用他人 ICCID → `8.2.1/1.2`（Profile ICCID Not Allowed (Authorisation)，已有 `rsp.CodeInputRefused`）；
  - 越权使用他人 Profile Type/模板 → `8.2.5/1.2`（Profile Type Not Allowed (Authorisation)，**需新增 `CodeProfileTypeNotAllowed`**）。
- Admin `createProfileReq` 增加 `uppTemplate` / `externalRef` / `tenant`（管理 API 是自有协议，不受 SGP.22 约束，可直接用结构化字段）。
- `Inventory.Allocate` 增加 `uppTemplate`/`tenant`/`externalRef` 参数并落库。
- `loadUPP` 优先级明确为：`profile.UPPTemplate`（订单指定）→ `session.UPPTemplate`（eUICC 版本兼容）→ 租户默认 → 全局默认 → 报错（**移除 `Any()` 兜底**，否则会静默下发错误模板）。
- 新增租户默认模板配置：`tenants.default_upp`（替代全局 `profiles.default_upp` 对多租户的不足，`config/config.example.yaml:129-134`）。

**验收**：两个租户各自绑定不同模板，分别下单下载，StoreMetadata/BPP 中的 ProfileElement 与各自模板一致；指定他人模板失败。

---

### G4. 下载时把实际 EID 回写到 Profile

**需求**：`PLAN.md` 模块 A/B：匿名一键领取时**没有 EID**；用户装到手机上后，esim42 需要知道“哪个用户的哪个设备安装了这张 eSIM”（设备列表、二次确认、防重复领取、看板按 EID 统计）。

**现状**：
- `profile.eid` 只在 `confirmOrder` 请求带 EID 时写入（`internal/api/es2plus/handlers.go:143-145`），或 Admin PATCH 写（`profiles.go:147-149`）。
- `AuthenticateClient` 拿到 eUICC 证书里的 EID 后，只写了 `sess.EID = ca.EID`（`internal/service/cmae.go:161`），**从不回写 `profile.EID`**；`GetBoundProfilePackage` 也只改 `state`/`error_reason`（`internal/service/download.go:90-97`）。
- 连带症状：归属检查 `if p.EID != "" && p.EID != eid`（`internal/service/cmae.go:194-196`）对匿名 Profile 永远放行 —— 同一激活码可被多台设备同时下载；`registerDownloadAttempt` 的回调里 EID 为空（`internal/service/cmae.go:213-225`），esim42 收到的进度通知缺 EID。

**建议改动**：
- `AuthenticateClient` 在 `lookupProfile` 成功后：若 `profile.EID == ""` 则写 `profile.EID = ca.EID`；否则保持原校验。
- 状态迁移：`Allocated → Linked` 或直接保持 `Allocated`（SGP.22 §3.1.6 对无 EID 订单的绑定语义），至少保证 `eid` 列可用、`GET /profiles?eid=` 能命中。
- 回调载荷带 `eid`（现有 `ProgressInfo` 已含 EID，修好回写即自动生效，`internal/api/es2plus/callback.go:90-102`）。
- 可选加固（P1）：`DownloadOrder`/claim 时支持 `eidLock: true` 语义——首次 `AuthenticateClient` 即锁定 EID，之后异 EID 一律拒绝（现在只在“订单已带 EID”时生效）。

**验收**：匿名领取（无 EID）→ LPA 下载 → `GET /profiles/{iccid}` 的 `eid` 等于该 eUICC 的 EID；用另一个 EID 重复下载被拒。

---

### G5. 幂等与业务关联

**需求**：`PLAN.md` 模块 A “自助一键领取”（高并发、用户重试、浏览器刷新）、模块 B “申领历史”、模块 C “名下 Profile 的领取用户列表”。esim42 必须能把自己的 `ProfileInstance`/`Order` 与 rsp42 的资源稳定对应，且重试不能重复扣号。

**现状**：
- `profiles` 无外部引用列（`00001_init.sql:6-27`）；查询只能靠 ICCID/MatchingID/EID（`store/profile.go:125-131`）。
- 无任何幂等实现（`grep -i idempot` 仅有注释）；`middleware.CORS` 已把 `Idempotency-Key` 列入 `Access-Control-Allow-Headers`（`internal/api/middleware/middleware.go:90`）但**没有代码读取它**。
- 重复 `downloadOrder` 会各扣一个 ICCID：`Inventory.Allocate` 在指定 ICCID 已存在时返回 `Profiles.Create` 的冲突错误（`internal/service/inventory.go:44-60`），最终应答 `8.2.1/3.8` **Failed**。而 SGP.22 Table 24 的 NOTE 规定：若 Profile 已处于 `Linked`/`Allocated` 且本次调用结果相同，**MAY 返回 Executed-Success 且不做其他动作**（“This allows graceful handling of resends in case a response on ES2+ gets lost”）。**当前实现与规范相反**，esim42 的响应丢失重试会直接被判失败。
- `matching_id` 在 `confirmOrder` 由 rsp42 生成 `MATCH-<16hex>`（`internal/api/es2plus/handlers.go:146-149`），虽可传入，但重放无保证。

**建议改动**（优先用规范自带机制，少造轮子）：
- **实现 Table 24 NOTE 的优雅重发**：`downloadOrder` 收到已存在的 ICCID 且其状态为 `Allocated`/`Linked` 且 `eid`/`profileType` 一致时，返回 `Executed-Success` + 该 ICCID，不新建、不重复扣池。这条单独就能覆盖 esim42“响应丢失后重试”的主场景，且 **esim42 应把 ICCID 显式传给 downloadOrder**（ICCID 由 esim42 侧号池或 Admin 预留提供，见 G6），这样重发天然可判定。
- **`Idempotency-Key` 用 HTTP 头**：SGP.22 §6.2 明确 “HTTP POST request and response MAY contain additional header fields. Their use is out of scope of this specification.” —— 即**自定义 HTTP 头是规范显式允许的**（与 JSON body 成员不同，见 §8.2）。因此幂等键走上表头，无需动 body。
  - 仅覆盖标准未定义重发语义的接口（`confirmOrder`/`releaseProfile`/`cancelOrder`）与 Admin 的 `POST /profiles`、`/batches`：
    ```sql
    CREATE TABLE idempotency (
        key           TEXT NOT NULL,
        endpoint      TEXT NOT NULL,
        tenant_id     TEXT,
        request_hash  TEXT NOT NULL,
        status        INTEGER NOT NULL,
        response_json TEXT,
        created_at    INTEGER NOT NULL,
        PRIMARY KEY (key, endpoint)
    );
    ```
  - 语义：同 key + 同 endpoint + 同 request_hash → 回放首次响应；同 key 不同 hash → 409。
- **业务关联不需要上 ES2+ 线**：`downloadOrder` 已经返回 `iccid`，esim42 用 ICCID 作为自己订单表的外键即可。`profiles.external_ref` 仅作为 **Admin API 的便利字段**（`GET /profiles?externalRef=`），不进入 ES2+ 请求体。
- `matching_id`：约定 esim42 显式传入可追溯 ID（现已支持），避免重发时生成新值。

**验收**：同 `Idempotency-Key` 连调两次不产生重复资源；不带幂等键、用同一 ICCID 重复 `downloadOrder` 返回 `Executed-Success` 且池只扣一次；`profiles.external_ref` 可反查。

---

### G6. 号码/凭据池：租户隔离、预留 TTL、失败回滚、与个性化解耦

**需求**：`PLAN.md` §4.3：运营商批量导入 ICCID/IMSI 池、锁机制、防高并发重复分配、状态回滚。

**现状**：
- `iccid_pool` 无租户、无预留过期、无业务引用列（`00006_iccid_pool.sql:9-19`）。
- `PoolRepo.Reserve` 是 `BEGIN`（deferred）下的 **read-then-update**（`internal/store/pool.go:107-126`）——并发下会 `database is locked`（busy_timeout 5s，`config:137`）或读同一行后第二个事务覆盖失败。
- **泄漏**：`Inventory.Allocate` 先 `Pool.Reserve`，若随后 `Profiles.Create` 失败，不释放池条目（`internal/service/inventory.go:63-72`）。
- **不回收**：`Cancel`/delete Profile 不回池（`internal/service/order.go:141-147` 完全不碰 Pool），`iccid_pool.state` 永久停在 `allocated`。
- **无 IMSI 池**：IMSI 只由全局前缀生成占位（`config:141` `imsi_pool_prefix`，`inventory.go:65` `IMSI: inv.IMSI`）。
- **个性化解耦缺失**：`personalization` 以 `iccid` 为主键（`00004_personalization.sql:8`），解析只能按 ICCID（`internal/service/personalization.go:41-50`）。而运营商批量导入的通常是 `IMSI + K + OPc`（ICCID 下发时才分配），当前流程被迫“先建 Profile 占号 → 再导入个性化”，与 §4.3 的自然流程相反。

**建议改动**：
- 池条目扩展：`tenant_id`、`reserved_until`、`reference`（esim42 订单/申领 ID）、`profile_id`（回滚用）。
- `Reserve(tenant, eid, reference) (iccid, error)`：限定租户范围；使用 `BEGIN IMMEDIATE`；TTL 默认 24h。
- 后台 GC（已有 ticker，见 `internal/cli/smdpp.go`/`server.go`）增加“超时预留 → 回 available + 审计”。
- `Inventory.Allocate` 失败路径 `defer` 回滚；`OrderService.Cancel`/`DeleteProfile` 按策略回池（`Available` 回池、`Unavailable` 转 `blocked`）。
- **凭据池**（P1）：`personalization` 改为 `id INTEGER PK` + `tenant_id` + 可空 `iccid` + `UNIQUE(tenant_id, imsi)`；`Resolve` 先按 ICCID，未命中再按 `profile.imsi` 找凭据；新增 `POST /personalization/pool/import`（无 ICCID 导入）与 `POST /iccid-pool/reserve` 返回成对 `{iccid, imsi}`。
- IMSI 池：新增 `imsi_ranges`/`imsi_pool`（结构同 ICCID），或在 `iccid_pool` 上增加 `imsi` 列做“号卡对”导入（更贴近运营商实际数据）。

**验收**：两租户各自导入号段，各自只领到自己的号；并发 200 次领号无重复、无锁错误；取消的 Profile 的 ICCID 可被再次领取；只导入 `IMSI+K/OPc` 也能完成一次完整下载。

---

## 2. 重要缺口 [P1]

### G7. 把 SAIP 模板能力外露给 esim42（替代 Python 微服务）

**需求**：`PLAN.md` §3C（上传 SAIP / Web 可视化创建）、§4.1（编解码选型）、§4.2（个性化参数：ICCID/IMSI/K/OPc/算法/SPN/PLMN）。

**现状**：rsp42 已具备 SAIP 解析/编辑/编码（`internal/saip`，`element.go`/`files.go`/`header.go`）与个性化引擎（`internal/saip/personalization/personalization.go:60-124`），但管理 API 只暴露只读视图：`GET /upp/{name}/decoded`（`internal/api/admin/admin.go:69`，`internal/api/admin/upp_decoded.go`）。

**建议新增端点**：

| 端点 | 作用 |
|---|---|
| `GET /upp/{name}/schema` | 返回可个性化字段清单：`iccid, imsi, k, opc, algorithm, spn, pin1, puk1, adm1, adm2, plmn[]`，含类型/必填/长度约束——esim42 前端据此渲染动态表单 |
| `POST /upp/validate` | 上传 SAIP 二进制 → 返回 SAIP 版本、ProfileElement 摘要、header/GFSTE 一致性校验结果、SHA-256（模块 C “直接上传 TCA SAIP 文件”） |
| `POST /upp/render`（或 `POST /profiles/preview`） | dry-run：给定 `uppTemplate + personalization` → 返回渲染后的 ICCID/IMSI/元素列表/字节长度/SHA-256，**不分配 ICCID、不落库**（前端预览与运营审核） |
| `POST /upp/{name}/clone` | 从全局模板派生租户模板；
| `POST /upp/{name}/promote` | 租户模板提升为全局（`tenant_id=NULL`），对应模块 D “提升为全局系统模板” |

**同时需要补齐的个性化字段**（`internal/saip/personalization/personalization.go:13-28` 目前只有 `ICCID/IMSI/K/OPc/Algorithm/PIN1/PUK1/ADM1/ADM2/SPN` + Milenage/TUAK 常量）：
- **PLMN 列表**（`EF.PLMNwAcT`/`EF.HPLMNwAcT` 或 SAIP 对应 PE）——`PLAN.md` §4.2 明确点名。
- MSISDN（可选）、`EF.ACC`、运营商自定义文件覆盖（`PE-File` 级 patch），否则“Web 可视化编辑”只能改固定几个字段。

> **已定**：K/OPc/KCV 由 **esim42 生成**，rsp42 只负责存储与注入，**不提供密钥生成/派生端点**（见 §8-4）。因此 `/schema` 只描述字段，`/render` 只接收调用方传入的密钥。

### G8. 审计与看板透视

**需求**：模块 C “领取用户列表/激活状态/消耗趋势”、模块 D “平台级审计日志”、模块 E “RSP 审计透视”。

**现状**：
- `middleware.Audit` 的 `Actor` 取的是 **`X-Request-ID`**（`internal/api/middleware/middleware.go:163-170`），语义错误；ES2+/ES9+ 的审计主体应当是 mTLS 主体或 `header.functionRequesterIdentifier`。
- 审计中间件只包了 es9p/es2p（`internal/cli/smdpp.go:153-169`），admin 路由靠 handler 手工写（`internal/api/admin/admin.go:142-156`），漏写路径（如 `GET /personalization/export`）无审计。
- `audit_log` 无 `tenant_id`（`00001_init.sql:87-97`）。
- 无聚合接口：`profiles` 列表无时间范围过滤（`store/profile.go:125-131`），无按日/按租户的统计端点；`/profiles/{iccid}/timeline` 只合并 order + notification（`admin/profiles.go:249-286`），不含 session/审计。

**建议改动**：
- 修 `Actor`：ES2+/ES12 优先取 `r.TLS.PeerCertificates[0].Subject`，其次请求体 `functionRequesterIdentifier`；管理 API（内网、无鉴权）固定记为 `esim42-backend`。
- `audit_log` 增 `tenant_id`；`GET /audit?tenant=` 过滤。
- 新增聚合端点：
  - `GET /profiles/stats?tenant=&from=&to=&groupBy=day|state` → 计数/趋势（模块 C 看板）。
  - `GET /audit/stats?groupBy=function|tenant|day&from=&to=`（模块 D 看板）。
  - `GET /notifications?iccid=&eid=&from=&to=&page=`（当前只能从 timeline 间接取）。
- `profileTimeline` 增加 session 事件与审计事件（下载尝试/CC 失败/过期）。

### G9. 回调（ES2+.HandleDownloadProgressInfo）的租户与关联字段

**需求**：模块 B/C 需要“用户真正下载/安装完成”的实时状态。

**现状**：rsp42 出站回调已经具备可靠投递（先落库再投递 + 退避重试 + 死信，`internal/api/es2plus/callback.go`，`internal/store/callback.go`），载荷为 `{header, eid, iccid, timestamp, notificationPointId, notificationPointStatus}`（`callback.go:90-102`）。缺口：
- 只有**一个全局 URL**（`config:147-156`），无法按租户路由；
- 载荷无 `tenantId` / `externalRef` / `matchingId`，esim42 只能用 ICCID 反查（可行，但把映射耦合在 esim42 侧）；
- `notificationPointId` 的取值集合（1/2/3/4）未在文档中定义。

**建议改动**：
- 载荷增加 `tenantId`、`externalRef`、`matchingId`（向后兼容的增量字段）。
- 支持 `tenants.callback_url` 覆盖全局 URL（P2）；或在 `docs/interfaces.md` 明确“esim42 单入口 + 按 ICCID 反查租户”为约定方案（推荐，改动最小）。
- 在 `docs/interfaces.md` 补 `notificationPointId` 语义表（1=下载尝试失败、2=CC 失败、3=下载成功、4=安装结果）。

### G10. 接口契约：完整 OpenAPI + 稳定错误码

**需求**：esim42 是 Nuxt/TS 前端 + Go 后端（`PLAN.md` §1.3），需要生成客户端 SDK 或至少类型安全的调用；`todo/02` 要求“接口矩阵 + 错误码规范”。

**现状**：`openapi` 是手写的最小 map，参数只用单个 `"query"` 占位（`internal/api/admin/admin.go:173-231`），没有 schema、没有错误模型。Admin 错误体是 `{"error": msg}` + HTTP 状态（`admin.go:119-121`），无稳定错误码；ES2+ 侧已合规（`docs/interfaces.md:55-61`）。

**建议改动**：
- 补全 OpenAPI 3.0（含 request/response schema、错误模型），纳入 CI 校验（与 esim42 的契约漂移检测）。
- Admin API 错误体升级为 `{"code": "profile_not_found", "message": "..."}`，保留 HTTP 状态；错误码表写入文档。
- 明确分页/排序/过滤的通用约定（现有 `page/size/sort` 已可用，需文档化 `sort` 白名单：`created_at|updated_at|iccid|state`，`store/profile.go:133-135`）。

### G11. 可观测性

**现状**：只有 `/healthz`、`/readyz`（`internal/api/router.go:76-87`），无 `/metrics`（`grep -i prometheus` 无命中）。

**建议**：新增 `/metrics`（Prometheus 文本格式）：下载成功/失败按 `tenant`、CC 失败数、回调队列 pending/dead-letter 深度、池可用/已分配/预留过期数、会话过期 GC 数。esim42 的运维看板与告警直接消费。

### G12. 并发与存储

**现状**：SQLite（WAL + `busy_timeout=5000`，`config:137`），单进程假设（GC/ticker 在进程内，`internal/cli/smdpp.go`）。

**建议**：
- 竞争路径（池预留、幂等表、回调队列取任务、`MarkInstalled`）改 `BEGIN IMMEDIATE`，避免 deferred 事务升级锁导致的 `SQLITE_BUSY`。
- 部署形态已确认**同机同网、esim42 单实例访问**（见 §8-5），因此 SQLite 足够。**PostgreSQL/MySQL 等后端与多副本部署明确不做**（§8.4）。`profiles.repository` 仅接受 `sqlite`，其他取值在配置校验阶段直接报错，不再作为“未来扩展位”保留语义。
- **多副本/leader 选举/分布式锁明确不做**：一个数据库文件只由**一个** rsp42 进程持有；横向扩副本不在支持范围内。

### G19. ES2+ 标准一致性修正（重发 / EID 关联 / 状态码）

**需求**：esim42 会按 SGP.22 状态码分支处理（“未找到” vs “无权限” vs “不可用”），且必须能安全地重试 ES2+ 调用。以下为核对 v2.7 后确认的偏离，均直接影响 G2/G4/G5 的落地。

**现状与规范对照**：

| # | 现状（代码） | 规范 | 影响 |
|---|---|---|---|
| a | 指定 ICCID 重复 `downloadOrder` → `Profiles.Create` 冲突 → `8.2.1/3.8` **Failed**（`internal/service/inventory.go:44-60`，`internal/api/es2plus/handlers.go:111-115`） | Table 24 NOTE：已处 `Allocated`/`Linked` 且结果相同的重发 → **MAY 返回 Executed-Success** | esim42 响应丢失重试被判失败；G5 无法依赖标准机制 |
| b | `confirmOrder` 无条件覆盖 EID（`internal/api/es2plus/handlers.go:143-145`） | §5.3.2：DownloadOrder 与 ConfirmOrder 的 EID 不一致 → **`8.1.1/3.10`** Invalid Association | 错误绑定设备；G4 的 EID 归属可能被静默改写 |
| c | `CodeProfileNotFound = 8.2.5/3.9` 被用于“未知 ICCID”（`handlers.go:140`）与“不可下载”（`internal/service/cmae.go:200`） | `8.2.5/3.9` 是 **Profile Type Unknown**；**未知 ICCID 应为 `8.2.1/3.9`**（`internal/rsp/errors.go:60`） | esim42 无法区分 ICCID 未知与 Profile Type 未知 |
| d | 缺失 `iccid` 返回 `8.2.5/3.9`（`handlers.go:134-136`） | §5.3.2 精神：缺失必填元素 → `8.1.1/2.2` Mandatory Element Missing | esim42 的重试/补偿判断失真 |

**建议**：a 按 NOTE 实现（同时是 G5 的首选幂等路径）；b 增加 EID 一致性校验并按 `8.1.1/3.10` 应答；c 拆分状态码（新增 `CodeProfileTypeUnknown = 8.2.5/3.9` 与 `CodeICCIDUnknown = 8.2.1/3.9`，并让越权码 `8.2.5/1.2` 独立命名）；d 缺失必填元素改 `8.1.1/2.2`。

**验收**：同一 ICCID 重复 downloadOrder 返回 Executed-Success 且不重复建号；EID 不一致的 confirmOrder 被拒；未知 ICCID / 未知 Profile Type / 缺必填元素 / 越权四类失败返回可区分的 subjectCode-reasonCode。

### G20. SM-DS 事件透视与运维（决策 6 启用后升为 P1）

**需求**：决策 6 选择**启用 SM-DS**，esim42 将用 ES12 注册/删除事件，并以 `/events` 支撑模块 B/C/D 的“无激活码推送”视图。

**现状**：ES11/ES12/ES15 服务与客户端均已实现并有测试（`internal/api/es12`、`internal/api/admin/ds.go`、`internal/service/smdsc.go`/`smds_event.go`/`registrar.go`）。只读 `GET /admin/api/v1/events` 支持 `eid`/`eventId`/`page`/`size`（`internal/api/admin/ds.go:45-58`）。缺口：
- 无时间范围与状态过滤（无法做“今日新增事件”“即将过期事件”）；
- 事件与 Profile/租户无关联查询（事件记录只有 EID/EventID/RSP address/caller OID，`00001_init.sql:99-114`），无法按运营商切分事件视图；
- 注册/级联失败只在日志里（`internal/api/es2plus/handlers.go:168-172` 仅 `Log.Warn`），esim42 无从感知“事件没注册上”；
- 过期事件的清理策略需要确认（`event_ttl` 配置存在，`config:90`）。

**建议改动**：
- `GET /events` 增 `tenant`、`since`/`until`、`expired`/`deleted` 过滤与排序；返回调用方 OID 与级联标记。
- 事件写入时携带 `tenant_id`（来自 G2 的解析）与关联 ICCID/MatchingID（注册时已知），使 `/events` 可按运营商与 Profile 关联。
- 注册失败可观测：写审计（`interface=es12`, `outcome=Failed`）+ 暴露 G11 的指标计数，供 esim42 告警。
- 明确并实现过期事件 GC（与 `event_ttl` 对齐）。

**验收**：`GET /events?tenant=a&since=…` 只返回 A 的事件；注册失败在审计与指标中可见；过期事件被回收。

---

## 3. 可选 [P2]

| # | 改动 | 说明 |
|---|---|---|
| G13 | ACR 调用方侧接线 | **已完成**。ES9+ 侧 ACR 检索（`service/acr.go`）+ SM-DP+ 主动调用 Operator `ES2+.HandleAcrRequest`（`notifications.es2p_callback.acr_url`，SGP.22 §5.3.8）均已接线：请求体只带 `iccid`（Table 32d/§6.5.2.20），两类 ACR（`ACR-0`/`ACR-1`）都会确认，拒绝返回规范码 `8.2.1/1.2` 并中止检索，传输失败退避重试、`acr_timeout` 兜底 |
| G14 | MatchingID 轮换 | 现无轮换接口（`admin/profiles.go:288-305` 只读现成值）。若需作废旧二维码：`POST /profiles/{iccid}/activation-code?rotate=1` |
| G15 | 配额硬校验（限流明确不做） | **rsp42 侧限流/429 明确不做**（§8.4），限流由 esim42 前置承担；rsp42 只做资源级硬校验：用 G2 的 `tenants.template_quota`（建模板）/`profile_quota`（分配）在写入时拒绝 |
| G16 | 聚合与导入补强 | 新增 `GET /eids`（按 EID 聚合设备与其 Profile）；`/profiles/import` 支持 CSV 上传与逐行错误报告（现为 JSON list，`admin/export.go:89-119`）。**事件查询部分因决策 6 升级为 P1，见 G20** |
| G17 | 文档一致性 | `README.md` 与 `TODO.md` 曾对 ASN.1 binding 的表述不一致（一个称已实现、一个称 out of scope），需对齐，否则 esim42 的接口契约判断会出错 |
| G18 | 模板版本与回滚 | `upp_templates` 每次 PUT 覆盖同名模板（`00003_upp_templates.sql`）。为此增加 `upp_template_versions` 归档与回滚接口（已实现） |

---

## 4. 数据库变更草案（汇总）

```sql
-- G2
CREATE TABLE tenants (id TEXT PRIMARY KEY, name TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'active',
                      template_quota INTEGER, profile_quota INTEGER, default_upp TEXT,
                      callback_url TEXT, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);
ALTER TABLE upp_templates   ADD COLUMN tenant_id TEXT;      -- NULL = 全局模板
ALTER TABLE profiles        ADD COLUMN tenant_id TEXT;
ALTER TABLE profiles        ADD COLUMN external_ref TEXT;   -- G5
ALTER TABLE iccid_ranges    ADD COLUMN tenant_id TEXT;
ALTER TABLE iccid_pool      ADD COLUMN tenant_id TEXT;
ALTER TABLE iccid_pool      ADD COLUMN reserved_until INTEGER;
ALTER TABLE iccid_pool      ADD COLUMN reference TEXT;
ALTER TABLE download_batches ADD COLUMN tenant_id TEXT;
ALTER TABLE personalization ADD COLUMN tenant_id TEXT;
ALTER TABLE audit_log       ADD COLUMN tenant_id TEXT;
-- 唯一约束调整（需重建表或建部分唯一索引）
CREATE UNIQUE INDEX idx_upp_tenant_name ON upp_templates(tenant_id, name);
CREATE UNIQUE INDEX idx_profiles_extref ON profiles(tenant_id, external_ref) WHERE external_ref IS NOT NULL;
CREATE UNIQUE INDEX idx_perso_imsi      ON personalization(tenant_id, imsi) WHERE imsi IS NOT NULL;

-- G5
CREATE TABLE idempotency (key TEXT NOT NULL, endpoint TEXT NOT NULL, tenant_id TEXT,
                          request_hash TEXT NOT NULL, status INTEGER NOT NULL,
                          response_json TEXT, created_at INTEGER NOT NULL, PRIMARY KEY (key, endpoint));

-- G6（凭据池，P1）
-- personalization: 主键由 iccid 改为 id INTEGER PK，iccid 变为可空唯一列
```

> 注：本节以下变更为草案。项目“无历史遗留、不做向后兼容代码”，但**迁移文件本身是追加式**的：
> 仓库已存在 `00002..00006`，合并回 `00001_init.sql` 等于整库 squash（并会使已迁移库的 goose 版本校验失败）。
> 因此实际落地为 `00007`–`00010`，详见 §9.1。

---

## 5. 管理 API 变更草案（汇总）

| 方法 | 路径 | 变更 | 对应 |
|---|---|---|---|
| GET | `/tenants`、`POST /tenants`、`PATCH /tenants/{id}` | 租户 CRUD 与配额 | G2 |
| GET | `/profiles` | 增 `tenant`、`externalRef`、`from`、`to`、`batchId` 过滤 | G2/G5/G8 |
| POST | `/profiles` | 请求体增 `uppTemplate`、`externalRef`、`tenant` | G3/G5 |
| POST | `/profiles/{iccid}/activation-code` | 支持 `?rotate=1`（P2） | G14 |
| GET | `/profiles/stats` | 按 `tenant/from/to/groupBy` 聚合 | G8 |
| GET | `/upp` | 增 `tenant` 过滤；返回 `tenantId/description` | G2 |
| GET | `/upp/{name}/schema` | 个性化字段 schema | G7 |
| POST | `/upp/validate` | 上传校验 SAIP 文件 | G7 |
| POST | `/upp/render` | dry-run 渲染预览 | G7 |
| POST | `/upp/{name}/clone`、`/promote` | 模板派生/提升为全局 | G7 |
| GET | `/personalization` | 增 `tenant` 过滤 | G2 |
| POST | `/personalization/pool/import` | 无 ICCID 的凭据池导入 | G6 |
| GET | `/iccid-pool`、`/iccid-pool/stats` | 增 `tenant`；`stats` 增 `reserved_ttl_expired` | G2/G6 |
| POST | `/iccid-pool/reserve` | 请求体增 `tenant`、`reference`；可返回成对 IMSI | G6 |
| GET | `/audit`、`/audit/stats` | 增 `tenant`、聚合计 | G2/G8 |
| GET | `/notifications` | 新端点（now only via timeline） | G8 |
| GET | `/eids` | 按 EID 聚合（P2） | G16 |
| GET | `/events`（SM-DS admin 监听） | 增 `tenant`/`since`/`until`/`expired` 过滤与排序；返回调用方 OID 与级联标记 | G20 |
| GET | `/metrics` | Prometheus（P1） | G11 |

> 管理 API **不引入鉴权**（见 §0.1-4）。因此 `/personalization` 的 K/OPc 导出（`?reveal=1`、`/export`）只依赖内网边界，esim42 必须确保该 API 不对外暴露/不被网关转发。

---

## 6. ES2+ 变更草案（**零 JSON body 扩展**）

> 规范依据：ES2+ JSON body 的字段集合是封闭枚举（下载：仅 `eid`/`iccid`/`profileType`，SGP.22 §6.5.2.1 + Table 22），规范**没有**“忽略未知成员”的向前兼容条款；而 SGP.22 §6.2 明确允许**额外 HTTP 头**。因此私有信息只走 HTTP 头，body 一律用标准字段。详见 §8.2。

| 函数 | 变更 | 规范依据 / 兼容性 |
|---|---|---|
| `downloadOrder` | **模板/产品选择改用 `profileType`**（约定 `"<tenant>/<template>"`） | §6.5.2.1 描述即 “content free information defined by the Operator”；Table 22 NOTE 允许 SM-DP+ 按 Profile Type 自由选 Profile |
| `downloadOrder` | **实现 Table 24 NOTE 的优雅重发**：ICCID 已存在且状态/入参一致 → `Executed-Success` + 原 ICCID，不重复扣池 | Table 24 NOTE；修复当前返回 Failed 的偏离（见 G19） |
| `downloadOrder` | 租户归属取自 `header.functionRequesterIdentifier` 映射（决策 3；不采用每运营商证书） | §6.5.1.3 无格式约束；§6.4 要求双向 TLS 与已注册身份 |
| `confirmOrder` / `releaseProfile` / `cancelOrder` | 仅按需支持 **`Idempotency-Key` HTTP 头**（标准未定义重发语义的函数） | §6.2 “MAY contain additional header fields … out of scope of this specification” |
| `confirmOrder` | EID 与 DownloadOrder 不一致时按规范返回 `8.1.1/3.10` Invalid Association（当前直接覆盖，见 G19） | §5.3.2 |
| 全部 | 越权状态码：ICCID → `8.2.1/1.2`；Profile Type/模板 → `8.2.5/1.2` | Table 24 / §5.3.1 |
| 回调 | 载荷增 `tenantId`、`externalRef`、`matchingId`（**这是 rsp42→Operator 的自有通知**，不受 ES2+ 输入约束） | 纯增量 |

---

## 7. 实施里程碑建议

| 里程碑 | 内容 | 阻塞 esim42 的什么 |
|---|---|---|
| **M1（租户与审计）** | G2 租户维度、G8 actor 修复、G17 文档对齐 | 模块 C/D/E 全部 |
| **M2（下单与领取闭环）** | G3 `profileType` 选择、G4 EID 回写、G5 重发幂等、G6 ICCID 池加固、G19 标准一致性修正、G20 SM-DS 事件透视（含 `rsp42 smds` 角色启用） | 模块 A/B/C 的领取与看板 |
| **M3（模板与个性化）** | G7 schema/validate/render/clone + PLMN 等字段、G6 凭据池/IMSI 池 | 模块 C 的可视化模板创建与批量开卡 |
| **M4（运维与契约）** | G8 统计接口、G10 OpenAPI/错误码、G11 metrics、G12 BEGIN IMMEDIATE | 模块 C/D 看板与 esim42 SDK 生成 |

**验收基线**：esim42 侧完成一次端到端（匿名领取 → LPA 下载 → 安装 → 看板可见 → 审计可查 → 取消/回池）的联调，全链路租户归属正确、幂等重放安全。

---

## 8. 已对齐决策（全部待定项已收敛）

### 8.1 决策表

| # | 问题 | 结论 | 对本文档的影响 |
|---|---|---|---|
| 1 | 租户 ID 由谁生成 | **直接用 esim42 的 Carrier 主键**作为 rsp42 `tenants.id`，不做二级映射 | G2 的 `tenants.id` 语义固定；无需 `external_ref` 映射层 |
| 2 | 调用通道 | **订单走 ES2+，管理走 Admin API** | G3/G5 必须在 ES2+ 与 Admin 两侧都实现 |
| 3 | 租户归属的承载方式 | **`header.functionRequesterIdentifier` 映射**（标准字段，零协议扩展）；**每运营商客户端证书明确不做**（§8.4） | G2 的解析器由此确定；§6 无 JSON body 扩展；§8.3 仅作历史备查，不再是候选方案 |
| 4 | K/OPc 是否允许 rsp42 生成 | **esim42 生成，rsp42 只存与注入** | rsp42 不提供密钥生成/派生端点；G7 的 `/schema`、`/render` 只承载字段与校验 |
| 5 | 部署形态 | **同机同网**（esim42 后端 ↔ rsp42 管理 API 内网直连），esim42 前端只经 esim42 后端 | 管理 API **不鉴权**（§0.1-4，原 G1 排除）；存储固定 SQLite 单进程，PostgreSQL 与多副本明确不做（§8.4） |
| 6 | SM-DS 是否启用 | **启用**：esim42 经 rsp42 走 ES12 事件注册/删除，并以 `/events` 做透视（支撑模块 B 的“无激活码推送”） | rsp42 的 SM-DS 能力已具备（`internal/api/es12`、`internal/api/admin/ds.go`），无需新建；但事件查询/清理需补齐，G16 中的事件部分**升级为 P1**（新增 G20） |

### 8.2 决策 3 的规范依据（备查）

- **ES2+ 不能新增 `tenantId` JSON body 字段**：SGP.22 v2.7 §6.5.2.1 对 `ES2+.DownloadOrder` 的 body schema 只定义 `eid`、`iccid`、`profileType`（Table 22 的 MOC 为 O/C/C）；规范没有 `additionalProperties: false`，也**没有**“接收方 SHALL 忽略未知成员”的向前兼容条款（对比 Activation Code 明确写了 “Device SHALL ignore … further parameters”）。本仓库 `downloadOrder.pprIds`（`internal/api/es2plus/handlers.go:64-66`）即此类既有私有扩展——v2.7 中 `pprIds` 只出现于 `RulesAuthorisationTable`（§5.7），并不在 DownloadOrder 中。
- **私有信息放 HTTP 头是规范显式允许的**：SGP.22 §6.2 “HTTP POST request and response MAY contain additional header fields. Their use is out of scope of this specification.” → `Idempotency-Key` 等走表头，body 成员不走。
- **承载分工**：租户 ← `functionRequesterIdentifier`（§6.5.1.3，type string、无格式约束）；模板/产品 ← `profileType`（§6.5.2.1 “content free information defined by the Operator” + Table 22 NOTE）；幂等 ← Table 24 NOTE + HTTP 头；`externalRef` ← 不上线，esim42 以 `downloadOrder` 返回的 ICCID 作为自身外键。
- **残留风险（已知并接受）**：`functionRequesterIdentifier` 是调用方自述字段，租户归属实质是“信任 esim42 后端”；在决策 5 的内网单后端前提下可接受。**“运营商绕过 esim42 直连 rsp42”不在支持范围内**：每运营商客户端证书明确不做（§8.4），因此该拓扑一旦出现，必须改为每运营商独立部署 rsp42（而不是给 rsp42 加证书映射）。

### 8.3 每运营商客户端证书（**明确不做**——仅作历史备查，不再评估）

- **rsp42 侧：低。** mTLS 管线已存在（`es2p.tls.client_ca_file` + `RequireAndVerifyClientCert`，`internal/config/config.go:56`、`internal/cli/server.go:71-77`）；身份提取可复用 ES12 `callerOID`（`internal/api/es12/handlers.go:87-92`）与 `cert.RegisteredIDs`（`internal/cert/chain.go:96`）。只需加“证书主体 → 租户”映射，约 0.5–1 人日，无密码学新代码。限制：`client_ca_file` 为**单一 CA**（运营商自带 CA 需改成 CA 列表）；无 CRL/OCSP（见 `docs/coverage.md` 的已知偏差），吊销只能撤映射/换 CA。
- **esim42 侧：中。** TLS 握手早于 HTTP 请求，无法按请求选证书 → 每运营商一个 `http.Client`/transport（`NewClient(..., hc)` 已支持，`internal/api/es2plus/clientlib.go:27-30`）。主要成本在**证书生命周期**：签发、分发、密钥保管、轮换、撤销、运营商上下线。
- **结论（已收敛为“不做”）**：决策 3 选择 `functionRequesterIdentifier`，且 §8.4 决策 8 明确**不做**每运营商证书。本节其余内容只保留为历史分析，不再作为候选方案评估；若将来真出现“运营商直连 rsp42”的需求，应重新立项评估，而不是在此处补丁式启用。

### 8.4 明确不做（决策 7–10）

| # | 问题 | 结论 | 落地表现 |
|---|---|---|---|
| 7 | 数据库后端 | **只做 SQLite**。PostgreSQL/MySQL 等**明确不做** | `profiles.repository` 仅接受 `sqlite`；配置校验对其它取值直接报错并说明原因。不保留“抽象后端”的暗示 |
| 8 | 多副本部署 | **明确不做**。单进程、单数据库文件 | 无 leader 选举、无分布式锁；GC/ticker 在进程内。横向扩容需重新立项 |
| 9 | 每运营商客户端证书 | **明确不做**。ES2+ 租户归属只用 `functionRequesterIdentifier` 映射 | §8.3 降级为历史备查；“运营商直连 rsp42”不在支持范围 |
| 10 | rsp42 侧限流 | **明确不做**（不提供 429 语义） | 限流由 esim42 前置承担；rsp42 只做资源级配额硬校验（`tenants.template_quota` / `profile_quota`） |

> 说明：这四项此前在本文中写作“不实施/仅备查/未来加固”，容易被读成“以后可能做”。现统一收敛为**范围外**：文档不再把它们列为待办，代码也不再为它们预留会被误用的配置语义。

---

## 附：现状能力对照（esim42 需求 → rsp42 是否已具备）

| esim42 需求 | 现状 | 结论 |
|---|---|---|
| ES2+ DownloadOrder/ConfirmOrder/ReleaseProfile/CancelOrder | 已实现（`internal/api/es2plus/handlers.go:106-226`） | ✅ 需扩展（G3/G5） |
| Profile 生命周期 9 态齐全 | 已实现（`internal/service/order.go:22-49`） | ✅ |
| 匿名领取所需“无 EID 下单” | 已实现（`Allocated`，`internal/service/inventory.go:38-42`） | ✅ 需补 EID 回写（G4） |
| 激活码 `1$fqdn$matchingId` + QR 内容 | 已实现（`internal/api/admin/profiles.go:288-305`） | ✅ |
| ACR（LPA 内找回激活码） | 已实现：ES9+ 检索（`service/acr.go`）+ Operator 确认 `ES2+.HandleAcrRequest`（`service.ACRChecker`，`acr_url`） | ✅ |
| 已审核后才可下载（审批流落点） | `Confirmed` 不可下载，须 `ReleaseProfile`（`service/cmae.go:197-201`） | ✅ |
| ICCID 池导入/预留/阻塞/统计 | 部分（`internal/store/pool.go`） | ⚠️ G6 |
| IMSI 池 | 无 | ❌ G6 |
| Profile 外部引用 / 幂等 | 无 | ❌ G5（走规范 Table 24 NOTE 重发 + `Idempotency-Key` 头；`externalRef` 仅 Admin 便利字段） |
| 租户隔离 | 无 | ❌ G2 |
| 管理 API 鉴权 | 无（**按部署前提有意保持**，见 §0.1-4） | ✅ 无需改动（原 G1 已排除） |
| SAIP 解析/编码/个性化 | 已实现（`internal/saip`、`internal/saip/personalization`） | ✅ 需外露（G7） |
| PLMN 列表个性化 | 无 | ❌ G7 |
| 审计日志查询（含 since/until） | 已实现（`internal/api/admin/audit.go:58`） | ⚠️ actor/tenant/统计待补（G8） |
| 下载/安装进度回调 | 已实现且可靠（`internal/api/es2plus/callback.go`） | ✅ 载荷待补字段（G9） |
| SM-DS 事件读写 | 已实现（ES11/ES12/ES15 + 只读 `/events`）；**决策 6 启用** | ⚠️ 需补事件过滤/租户/失败可观测（G20） |
| OpenAPI 契约 | 最小手写描述 | ❌ G10 |
| 监控指标 | 仅 healthz/readyz | ❌ G11 |

---

## 9. 实施状态（rsp42 侧，已落地）

> 本节记录本文档各项改造在本仓库中的落地情况。图例：`[x]` 已实现并有测试；`[~]` 部分实现/已登记后续；`[ ]` 未做。

| # | 项 | 状态 | 落地位置 |
|---|---|---|---|
| G2 | 租户维度 | `[x]` | `internal/store/migrations/00007_esim42_tenancy.sql`（`tenants` 表 + 各资源 `tenant_id`）、`store/tenant.go`、`store/{profile,upp,pool,batch,personalization,audit,events,order}.go`、`api/admin/tenants.go`、`api/es2plus/handlers.go`（`functionRequesterIdentifier` → 租户）、`config.smdpp.es2p.requester_tenants` |
| G3 | `profileType` 选择模板 | `[x]` | `api/es2plus/handlers.go:resolveProfileType`（`"<tenant>/<template>"`，越权 `8.2.5/1.2`、未知 `8.2.5/3.9`）、`service/download.go:loadUPP`（订单 → 会话 → 租户默认 → 全局默认，移除 `Any()` 兜底）、`tenants.default_upp` |
| G4 | 下载回写 EID | `[x]` | `service/cmae.go` `AuthenticateClient`（EID 为空则绑定；`Allocated → Linked`），异 EID 复用被 `lookupProfile` 拒绝 |
| G5 | 幂等与业务关联 | `[x]` | `service/inventory.go:sameResend`（Table 24 NOTE 优雅重发）、`api/middleware/idempotency.go`（`Idempotency-Key`，哈希排除易变的 `functionCallIdentifier`）、`store/idempotency.go`、`profiles.external_ref`（Admin 过滤） |
| G6 | 池加固与凭据池 | `[x]` | `store/pool.go`（租户隔离、`reserved_until`、`reference`、`profile_id`、`ReleaseExpired`）、`service/inventory.go` 失败回滚、`service/order.go` Cancel/Delete 回池、`store/personalization.go`（`id` 主键、可空 `iccid`、`UNIQUE(tenant,imsi)`、`ReservePair`）、`POST /personalization/pool/import`、`POST /iccid-pool/reserve` 返回成对 `{iccid, imsi}` |
| G7 | SAIP 模板能力外露 | `[x]` | `GET /upp/{name}/schema`、`POST /upp/validate`、`POST /upp/render`、`POST /upp/{name}/clone`、`POST /upp/{name}/promote`（`api/admin/upp_tools.go`、`service/upp_inspect.go`）；个性化新增 PLMN 列表、MSISDN、ACC、任意 EF 覆盖（`saip/personalization`） |
| G8 | 审计与看板 | `[x]` | `api/middleware`（actor 取 mTLS 主体 / `functionRequesterIdentifier` / ES12 caller OID；管理 API 记为 `esim42-backend`）、`audit_log.tenant_id`、`GET /audit/stats`、`GET /profiles/stats`、`GET /notifications`、timeline 含 session + 审计事件 |
| G9 | 回调字段与租户路由 | `[x]` | `ProgressInfo` 增 `tenantId/externalRef/matchingId`；`tenants.callback_url` 覆盖全局回调地址；本文 §2 已补 `notificationPointId` 语义表（`docs/interfaces.md`） |
| G10 | OpenAPI + 错误码 | `[x]` | `internal/api/admin/openapi.json`（完整 OpenAPI 3.0，含 schema/错误模型，`//go:embed` + 校验测试）、管理 API 错误体 `{code, message}` |
| G11 | 可观测性 | `[x]` | `internal/metrics`，管理监听器 `GET /metrics`（下载进度按租户/点位/状态、CC 失败、回调队列深度、池可用/已分配/预留过期、session/event GC、ES12 注册失败） |
| G12 | 并发与存储 | `[x]`（范围已收敛） | `store.Open` 统一追加 `_txlock=immediate`；并发 200 次领号测试 `TestPoolConcurrentReserve`。**PostgreSQL 与多副本明确不做**（§8.4 决策 7–8），`profiles.repository` 只接受 `sqlite` |
| G13 | ACR 调用方侧接线 | `[x]` | `service.ACRChecker` + `es2plus.CallbackClient.HandleAcrRequest`：请求体 `{header, iccid}`（Table 32d）、拒绝 `8.2.1/1.2`（Table 32e）不重试、传输失败退避重试、`acr_timeout` 兜底、按租户计数与审计；接线与进度回调**相互独立**（只配 `acr_url` 也能生效） |
| G14 | MatchingID 轮换 | `[x]` | `POST /profiles/{iccid}/activation-code?rotate=1` |
| G15 | 配额硬校验（限流明确不做） | `[x]` | `template_quota`（建模板，409 `quota_exceeded`）与 `profile_quota`（分配时，ES2+ 侧 `8.2.1/3.8`）均已硬校验；**rsp42 侧限流/429 明确不做**（§8.4），由 esim42 前置承担 |
| G16 | 聚合与导入补强 | `[x]` | `GET /eids`（按 EID 聚合设备与其 Profile）；`POST /profiles/import` 支持 `text/csv` 与逐行错误报告；事件查询已按 G20 完成 |
| G17 | 文档一致性 | `[x]` | `README.md` / `docs/interfaces.md` / `docs/operations.md` / `docs/coverage.md` 已对齐（ASN.1 binding 为已实现） |
| G18 | 模板版本与回滚 | `[x]` | `upp_template_versions` 归档 + `GET /upp/{name}/versions`、`POST /upp/{name}/versions/{id}/restore`（回滚本身可逆） |
| G19 | ES2+ 标准一致性 | `[x]` | 重发（Table 24 NOTE）、`confirmOrder` EID 不一致 `8.1.1/3.10`、状态码拆分（`8.2.1/3.9` ICCID 未知 / `8.2.5/3.9` Profile Type 未知 / `8.2.5/1.2` 越权 / `8.1.1/2.2` 缺必填） |
| G20 | SM-DS 事件透视 | `[x]` | `GET /events` 增 `tenant`/`iccid`/`matchingId`/`status`/时间范围/排序/级联与 OID 返回；ES12 事件写入携带 `tenant_id`（`X-RSP42-Tenant` 头，规范 §6.2 允许）；注册失败写审计（`interface=es12`）并计数；事件过期 GC 与 `event_ttl` 对齐并计数 |

### 9.1 与本文档的两处偏差（已确认实施选择）

0. **迁移文件为 `00007`—`00010`**（租户、凭据池、ES12 注册租户、模板版本）。
1. **数据库变更未合并进 `00001_init.sql`**。§4 当时的建议基于“单一当前 schema 迁移”的设想；但仓库现状已存在 `00002..00006`，合并意味着整库 squash（并使已迁移数据库的 goose 版本校验失败）。因此改为追加式迁移 `00007`–`00010`，与仓库现有的增量迁移实践一致，且不做任何向后兼容代码。
2. **ES12 的租户归属走 HTTP 头 `X-RSP42-Tenant`**（§6.2 明确允许额外头部），而非新增 ES12 body 成员。服务端另有 `smds.es12.requester_tenants`（caller OID → 租户）作为回落。

### 9.2 明确不做（决策 7–10，见 §8.4）

以下四项**不在本项目范围内**，不再作为“待办/未来加固”跟踪，相关文档与配置已按“仅支持当前形态”收敛：

1. **PostgreSQL / 其他数据库后端**：仅 SQLite。`profiles.repository` 只接受 `sqlite`，其他取值在配置校验阶段报错。
2. **多副本部署**：单进程、单数据库文件、无 leader 选举/分布式锁。需要横向扩容时应重新立项，而不是在当前形态上加锁。
3. **每运营商客户端证书**：ES2+ 租户归属只用 `header.functionRequesterIdentifier`（§8.3 降级为历史备查）。
4. **rsp42 侧限流 / 429 语义**：限流由 esim42 前置承担；rsp42 只做资源级配额硬校验（`tenants.template_quota` / `profile_quota`）。

### 9.3 尚未实施的 P2

**无。** 文档 §3 的可选项已全部落地：G13（ACR 调用方侧接线）、G14（MatchingID 轮换）、G15（配额硬校验）、G16（`GET /eids` / CSV 导入）、G18（模板版本与回滚）均已完成；G17 文档已对齐。§9.2 列出的四项为**明确不做**（范围外）。
