# rsp42 ← esim42 对接改造清单（反向差距分析）

> 输入（**两轮**）：
> - **第一轮（G 清单）**：`../esim42/PLAN.md`（eSIM 综合运营平台规划，模块 A–E）与 `../esim42/todo/02-rsp42-api-gap-analysis.md` 的**预期产出**（该文档当时尚未产出）。
> - **第二轮（N 清单）**：`../esim42/todo/01`–`06` 与 `todo/research/*` 的**实际产出**（2026-10-14 18:11 定稿，晚于本文件 16:16）。第二轮把 rsp42 的改动重编为 **N1–N17**，并带来两处与本文件第一轮判断的**优先级冲突**（见 §0.3 与 §9.4）。
>
> 本文只回答一件事：**站在 rsp42 的角度，为了支撑 esim42，需要改什么、不需要改什么、以及接口契约长什么样**。
> 图例：`[P0]` 阻塞（不改则 esim42 无法安全/正确上线）；`[P1]` 重要（影响功能完整性或可运维性）；`[P2]` 可选/后续。
> 现状判定均以本仓库**当前代码**为准（附 `文件:行`）；第二轮各项均已逐条实测并标注“现状”。

---

## 0. 结论摘要

### 0.1 边界原则与部署前提（先划边界，再列改动）

1. **rsp42 是 RSP 层（SM-DP+/SM-DS），不是 BSS 层。** 用户、账号、OAuth、运营商业务、商城、可见性、审批流、前端一律属于 esim42；rsp42 只多认一样东西：**租户（tenant/carrier）归属**，因为资源隔离、审计归属与配额必须落在持有资源的进程里。
2. **esim42 不需要新引入 SAIP 编解码栈。** rsp42 已有 Go 版 SAIP 解析/编码与个性化引擎（`internal/saip`、`internal/saip/personalization`）。正确做法是 rsp42 把模板能力（schema / validate / render / clone）以管理 API 外露，esim42 前端只做表单与编辑器 —— 这直接消解 `PLAN.md` §4.1 的“Go 主干 + Python 编解码微服务”选型风险，并满足“严禁造轮子”。
3. **订单生命周期走标准 ES2+，非标准的管理动作走 Admin API。** esim42 用 ES2+（mTLS）做 downloadOrder/confirmOrder/releaseProfile/cancelOrder，用 `/admin/api/v1` 做库存、模板、池、审计、看板。因此 **ES2+ 也必须具备租户归属、模板绑定、幂等与外部引用能力**，否则 esim42 只能退回“全部走 Admin API”或“一个运营商一套 rsp42 实例”。
4. **部署前提（已与 esim42 确认）：管理 API 保持无鉴权。** esim42 后端与 rsp42 管理 API **同机同网、内网直连**；esim42 前端只经 esim42 后端访问，绝不直连 rsp42。因此管理 API 不引入 Bearer/mTLS/scope，**安全边界由 esim42 承担**（esim42 必须保证该 API 不被反向代理、网关或前端暴露）。原初稿的 G1“管理 API 鉴权”据此**排除**，正式改动清单从 G2 起。
5. **SM-DS 启用（决策 6）**：esim42 走 ES12 事件注册/删除并以 `/events` 做透视，支撑模块 B 的“无激活码推送”。rsp42 需同时部署 `smds` 角色（`RSP42_ROLE=smds`），并补齐事件的时间/租户过滤与注册失败可观测（G20）。
6. **明确不做（决策 7–10，见 §8.4）**：**PostgreSQL/其他数据库后端**、**多副本部署**、**每运营商客户端证书**、**rsp42 侧限流/429**。这四项不在本项目范围内，也不是“以后再说”的备选项——相关配置与文档已按“仅支持当前形态”收敛。
7. **SAIP 基线由 esim42 定为 V2.3.1（包内编码 `(2,3)`）**（esim42 `01` §6.5 D1/D2）。由此 rsp42 需要一条**版本上限**（N16）与一条**运行期兼容性干净失败**（N12），二者是第二轮唯一的 P0。注意“V2.3.1 是文档修订号，包内与 V2.3 同形”，任何比较都只能按 `(major, minor)`。SAIP V3.x 的 PE/模板/feature 覆盖与 SGP.22 Annex F 的 `PE-GenericFileManagement` 降级构造（N14）由 esim42 明确列为**范围外**，rsp42 不为其预留代码位或配置开关（见 §0.4）。

### 0.2 必改项 Top 7（第一轮 G：已全部落地）

| # | 改动 | 对应 esim42 需求 | 优先级 |
|---|---|---|---|
| G2 | 租户维度贯穿 `upp_templates / profiles / iccid_pool / iccid_ranges / batches / personalization / audit_log` | §2.1 多租户、模块 C/D | **P0** |
| G3 | 模板/产品选择走标准 `profileType`（不再只靠 eUICC 版本 + 全局默认） | §3C“可视化模板创建/多运营商” | **P0** |
| G4 | 下载时回写 `profile.eid`（匿名领取无 EID，安装后无法设备归属） | 模块 B“我的 eSIM/设备” | **P0** |
| G5 | 幂等：实现 Table 24 NOTE 优雅重发 + （按需）`Idempotency-Key` HTTP 头 | 模块 A/B 一键领取、模块 C 看板 | **P0** |
| G6 | ICCID/IMSI 池：租户隔离、预留 TTL、失败回滚、与个性化解耦（凭据池） | §4.3 资源池管理 | **P0/P1** |
| G7 | SAIP 模板能力外露（`/schema`、`/validate`、`/render`、`/clone`、全局模板提升） | §3C/§3D、§4.1/§4.2 | P1 |
| G8 | 审计 `actor` 语义修复 + 租户维度 + 统计/看板接口 | 模块 C/D/E 审计透视 | P1 |

---

### 0.3 第二轮必改项（N 清单：除 N6/N10 范围外，其余待实施）

> 来源：`../esim42/todo/02` §7.2（N1–N17）、`01` §8（N11–N17）、`03` §3.3/§7/§11、`06` §13.1。
> 第一轮的 G2–G20 已全部落地（见 §9）；下列各项在 rsp42 **均未落地**（**N6/N10 本轮明确不做**，见 §8.4 决策 11 与 §10.3 步骤 2.4），逐条实测结论见 §1bis / §2 / §3 对应的 N 小节与 §9.4。分步实施计划见 §10。

| # | 改动 | 对应 esim42 需求 | 优先级 |
|---|---|---|---|
| N16 | `/upp`、`/upp/validate` 加 SAIP 版本上限 `≤(2,3)`；新增 `profiles.allowed_saip_versions: ["2.3"]`（**列表形态**，为双 major 预留）；超限 `409 saip_version_not_supported` | `01` §6.5 D2；`06` D2.11 | **P0** |
| N12 | `loadUPP` 每一级回落都校验版本；无兼容模板时返回明确码且不生成 BPP；审计 `euiccProfileVersion` | `01` §6.5 D3/D5；`06` D2.12 | **P0** |
| N1 | 审计单调游标：`AuditEntry.id` + `GET /audit?afterId=&limit=` | 模块 E 增量审计同步 | P1 |
| N2 | 回调队列管理 API：`GET /callbacks`、`POST /callbacks/{id}/retry`、`POST /callbacks/retry-dead` | 模块 C/E 回调可靠性 | P1 |
| N3 | 租户删除引用保护：`409 tenant_in_use` + `usage`；`?force=true&reassignTo=` | 模块 D 防误删 | P1 |
| N6 | admin `bind` 默认 `127.0.0.1`；`X-RSP42-Reveal-Secrets: yes` 护栏（`secret_reveal_not_confirmed`） | 部署约束 | **范围外**（§8.4 决策 11、§10.3 步骤 2.4） |
| N11 | 解析 `additionalEuiccProfilePackageVersions`；`Version`/`SupportedVersions`/`IsV3Capable`；移除 `SelectBestFor` 的 `major<=0` 回退 | SEC；`01` §8.4.1 | P1 |
| N15 | `ServicesList` 补到 V2.3.1 的 24 项（`dfLink`/`cat-tp`/`get-identity`/`profile-a-x25519`/`profile-b-p256`） | `03` §3.1 能力位 | P1 |
| N13 | Annex A 模板表（V2.3.1 的 13 个模板 OID）+ 约束校验 + V2.3.1 测试向量 | 模块 C 模板上架校验 | P1 |
| N17 | `SdKey*` 与 `MncLen` 个性化 | MNO-SD 密钥集 / `EF.AD` | P1 |
| N4 | `/upp/{name}/schema` 的 `fields[]` 增 `applicable`/`targets[]`/`requiredIn[]`/`note` | 模块 C 动态表单 | P2 |
| N5 | `/upp/render` 接受未入库模板（`data` base64 DER） | 模块 C 上传向导 | P2 |
| N7 | 契约补全：`profiles/stats` 的 `groupBy` 补 `profile_type`；`sort` 白名单补 `tenant`；删除 catch-all `error` | 模块 C/D 筛选器与 SDK | P2 |
| N8 | SM-DS 事件管理写接口 `POST/DELETE /admin/api/v1/events` | 模块 B 边缘场景 | P2 |
| N9 | HTTP 延迟直方图 `rsp42_admin_http_request_duration_seconds` 等 | SLO 看板 | P2 |
| N10 | 密钥端点显式契约：`secret-bearing endpoint` 标注、`Cache-Control: no-store`、审计不记密钥 | 防密钥管道滥用 | **范围外**（随 N6，§10.3 步骤 2.4） |
| N14 | SGP.22 Annex F 的 `PE-GenericFileManagement` 降级构造 | **esim42 明确范围外**，不预留代码位/开关 | — |

> **与第一轮的优先级冲突（需注意）**：`TODO.md` 把“SAIP 完整模板表”与“`SdKey*`/`MncLen`”都记为 **P2**，而 esim42 把它们定为 **N13/N17 = P1**；反过来 `TODO.md` 的 `CancelSession` 验签/OID 与 Brainpool 两项 esim42 **未提出要求**。详见 §9.4。

---

### 0.4 明确“不需要做”的部分（避免把 BSS 逻辑渗进 RSP 层）

| esim42 侧需求 | 归属 | 说明 |
|---|---|---|
| 用户/角色/配额 M（用户可激活上限） | esim42 | SGP.22 无“用户”概念（rsp42 只维护 Profile 库存/订单/安装状态，见 `TODO.md` §1） |
| OAuth 适配器、`dn42.active_mnt` 映射 | esim42 | rsp42 不引入身份体系 |
| Profile 市场可见性、匿名开关、Brand/Logo/APN 指引 | esim42 | 业务属性；rsp42 只提供 `tenant_id` 与稳定模板标识 |
| 运营商提交审批流（下发前人工审批） | esim42 | rsp42 现有语义已够：`Confirmed` 不参与下载，必须显式 `ReleaseProfile`（`service/cmae.go:197-201`，T6） |
| 用户名额扣减/回滚 | esim42 | 由 esim42 编排 `downloadOrder`/`cancelOrder`；rsp42 只保证幂等与状态机 |
| 二维码渲染/发送（短信、邮件） | esim42 | rsp42 返回 `activationCode`/`qrContent` 字符串即可（`api/admin/profiles.go:288-305`） |
| ICCID/IMSI/K/OPc 的**权威**数据管理与订户绑定 | esim42 | rsp42 只做**存储 + 校验 + 分配**（见 `TODO.md` §1） |
| SAIP V3.x（V3.0–V3.4.1）的 PE、模板与 feature 覆盖（`df-snpn`、`iot`/`opt-iot` 的 IoT Minimal 语义、`df-5gprose`、`ssim`、`usatAppPairing`、5G ProSe 上报 Bit 8、带版本的模板 OID） | esim42 `01` §6.5 D1 + N16 | 基线 V2.3.1；超版本模板在 `/upp` 被拒（N16）。抬升上限需重新立项 |
| SGP.22 Annex F 的 `PE-GenericFileManagement` 降级构造（N14） | esim42 `01` §6.5 D4 | 不服务不适配机群，在资格检查阶段干净拒绝；**不预留代码位或配置开关** |
| 双 major 选择逻辑 | esim42 `06` §13.1 | 仅做**接口预留**（`allowed_saip_versions` 用列表、`SelectBestFor` 收版本集合），现阶段不实现双 major 选择 |
| 管理 API 监听面收敛与密钥导出护栏（N6/N10） | 本次决策 11（§8.4） | **明确不做**：admin `bind` 保持现状，不引入 `X-RSP42-Reveal-Secrets` 护栏与 `Cache-Control: no-store`；安全边界完全由 esim42 承担（esim42 必须保证管理 API 不被反向代理/网关/前端暴露） |

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

## 1bis. 第二轮阻塞级缺口 [P0]

> 编号来自 esim42 的实际产出（`../esim42/todo/02` §7.2 与 `01` §8），与第一轮的 G 编号并行、不重号。
> 本节刻意**不重排后续章节编号**：`§4`、`§8.1`、`§8.4`、`§0.1-4` 被迁移文件、`openapi.json` 描述与 `TODO.md` 外部引用，重排会使其失效。

### N16. SAIP 版本上限（`/upp`、`/upp/validate`）

**需求**：esim42 `01` §6.5 D1/D2 把 SAIP 基线定为 **V2.3.1（包内 `(2,3)`）**，并要求 rsp42 拒绝超基线模板。理由：在 V2.3.1 基线下 rsp42 **无法校验 V3.x 模板的 PE/服务语义**（`iotOptions` 必填、PE-IoT 必须紧跟 header、`df-5gprose`/`ssim` 的模板 OID 不在 V2.3.1 name 表语义里），而模板一旦被 `SelectBestFor` 选中就会被下发。

**现状（实测）**：
- `POST /upp` 由服务端解析 SAIP 版本后**直接入库，无任何上限**（`internal/api/admin/upp.go:113-121`）。
- `POST /upp/validate` 只回 `{valid, inspection}`，没有超版本 warning（`internal/api/admin/upp_tools.go:73-93`）。
- 配置中不存在 `allowed_saip_versions` / `max_saip_version`（`config/config.example.yaml`）。

**建议改动**：
- 新增配置 `profiles.allowed_saip_versions: ["2.3"]`。**必须是列表而不是标量**：现阶段语义等价于上限，但将来加 `"3.2"` 时不需要改配置形态、不需要迁移（esim42 `06` §13.1 R1 的零成本接口预留）。
- `POST /upp`：`major > 2 || (major == 2 && minor > 3)` → `409 {"code":"saip_version_not_supported","message":"…(V2.3.1, encoded as 2.3)","details":{"templateVersion":"3.2","maxSupported":"2.3"}}`。
- `POST /upp/validate`：保持 `valid: true`（便于“上传看看结构”），但在响应里给出明确 `warnings[]`。
- 实现处需**显式注释**“V2.3.1 是文档修订号，与 V2.3 在包内同形”，避免后人试图精确到修订号。
- ⚠️ **esim42 自身口径不一致**：`01` §6.5 D2 写的是标量 `profiles.max_saip_version: "2.3"`，而 `02` §7.2 N16 与 `06` §13.1 R1 写的是列表 `allowed_saip_versions: ["2.3"]`。**以列表形态实现**，并要求 esim42 修正 `01` 的表述，否则升级时会引入一次配置迁移。

**验收**：上传 `(3,2)` → `409`；`(2,4)` → `409`；`(2,3)` → 通过；`/upp/validate` 对 `(3,2)` 返回 warning 且仍 `valid: true`。

---

### N12. 版本不匹配时必须干净失败（不得把不兼容模板交给 eUICC）

**需求**：esim42 `01` §6.5 D3/D5：不服务不适配机群，且必须**在下载末期之前**干净失败，而不是让 eUICC 以 `unsupported-profile-version(31)` / `template-not-supported(9)` 拒绝（`01` §2.6.5）。在 esim42 的 D5 真机实测完成前，这是唯一的技术保障。

**现状（实测）**：`internal/service/download.go:224-250` 的 `loadUPP` 解析顺序为“订单 pin → session（`pickUPP`）→ **租户默认** → **全局默认**”，其中**后两级完全不校验版本**；`pickUPP` 依赖 `internal/store/upp.go:113-127` 的 `SelectBestFor`。当注册表只有 `(2,3)` 模板、而 eUICC 声明 `profileVersion=(2,1)` 时，会拿到 `(2,3)` 模板并在下载末期被拒；用户看到的是“装卡失败”。

**建议改动**：
1. `loadUPP` 的**每一级回落**都做 `(major, minor)` 版本校验；
2. 无兼容模板时返回明确状态码，且**不生成任何 BPP 段**；
3. ES2+ 侧用 `8.2.6/3.8` + 可读 message（SGP.22 无直接对应码；**不要**复用 `8.8.5/4.10` 的 unsupported curve）；
4. 管理 API 侧新增稳定错误码 `profile_version_not_supported`，写入 timeline 与审计；
5. 审计 `interface=es9p, function=authenticateClient, outcome=Failed, detail={euiccProfileVersion, supportedVersions, lowestTemplateVersion}`；
6. 当 eUICC 声明 `additionalEuiccProfilePackageVersions` 时记 `v3-capable-euicc` 指标/审计（与 N11 同处代码）。

**验收**：注册表只有 `(2,3)` + `profileVersion=(2,1)` 的 eUICC → 返回可区分失败码、BPP 未生成、审计与指标可查；esim42 能映射为“设备不支持，请更换设备”。

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
| `POST /upp/{name}/clone` | 从全局模板派生租户模板 |
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

### N1. 审计日志的单调增量游标

**需求**：模块 E 的“RSP 审计透视”要求 esim42 能每 N 秒增量拉取新增审计事件。

**现状（实测）**：`internal/store/audit.go:12-23` 的 `AuditEntry` **没有 `id`**；`GET /audit` 只有 `from`/`to` + `page`/`size`（`internal/api/admin/audit.go`）。按 `time > last_seen` 会漏掉同毫秒的并发写入，`>=` 会重复，而深翻页在并发写入下会漂移（`OFFSET` 语义不稳定）。

**建议改动**：把 `audit_log` 现有的 rowid 显式暴露为 `id`（**单调递增且不回收**）；新增 `GET /audit?afterId=<int64>&limit=<int>`，与 `page`/`size` 互斥，按 `id ASC` 返回至多 `limit`（默认 500）条；响应 `{items[].id, nextAfterId, hasMore}`，空批时 `nextAfterId` 原样返回入参，`afterId` 是**排他**下界。

**验收**：增量同步“至少一次 + 无重复”。

---

### N2. 出站回调队列的可见性与重投

**需求**：模块 C/E 需要知道“回调死了”，并且能补投。

**现状（实测）**：`callbacks` 表已有 `Enqueue/Get/Due/MarkSent/MarkFailed/MarkRetry/Stats`，`/metrics` 也暴露队列深度，但**没有任何管理 API**（`internal/api/admin/admin.go` 的 `Mount` 中不存在 `/callbacks`）。esim42 后端停机超过 `max_attempts × retry_interval`（默认 5 × 30s = 2.5min）后，回调进入死信，下载/安装状态**永久丢失**且运维没有入口查看或补投。

**建议改动**：
- `GET /callbacks?state=pending|sent|failed|dead&tenant=&iccid=&from=&to=&page=&size&sort=created_at`，`payload` 返回**已解析的 JSON 对象**（不是原始字符串）。
- `POST /callbacks/{id}/retry` → `200 {id,state:"pending",attempts:0,nextAttemptAt}` / `404 not_found` / `409 conflict`（状态不是 dead/failed）。
- `POST /callbacks/retry-dead`，body `{tenant,before,limit}` → `{requeued}`。
- 重投重置 `attempts = 0` 并立即入队；写审计 `function=retryCallback`。

**验收**：死信可查、可补投；补投不产生重复的状态推进。

---

### N3. 租户删除的引用保护

**需求**：模块 D“删除运营商”必须是两阶段、有保护的操作。

**现状（实测）**：`internal/store/tenant.go:112-114` 的注释明写 “Resources keep their tenant_id (dangling by design: the registry is a control-plane view, not a referential parent)”；`internal/api/admin/tenants.go:137-149` 直接删除并返回 204。删除后 `GET /profiles?tenant=<已删>` 仍返回资源，而 `/upp?tenant=<已删>` 返回空，行为不一致且不可恢复。

**建议改动**：无 `force` 且存在任何引用 → `409 {"code":"tenant_in_use", "message":…, "usage":{"profiles":…,"templates":…,"poolEntries":…,"batches":…,"personalization":…}}`；`?force=true&reassignTo=<tenant|"">` 先把资源 `tenant_id` 批量迁移（空串 = 平台默认）再删，未注册的目标 → `400 unknown_tenant`；`GET /tenants/{id}` 增 `usage`，供 esim42 在删除前预警。esim42 侧 `credential_assignments` 也应计入 usage（`03` §11）。

**验收**：误删被拦；`force` 路径可审计地迁移或显式接受孤儿。

---

### N6. 管理 API 监听面收敛与密钥导出加固（部署约束）—— **【不做】**

> **决策**：本项**明确范围外**（§8.4 决策 11、§10.3 步骤 2.4），本轮不实施。以下“现状/建议改动/验收”仅保留为历史分析与将来重启时的参考，**不作为待办**。

**需求**：管理 API 无鉴权是既定前提（§0.1-4），因此必须用**默认值与护栏**把风险面收敛。

**现状（实测）**：`config/config.example.yaml:19,73` 的 admin `bind` 均为 `0.0.0.0`；`GET /personalization/export` 与 `?reveal=1`（`internal/api/admin/personalization.go`）没有显式确认；全仓无 `Cache-Control`。

**建议改动（本轮不做）**：
1. `config/config.example.yaml` 与 `docs/operations.md` 把 admin `bind` 默认改为 `"127.0.0.1"`，并写明“跨主机部署必须用容器网络或 mTLS 反代，不得直接暴露”。
2. 启动时若 `admin.bind` 不是 loopback 且 `audit.enabled == false`，打 `WARN`（“unauthenticated management API exposed on non-loopback address”）。
3. `GET /personalization/export` 与 `?reveal=1` 必须带 `X-RSP42-Reveal-Secrets: yes`，否则 `403` + `secret_reveal_not_confirmed`。若将来重启，护栏须同时覆盖 `GET /personalization?reveal=1`（该分支同样回明文 K/OPc）。
4. `/metrics` 与 `/healthz` 保持无鉴权（可接受）。

**验收（仅在重启该项时适用）**：即使 esim42 侧配置失误，误配置的反代也无法直接拖走全站 K/OPc。本轮的安全边界完全由 esim42 承担。

---

### N11. 解析 `additionalEuiccProfilePackageVersions`（仅用于 SEC）

**需求**：`01` §6.5 D5 需要判断某台设备是否 “V3-capable”，以便在 SEC 阶段决定是否放行。

**现状（实测）**：全仓 grep `additionalEuicc*` **零命中**；`internal/store/upp.go:114-116` 的 `major <= 0 → AnyForTenant()` 回退仍在。

**建议改动**：`internal/rsp` 的 `EuiccInfo2` 增 `additionalEuiccProfilePackageVersions [15] SEQUENCE OF VersionType OPTIONAL`；新增 `type Version struct{ Major, Minor int }`、`SupportedVersions()` = `{profileVersion} ∪ additional…`、`IsV3Capable()`；通过 session/timeline 把 `(profileVersion, additional[], uiccCapability)` 暴露给 esim42；**移除 `major<=0` 的 `AnyForTenant()` 回退**（“未知版本”不应静默挑模板）；`SelectBestFor` 入参改为版本集合（**接口预留**，**不要**现在实现双 major 选择逻辑）。

**验收**：声明 `(2,3)` + `additional=[{3,2}]` 的 eUICC 产生 `v3-capable-euicc` 标记，且 esim42 可从 timeline 读到该集合。

---

### N15. `ServicesList` 索引表补全到 V2.3.1 的 24 项

**需求**：`03` §3.1 的 `required_capability_bits_json` 与资格检查依赖完整的服务位；SGP.22 v2.7 Annex F 建议 SM-DP+ 在配置 service n°125 / DF SAIP 前检查 `getIdentity`（`uiccCapability` 位 22），其模板侧对应物正是 index 21。

**现状（实测）**：`internal/saip/header.go:101-119` 的 `Svc*` 常量止于 `SvcBERTLV`(18)，`internal/saip/header.go:237` 的循环上界同为 18；`serviceNames`（`internal/saip/header.go:225-231`）同样止于 18。索引 0–18 与 V2.3.1 的声明顺序逐项一致，因此是**纯扩展**。

**建议改动**：新增 19 `dfLink`、20 `cat-tp`、21 `get-identity`、22 `profile-a-x25519`、23 `profile-b-p256`（按 V2.3.1 ASN.1 拼写），引入 `svcMax` 并把它作为 `Services()` 的循环上界；补 24 项表驱动单测；顺带修正 `bertlv` → 规范拼写 `ber-tlv`（这是 `/upp/{name}/decoded` 的**对外契约变更**，需同步 esim42 的静态映射与契约快照）。**不要**为 V3.2 才引入的 5 项（`suciCalculatorApi`/`dns-resolution`/`scp11ac`/`scp11c-authorization-mechanism`/`s16mode`）预留常量。

**顺带一处真实缺陷**：`SvcTUAK256` 只声明、从未置位（`internal/saip/header.go:117`、`:230`），而 `RebuildMandatoryServices` 只按 `algo==1/2/3` 置 Milenage/TUAK128/USIM-test（`internal/saip/header.go:143-145`）→ 32 字节 K 的 TUAK-256 会得到**错误的服务位**。可对齐 pySim 的 `len(key) == 16 vs 32` 判定。

**验收**：含 `get-identity` 的 V2.3.1 模板在 `/upp/{name}/decoded` 的 `services[]` 中可见。

---

### N13. Annex A 模板表（V2.3.1 范围）+ 约束校验 + 测试向量

**需求**：模块 C 的“上传 SAIP”必须能在 rsp42 侧校验，且 rsp42 不能把不兼容/不合规的模板放进注册表。

**现状（实测）**：`internal/saip/` 下没有 `templates.go`（只有 `doc.go`/`element.go`/`files.go`/`header.go` 与 `personalization/`），`TODO.md` §2 记为未实现 → rsp42 只能改模板里已声明的文件，无法按 Annex A 校验，也没有 `SIZE(...)`/`INTEGER(0..n)` 之类的值域约束校验。

**建议改动**：
1. **V2.3.1 Annex B 模板表**：13 个模板 OID，全部**无版本维度**（另加 spec-version OID `2.23.143.1.1.2`）。V2.3.1 没有版本化子弧，因此基线内**没有模板版本失败面**。
2. `/upp/validate` 增约束校验（对齐 pySim `validation.py`）：首个 PE 必须 `header`、第二个 `mf`、末位 `end`；`header/mf/end/cd/telecom/usim/isim/csim/opt-*/df-saip/df-5gs` 单例；可选 PE 顺序（`opt-usim` 在 `usim` 后、`gsm-access`/`phonebook`/`df-5gs`/`df-saip` 在 `usim` 后、`opt-csim` 在 `csim` 后）；mandatory-services ↔ PE 存在性一致；AKA 算法 ↔ 服务位一致（含 TUAK-128/256）；`identification` 唯一；`File` 内 `doNotCreate` 互斥且 `fileDescriptor` 优先；**`gfste[]` 必须全部落在 13 个模板 OID 内，且拒绝带版本子弧**（如 `2.23.143.1.2.13.2`，说明来自更高规范）；非 V2.3.1 PE（`BE`/`BF20`/`BF21`/`BF1F`/`BF22`）带 `mandated` → warning。
3. `testdata/upp/` 补 **V2.3.1 专用测试向量**（含 DF 5GS、DF SAIP、`get-identity` 服务位）。
4. 顺带修 `FileHandle.Body()` **忽略 `fillFileOffset`** 的问题（`internal/saip/files.go:59-67`）：offset 分片的模板文件无法被 `Body()` 忠实还原，需补定向测试。

**验收**：缺 `end`、PE 顺序错、带版本子弧的模板 → `/upp/validate` 给出明确错误；现有 TS.48 向量仍全部通过。

---

### N17. `SdKey*` 与 `MncLen` 个性化

**需求**：真实 MNO-SD 场景需要注入 GP 安全域密钥集；`EF.AD` 的 MNC 长度需要可个性化。二者在 V2.3.1（`PE-SecurityDomain`、`EF.AD`）中都已存在，与基线无关。

**现状（实测）**：`TODO.md` §2 记为未实现；`internal/saip/personalization/personalization.go` 与 `internal/saip/personalization/csv.go` 中无对应字段（当前只覆盖 ICCID/IMSI/K/OPc/算法/PIN/PUK/ADM/SPN/PLMN/MSISDN/ACC/`filePatches`）。

**建议改动**：新增 `SdKey*`（SD/MNO-SD 密钥集、KVN、key usage qualifier，落在 `PE-SecurityDomain`）与 `MncLen`（`EF.AD` bit 4，FID `6F3A`）；同步 `/upp/{name}/schema` 的字段目录（与 N4 一起解决“目录 ≠ 模板可绑定字段”）；更新 `docs/coverage.md` 的 SAIP 个性化行。

**验收**：含 `PE-SecurityDomain` 的模板可注入 SD 密钥集；`EF.AD` 的 MNC 长度可个性化。

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

### 3.1 第二轮可选项（N4 / N5 / N7–N10）

| # | 改动 | 现状（实测）与建议 |
|---|---|---|
| N4 | `/upp/{name}/schema` 的模板级字段可用性 | `fields[]` 是**全局静态目录**（`internal/api/admin/upp_tools.go:20-29` 的 `uppFieldSchema`），与具体模板无关 → 模板里没有 `EF.SPN` 时编辑器仍展示 `spn`；`iccid.required=true`（`internal/api/admin/upp_tools.go:33`）还与凭据池流程冲突。**建议**：每项增 `applicable`(bool) / `targets[]`（命中的 EF/PE 名，空数组 = 不适用）/ `requiredIn[]`（`["render"]` \| `["render","import"]` \| `[]`）/ `note`；`applicable` 由 `inspection.files[]`/`elements[]` 推导；保留 `required`（= `requiredIn.includes("render")`）以兼容 |
| N5 | `/upp/render` 支持未入库模板 | 现状强制 `name`（`internal/api/admin/upp_tools.go:98-121`，空则 400），上传向导无法“校验 → 预览 → 保存”。**建议**：请求体接受 `{name,…}` 或 `{data:"<base64 DER>",…}` 二选一；同时给出 → `400 invalid_request`；`data` 路径不得落库，审计 `function=renderUPP, subject="<ad-hoc>"` |
| N7 | 统计与排序参数的契约补全 | 实测：openapi 中 `profiles/stats` 的 `groupBy` enum = `[state, day, tenant]`，**缺 `profile_type`**（而 `internal/store/stats.go:36-41` **已支持** `profile_type`）；`components.parameters.sort` 的 enum 与白名单（`internal/store/profile.go:217`）**均缺 `tenant`/`-tenant`**；`internal/api/admin/admin.go:181` 仍有 catch-all `"error"` 码。**注**：esim42 称 `/iccid-pool/stats` 未文档化 `tenant`，实测**已列**，该项无需改动 |
| N8 | SM-DS 事件的管理写接口 | 现仅只读 `GET /events`（`internal/api/admin/ds.go:19`），写入只走 ES12（mTLS + Registered-ID SAN）。**建议**：`POST /events`（`eventId` 省略时生成 `EVT-<…>`；重名 → `409 event_id_in_use`）、`DELETE /events/{id}`；审计 `function=registerEvent`。**不阻塞首期**（首期靠 `ConfirmOrder` 自动注册） |
| N9 | HTTP 延迟直方图 | `internal/metrics/metrics.go` 无 Histogram 类型，esim42 无法对重查询（`/profiles/export`、`/profiles/{iccid}/timeline`、`/upp/{name}/decoded`）做 SLO。**建议**：`rsp42_admin_http_request_duration_seconds{route,method,status}`（`route` 用 chi 的 pattern 模板，避免高基数）与 `rsp42_es2p_http_request_duration_seconds{function}` |
| N10 | 明文密钥路径的显式契约 | **【不做】**（§8.4 决策 11、§10.3 步骤 2.4）：实测无 `Cache-Control`、`docs/interfaces.md` 未标注；本轮维持现状，不引入 `X-RSP42-Reveal-Secrets` 护栏、`Cache-Control: no-store` 与 secret-bearing 标注，安全边界由 esim42 承担 |

### 3.2 代码级一致性修复（C 清单，与 N 清单并行）

> 这些是核对 SGP.22 v2.7 原文与代码时实测发现的问题，esim42 未逐条点名，但会直接影响其上层的分支判断与契约生成。

| # | 问题 | 现状（实测） | 建议 |
|---|---|---|---|
| C1 | ES2+ `downloadOrder.pprIds` 与“零 JSON body 扩展”原则冲突 | `internal/api/es2plus/handlers.go:59-67` 仍接受该私有 body 成员；而 SGP.22 v2.7 Table 22 的 DownloadOrder Additional Input Data **只有 `eid`/`iccid`/`profileType`**（`pprIds` 仅出现在 §5.7 的 `RulesAuthorisationTable`），与 §8.2 的自我约定矛盾 | **已定：选 ①** —— **删除该成员**，PPR **只走管理 API / `profiles.ppr_ids`**；同步删除 PPR 覆盖分支与 `config` 中“订单可覆盖 pprIds”的注释，`docs/interfaces.md`/openapi 不再声明该私有扩展。见 §10.6 |
| C2 | `profileType` 解析静默降级 | `internal/api/es2plus/handlers.go:293-296`：不含 `/` 的值直接 `return "", nil`，回落版本选择 | 至少记审计/指标 `profileType-unparsed`，否则运营商拼写错误会表现为“下发了他人的模板”而不是明确失败 |
| C3 | `8.2.1/3.8` 语义重载 | `internal/rsp/errors.go:61` 同时承载“池耗尽”与“租户 `profile_quota` 用尽”，且 `8.2.1/3.8` 不在 Table 24 的 DownloadOrder 专有码表内（esim42 `02` §10 q2 已提问） | 拆码（如 `8.2.5/3.7` No more Profile available），或把配额错误做成结构化字段 |
| C4 | `8.2.6/3.7` 语义错位 | `internal/rsp/errors.go:62`：`8.2.6` 是 Matching ID、`3.7` 是 Unavailable，用于“数据库更新失败”不贴切 | 换用更贴切的主体/原因 |
| C5 | `internal/asn1/doc.go` 陈述过期 / 两层并行 ASN.1 抽象 | `internal/asn1/doc.go:1` 仍写 “wraps `github.com/euicc-go/bertlv`”，但该包实际自成一层，仅 `internal/asn1/construct.go:7` 还 import bertlv（`internal/rsp/types.go:15`、`internal/rsp/notification.go:6`、`internal/crypto/ecdsa.go:15` 亦直接 import） | 修 doc；与 `TODO.md` §3.1「收紧 `bertlv` 抽象」合并，并提到与 N11/N12 同批处理 |
| C6 | `FileHandle.Body()` 忽略 `fillFileOffset` | `internal/saip/files.go:59-67` 只拼接 `fillFileContent`；`SetBody`（`:71-81`）会删除 offset 并线性化 | 补 offset 分片模板的定向回归测试（已并入 N13 第 4 条） |
| C7 | `ServicesList` 命名 `bertlv` vs 规范 `ber-tlv` | `internal/saip/header.go:231` | 与 N15 同批修正；这是 `/upp/{name}/decoded` 的对外契约变更 |
| C8 | BER 不定长（indefinite length）被显式拒绝 | `internal/asn1/tlv.go:152`；长度字段 `> 4` 字节亦报错（`internal/asn1/tlv.go:155-157`）。esim42 `01` §4.1 称 SAIP 使用 `AUTOMATIC TAGS` + `EXTENSIBILITY IMPLIED`、多字节 high-tag-number，且实际数据会出现不定长编码 | 若采纳该结论则需支持；否则在 `TODO.md` 登记为「已知边界 + 影响面」，与 `TODO.md` §4.3 的 `bertlv` 多字节长度边界单测合并 |
| C9 | V3.4/3.4.1 的 PE tag 常量缺失且未登记 | `bf1f`（df-5gprose）、`bf22`（ssim）在 `internal/saip` **零命中**，`TODO.md` 也无 V3 相关条目 → 能无损解析，但对 `PEName`/`isTemplatePE`/`RebuildMandatoryGFSTEList`/`/upp/{name}/decoded` 不可见 | 至少在 `TODO.md` 登记为**明确范围外**（对应 §0.4），避免后人当成遗漏缺陷 |
| C10 | 无值域约束校验 | 树结构不查 schema，无 `SIZE(...)`/`INTEGER(0..n)` 校验，也没有 pySim `validation.py` 的对等物 | 归入 N13 的实现范围 |
| C11 | `RebuildMandatoryServices` 覆盖不全且边界未文档化 | `internal/saip/header.go:125-146` 只处理 7 位；GFSTE 由独立的 `RebuildMandatoryGFSTEList`（`internal/saip/header.go:170`）负责 | N15 补到 24 项后写明两者职责边界，否则会出现“补了常量但不会自动置位” |

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

-- 第二轮（N 清单）的数据库影响：均为“无需新列”，只有暴露与查询语义的改动
-- N1  审计游标：不新增列；把 audit_log 现有 rowid 显式暴露为 id（单调、不回收）
-- N2  回调队列：callbacks 表及其 Enqueue/Due/MarkSent/MarkFailed/MarkRetry/Stats 已存在（00001），无需迁移
-- N3  租户删除保护：不新增列；需按 tenant_id 对 profiles / upp_templates / iccid_pool / download_batches / personalization 做引用计数与批量改属
-- N11 SEC：不新增列；additionalEuiccProfilePackageVersions 可复用 session/timeline 承载（或由 session 新增 JSON 列）
-- N16 版本上限：不落库；只在 /upp 的写入路径做校验（配置 profiles.allowed_saip_versions）
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

### 5.1 第二轮（N 清单）新增/变更

| 方法 | 路径 | 变更 | 对应 |
|---|---|---|---|
| GET | `/audit?afterId=&limit=` | 单调增量游标；响应含 `items[].id` / `nextAfterId` / `hasMore`；与 `page/size` 互斥、按 `id ASC` | N1 |
| GET | `/callbacks` | 新端点：回调队列（`state=pending\|sent\|failed\|dead`，`tenant`/`iccid`/时间范围/分页/排序，`payload` 返回已解析对象） | N2 |
| POST | `/callbacks/{id}/retry`、`/callbacks/retry-dead` | 单条/批量重投；重置 `attempts`，审计 `retryCallback` | N2 |
| DELETE | `/tenants/{id}` | 改为存在引用时 `409 tenant_in_use` + `usage`；新增 `?force=true&reassignTo=<tenant\|"">` | N3 |
| GET | `/tenants/{id}` | 响应增 `usage`（同 `tenant_in_use` 结构） | N3 |
| POST | `/upp` | 超版本 → `409 saip_version_not_supported`（+`details.{templateVersion,maxSupported}`） | N16 |
| POST | `/upp/validate` | 超版本时保持 `valid:true` 但返回 `warnings[]` | N16 |
| GET | `/upp/{name}/schema` | `fields[]` 增 `applicable`/`targets[]`/`requiredIn[]`/`note`；`iccid.required` 与凭据池流程解耦 | N4 |
| POST | `/upp/render` | 请求体接受 `data`（base64 DER）作为 `name` 的替代；二者同时给出 → `400` | N5 |
| GET | `/profiles/stats`、`/audit/stats` | `groupBy` enum 补全（profiles 增 `profile_type`）；`sort` 白名单增 `tenant`/`-tenant`；删除 catch-all `error` 码 | N7 |
| POST/DELETE | `/events`、`/events/{id}` | SM-DS 事件管理写接口（重名 → `409 event_id_in_use`），审计 `function=registerEvent` | N8 |
| GET | `/personalization`、`/personalization/{iccid}?reveal=1`、`/personalization/export` | 需 `X-RSP42-Reveal-Secrets: yes`，否则 `403 secret_reveal_not_confirmed`；响应 `Cache-Control: no-store`；审计不记密钥 | N6/N10（**不做**，§10.3 步骤 2.4） |
| — | （无端点） | `profile_version_not_supported` 作为 timeline/审计可见的稳定错误码 | N12 |

> 管理 API **不引入鉴权**（见 §0.1-4）。因此 `/personalization` 的 K/OPc 导出（`?reveal=1`、`/export`）只依赖内网边界，esim42 必须确保该 API 不对外暴露/不被网关转发。N6/N10 的“默认值与护栏”补强**本轮明确不做**（§8.4 决策 11、§10.3 步骤 2.4），安全边界完全由 esim42 承担。

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

### 6.1 第二轮（N 清单）的 ES2+ 影响

| 函数 | 变更 | 规范依据 / 兼容性 |
|---|---|---|
| `downloadOrder` | **移除私有 body 成员 `pprIds`**（**已定**，见 C1/§10.6）：PPR 只走管理 API / `profiles.ppr_ids` | SGP.22 v2.7 Table 22 的下载输入仅 `eid`/`iccid`/`profileType`；`pprIds` 只出现在 §5.7 的 `RulesAuthorisationTable`。见 §8.2 与 C1 |
| `downloadOrder` | `profileType` 不含 `/<template>` 时**不再静默回落**：至少记审计/指标（`profileType-unparsed`），避免拼写错误表现为“下发了他人的模板” | 见 C2；与 N16/N12 同为“不静默降级”原则 |
| `authenticateClient`（间接，下载末期之前） | 无兼容模板时以 `8.2.6/3.8` + 可读 message 干净失败，且**不生成任何 BPP 段** | N12；SGP.22 无直接对应码，**不要**复用 `8.8.5/4.10`（unsupported curve） |
| 全部 | 版本上限在 `/upp` 侧拦截（N16）是**第一道防线**，ES2+/ES9+ 的运行期校验（N12）是第二道；两者必须同时存在 | N16/N12 |

---

## 7. 实施里程碑建议

### 7.1 第一轮（G 清单）—— 已全部落地

| 里程碑 | 内容 | 阻塞 esim42 的什么 |
|---|---|---|
| **M1（租户与审计）** | G2 租户维度、G8 actor 修复、G17 文档对齐 | 模块 C/D/E 全部 |
| **M2（下单与领取闭环）** | G3 `profileType` 选择、G4 EID 回写、G5 重发幂等、G6 ICCID 池加固、G19 标准一致性修正、G20 SM-DS 事件透视（含 `rsp42 smds` 角色启用） | 模块 A/B/C 的领取与看板 |
| **M3（模板与个性化）** | G7 schema/validate/render/clone + PLMN 等字段、G6 凭据池/IMSI 池 | 模块 C 的可视化模板创建与批量开卡 |
| **M4（运维与契约）** | G8 统计接口、G10 OpenAPI/错误码、G11 metrics、G12 BEGIN IMMEDIATE | 模块 C/D 看板与 esim42 SDK 生成 |

### 7.2 第二轮（N 清单）—— 建议顺序

esim42 `02` §7.2 与 `06` §13.1 给出的顺序，与第一轮的 M1–M4 **并行不冲突**：

| 批次 | 内容 | 阻塞 esim42 的什么 |
|---|---|---|
| **批 1（P0）** | **N16 → N12**（同批做 N11 的接口预留：`Version` 集合入参、移除 `major<=0` 回退） | esim42 M2 的硬性退出条件；esim42 M3 的“不服务不适配机群”承诺 |
| **批 2（P1，防数据丢失/误操作）** | **N2 → N3 → N1**（**N6 范围外**，见 §10.3 步骤 2.4） | 模块 C/E 的回调可靠性、模块 D 的误删防护、模块 E 的增量审计同步 |
| **批 3（P1，SAIP 能力）** | **N15 → N13 → N17** | 模块 C 的模板上架校验与动态表单、MNO-SD 密钥集 |
| **批 4（P2）** | **N4 → N5 → N7 → N8 → N9**（**N10 随 N6 范围外**） | 模块 C 的上传向导体验、契约生成与 SLO |
| **并行（工程化）** | C1–C11（§3.2）与 §3 的文档项 | 契约漂移、错误分支正确性 |

**验收基线**：esim42 侧完成一次端到端（匿名领取 → LPA 下载 → 安装 → 看板可见 → 审计可查 → 取消/回池）的联调，全链路租户归属正确、幂等重放安全；外加 esim42 `02` §9 的 A1–A25（其中 A13–A17 依赖批 3 的 N13/N15/N17）。

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
| 7 | SAIP 基线版本 | **V2.3.1（包内编码 `(2,3)`）**（esim42 `01` §6.5 D1）；rsp42 据此增加版本上限（N16）与运行期兼容性干净失败（N12） | 新增 N16/N12（第二轮仅有的两个 P0）；SAIP V3.x 与 Annex F 降级构造（N14）列为范围外（§0.4） |
| 8 | 版本上限的配置形态 | **列表** `profiles.allowed_saip_versions: ["2.3"]`，**不是**标量 `max_saip_version` | 与 esim42 `06` §13.1 R1 一致（零成本预留，将来加 `"3.2"` 不需迁移）；需 esim42 修正 `01` §6.5 D2 的标量表述 |
| 9 | 双 major 选择逻辑 | **明确不做**，只做接口预留：`SelectBestFor` 收版本集合、移除 `major<=0` 的 `AnyForTenant()` 回退 | N11 的落地形态；esim42 `06` §13.1 已把双 major 登记为“未来规划”，现阶段不得实现 |
| 10 | 回调队列是否可重投 | **做**（N2）：新增管理 API，让死信可查、可补投 | rsp42 队列 API + esim42 对账任务共同构成回调可靠性；`06` 的 SLO 以此为前提 |

### 8.2 决策 3 的规范依据（备查）

- **ES2+ 不能新增 `tenantId` JSON body 字段**：SGP.22 v2.7 §6.5.2.1 对 `ES2+.DownloadOrder` 的 body schema 只定义 `eid`、`iccid`、`profileType`（Table 22 的 MOC 为 O/C/C）；规范没有 `additionalProperties: false`，也**没有**“接收方 SHALL 忽略未知成员”的向前兼容条款（对比 Activation Code 明确写了 “Device SHALL ignore … further parameters”）。本仓库 `downloadOrder.pprIds`（`internal/api/es2plus/handlers.go:64-66`）即此类既有私有扩展——v2.7 中 `pprIds` 只出现于 `RulesAuthorisationTable`（§5.7），并不在 DownloadOrder 中。
- **私有信息放 HTTP 头是规范显式允许的**：SGP.22 §6.2 “HTTP POST request and response MAY contain additional header fields. Their use is out of scope of this specification.” → `Idempotency-Key` 等走表头，body 成员不走。
- **承载分工**：租户 ← `functionRequesterIdentifier`（§6.5.1.3，type string、无格式约束）；模板/产品 ← `profileType`（§6.5.2.1 “content free information defined by the Operator” + Table 22 NOTE）；幂等 ← Table 24 NOTE + HTTP 头；`externalRef` ← 不上线，esim42 以 `downloadOrder` 返回的 ICCID 作为自身外键。
- **残留风险（已知并接受）**：`functionRequesterIdentifier` 是调用方自述字段，租户归属实质是“信任 esim42 后端”；在决策 5 的内网单后端前提下可接受。**“运营商绕过 esim42 直连 rsp42”不在支持范围内**：每运营商客户端证书明确不做（§8.4），因此该拓扑一旦出现，必须改为每运营商独立部署 rsp42（而不是给 rsp42 加证书映射）。

### 8.3 每运营商客户端证书（**明确不做**——仅作历史备查，不再评估）

- **rsp42 侧：低。** mTLS 管线已存在（`es2p.tls.client_ca_file` + `RequireAndVerifyClientCert`，`internal/config/config.go:56`、`internal/cli/server.go:71-77`）；身份提取可复用 ES12 `callerOID`（`internal/api/es12/handlers.go:87-92`）与 `cert.RegisteredIDs`（`internal/cert/chain.go:96`）。只需加“证书主体 → 租户”映射，约 0.5–1 人日，无密码学新代码。限制：`client_ca_file` 为**单一 CA**（运营商自带 CA 需改成 CA 列表）；无 CRL/OCSP（见 `docs/coverage.md` 的已知偏差），吊销只能撤映射/换 CA。
- **esim42 侧：中。** TLS 握手早于 HTTP 请求，无法按请求选证书 → 每运营商一个 `http.Client`/transport（`NewClient(..., hc)` 已支持，`internal/api/es2plus/clientlib.go:27-30`）。主要成本在**证书生命周期**：签发、分发、密钥保管、轮换、撤销、运营商上下线。
- **结论（已收敛为“不做”）**：决策 3 选择 `functionRequesterIdentifier`，且 §8.4 决策 8 明确**不做**每运营商证书。本节其余内容只保留为历史分析，不再作为候选方案评估；若将来真出现“运营商直连 rsp42”的需求，应重新立项评估，而不是在此处补丁式启用。

### 8.4 明确不做（决策 7–11）

| # | 问题 | 结论 | 落地表现 |
|---|---|---|---|
| 7 | 数据库后端 | **只做 SQLite**。PostgreSQL/MySQL 等**明确不做** | `profiles.repository` 仅接受 `sqlite`；配置校验对其它取值直接报错并说明原因。不保留“抽象后端”的暗示 |
| 8 | 多副本部署 | **明确不做**。单进程、单数据库文件 | 无 leader 选举、无分布式锁；GC/ticker 在进程内。横向扩容需重新立项 |
| 9 | 每运营商客户端证书 | **明确不做**。ES2+ 租户归属只用 `functionRequesterIdentifier` 映射 | §8.3 降级为历史备查；“运营商直连 rsp42”不在支持范围 |
| 10 | rsp42 侧限流 | **明确不做**（不提供 429 语义） | 限流由 esim42 前置承担；rsp42 只做资源级配额硬校验（`tenants.template_quota` / `profile_quota`） |
| 11 | 管理 API 监听面收敛与密钥导出护栏（N6/N10） | **明确不做**。admin `bind` 默认值保持现状；不引入 `X-RSP42-Reveal-Secrets: yes` 护栏、`Cache-Control: no-store` 与 secret-bearing 标注 | 安全边界完全由 esim42 承担（§0.1-4、§8.1 决策 5）：esim42 必须保证管理 API 不被反向代理、网关或前端暴露。见 §10.3 步骤 2.4 |

> 说明：前四项此前在本文中写作“不实施/仅备查/未来加固”，容易被读成“以后可能做”；决策 11 为本次复核后新增的范围收敛项。现统一收敛为**范围外**：文档不再把它们列为待办，代码也不再为它们预留会被误用的配置语义。

---

## 附：现状能力对照（esim42 需求 → rsp42 是否已具备）

### 附一：第一轮（G 清单）改造前快照

> 下表是**改造前**的判定，保留为历史对照；实际落地情况见 §9。

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

### 附二：第二轮（N 清单）当前判定

> 判定基于本仓库当前代码（2026-10-14，commit `f3232da` 之后）。G 清单对应项的状态见 §9。

| esim42 需求（N 编号） | 现状 | 结论 |
|---|---|---|
| OpenAPI 契约完整 | 完整 OpenAPI 3.0（`internal/api/admin/openapi.json`，`//go:embed` + 校验测试） | ✅ G10；N7 的 enum 补全待做 |
| 监控指标 | `internal/metrics` + 管理监听 `GET /metrics` | ✅ G11；N9 的延迟直方图待做 |
| SAIP 版本上限（N16） | 无（任意版本可入库） | ❌ **P0** |
| 运行期版本兼容失败（N12） | 回落不校验版本，会把不兼容模板交给 eUICC | ❌ **P0** |
| 审计单调游标（N1） | `AuditEntry` 无 `id`；只能按时间 + 分页 | ❌ P1 |
| 回调队列管理 API（N2） | 无（仅内部方法与 `/metrics` 深度） | ❌ P1 |
| 租户删除引用保护（N3） | 悬空引用删除 | ❌ P1 |
| 管理 API 密钥导出护栏（N6/N10） | 无（仅 `?reveal=1` 约定） | 范围外（§8.4 决策 11、§10.3 步骤 2.4） |
| `additionalEuiccProfilePackageVersions`（N11） | 未解析 | ❌ P1 |
| `ServicesList` 24 项（N15） | 止于 18 项 | ❌ P1 |
| Annex A 模板表（N13） | 未内置 | ❌ P1 |
| `SdKey*` / `MncLen` 个性化（N17） | 未实现 | ❌ P1 |
| schema 模板级字段可用性（N4） | 全局静态目录 | ❌ P2 |
| `/upp/render` 未入库模板（N5） | 不支持 | ❌ P2 |
| 统计/排序契约补全（N7） | 部分（`/iccid-pool/stats` 的 `tenant` 已列） | ⚠️ P2 |
| SM-DS 事件管理写接口（N8） | 只读 | ❌ P2 |
| HTTP 延迟直方图（N9） | 无 | ❌ P2 |
| Annex F 降级构造（N14） | — | 范围外（§0.4） |

---

## 9. 实施状态（rsp42 侧，已落地）

> 本节记录本文档各项改造在本仓库中的落地情况。图例：`[x]` 已实现并有测试；`[~]` 部分实现/已登记后续；`[ ]` 未做。
> **§9 的状态表与 §9.1–§9.3 覆盖第一轮 G 清单；第二轮 N 清单见 §9.4。**

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

### 9.2 明确不做（决策 7–11，见 §8.4）

以下五项**不在本项目范围内**，不再作为“待办/未来加固”跟踪，相关文档与配置已按“仅支持当前形态”收敛：

1. **PostgreSQL / 其他数据库后端**：仅 SQLite。`profiles.repository` 只接受 `sqlite`，其他取值在配置校验阶段报错。
2. **多副本部署**：单进程、单数据库文件、无 leader 选举/分布式锁。需要横向扩容时应重新立项，而不是在当前形态上加锁。
3. **每运营商客户端证书**：ES2+ 租户归属只用 `header.functionRequesterIdentifier`（§8.3 降级为历史备查）。
4. **rsp42 侧限流 / 429 语义**：限流由 esim42 前置承担；rsp42 只做资源级配额硬校验（`tenants.template_quota` / `profile_quota`）。
5. **管理 API 监听面收敛与密钥导出护栏（N6/N10）**：admin `bind` 保持现状，不引入 `X-RSP42-Reveal-Secrets` 护栏、`Cache-Control: no-store` 与 secret-bearing 标注。安全边界完全由 esim42 承担（§8.4 决策 11、§10.3 步骤 2.4）。

### 9.3 第一轮（G）：尚未实施的 P2

**无。** 文档 §3 的 G13–G18 已全部落地：G13（ACR 调用方侧接线）、G14（MatchingID 轮换）、G15（配额硬校验）、G16（`GET /eids` / CSV 导入）、G18（模板版本与回滚）均已完成；G17 文档已对齐。§9.2 列出的四项为**明确不做**（范围外）。

> ⚠️ 本结论**只覆盖第一轮 G 清单**。第二轮 N 清单：**批 1（N16/N11/N12）、批 2（N2/N3/N1）已落地**（见 §9.4）；**N6/N10 为范围外**（§8.4 决策 11）；**批 3（N15/N13/N17）与批 4（N4/N5/N7/N8/N9）待实施**。§3.2 的 C1–C11 仍待处理（其中 **C1 已定方案**：删除 `pprIds`，见 §10.6）。第二轮的分步实施计划与已收敛决策见 **§10**。

### 9.4 第二轮（N）：实施状态

> 来源：`../esim42/todo/02` §7.2 与 `01` §8。判定均为本仓库当前代码（commit `f3232da` 之后）逐条实测。
> 图例：`[x]` 已实现并有测试；`[~]` 部分实现；`[ ]` 未做。

| # | 项 | 状态 | 现状证据 |
|---|---|---|---|
| N16 | SAIP 版本上限 | `[x]` | `profiles.allowed_saip_versions`（`internal/config/config.go`、`config/config.example.yaml`）+ 唯一 choke point `internal/service/saip_version.go`；`api/admin/upp.go`（`putUPP` 409 `saip_version_not_supported` + `details`）、`api/admin/upp_tools.go`（`validateUPP` warning、`clone`/`promote`/`restore` 同校验）、`internal/cli/admin_upp.go`（CLI import 同策略）；迁移 `00011` 无关，仅版本比对 `(major,minor)` |
| N12 | 版本不兼容干净失败 | `[x]` | `internal/service/download.go` `resolveUPPTemplate`/`loadUPP`（四级回落均校验，显式 pin 不回落）；`ErrProfileVersionNotSupported`；`rsp.CodeProfileVersionNotSupported`（8.2.6/3.8）；`CMAE.noteVersionFailure` 写审计 `interface=es9p, function=authenticateClient, outcome=Failed` 并计数；`AuthenticateClient` 提前干净失败；迁移 `00011` |
| N1 | 审计单调游标 | `[x]` | `store.AuditEntry.ID` + 所有 SELECT/scan 补 `id`（`internal/store/audit.go`）；`ListAfterID`（排他下界、`id ASC`）；`GET /audit?afterId=&limit=` 响应 `{items[].id, nextAfterId, hasMore}`，与 `page`/`size` 互斥。**无需迁移**：`audit_log.id` 本就是 `INTEGER PRIMARY KEY AUTOINCREMENT`（`00001_init.sql:109`），id 单调不回收 |
| N2 | 回调队列管理 API | `[x]` | `store.CallbackFilter`/`ListFiltered`/`Requeue`/`RequeueDead`（`internal/store/callback.go`，tenant/iccid 走 `json_extract(payload_json,…)`，**无需迁移**）；`api/admin/callbacks.go` + `Mount`：`GET /callbacks`（`payload` 已解析对象）、`POST /callbacks/{id}/retry`（非 dead/failed → 409）、`POST /callbacks/retry-dead`；审计 `retryCallback` |
| N3 | 租户删除引用保护 | `[x]` | `store.TenantUsage`/`Usage`/`DeleteWithReassign`（`internal/store/tenant.go`）；`api/admin/tenants.go`：无 `force` 且被引用 → `409 tenant_in_use` + 顶层 `usage`；`?force=true&reassignTo=<tenant\|"">`（未注册 → `400 unknown_tenant`，自指 → `400 invalid_request`）；`GET /tenants/{id}` 增 `usage`。esim42 侧 `credential_assignments` 仍需 esim42 自行计入 |
| N6 | admin 监听面 / 密钥导出加固 | `—` | **范围外**（§8.4 决策 11、§10.3 步骤 2.4）；现状：`config/config.example.yaml:19,73` = `0.0.0.0`，无 reveal 头校验，**本轮不改** |
| N11 | `additionalEuiccProfilePackageVersions` | `[x]` | `internal/rsp/types.go`（`EUICCInfo2` 解析 `[15]`、`SupportedVersions()`、`IsV3Capable()`）+ `internal/rsp/version.go`（`Version`）；`store.SelectBestFor` 改版本集合入参并移除 `major<=0 → AnyForTenant()` 回退；会话持久化 `euicc_profile_version`/`euicc_supported_versions`/`uicc_capability`（迁移 `00011`）；`v3-capable-euicc` 指标 |
| N15 | `ServicesList` 24 项 | `[ ]` | `internal/saip/header.go:101-119`、`:237` 止于 18；`SvcTUAK256` 从未置位 |
| N13 | Annex A 模板表 + 约束 + 向量 | `[ ]` | `internal/saip/` 无 `templates.go`；`TODO.md` §2 |
| N17 | `SdKey*` / `MncLen` | `[ ]` | `TODO.md` §2 |
| N4 | schema 模板级字段可用性 | `[ ]` | `internal/api/admin/upp_tools.go:20-29` 为全局静态目录 |
| N5 | `/upp/render` 未入库模板 | `[ ]` | `internal/api/admin/upp_tools.go:98-121` 强制 `name` |
| N7 | 统计 / 排序契约补全 | `[~]` | `profiles/stats` 的 enum 缺 `profile_type`；`sort` 缺 `tenant`/`-tenant`；catch-all `"error"` 仍在（`internal/api/admin/admin.go:181`）；`/iccid-pool/stats` 的 `tenant` **已列** |
| N8 | SM-DS 事件管理写接口 | `[ ]` | `internal/api/admin/ds.go:19` 仅只读 |
| N9 | HTTP 延迟直方图 | `[ ]` | `internal/metrics/metrics.go` 无 Histogram |
| N10 | 密钥端点显式契约 | `—` | **范围外**（随 N6，§10.3 步骤 2.4）；现状：无 `Cache-Control`、`docs/interfaces.md` 未标注，**本轮不改** |
| N14 | Annex F 降级构造 | — | **范围外**（§0.4），不预留代码位/开关 |

**代码级一致性（C1–C11，见 §3.2）**：全部未处理；其中 **C1 已定方案**（删除 `pprIds`，PPR 只走管理 API / `profiles.ppr_ids`，见 §10.6），其余见 §10.6 的处理计划。

**本轮新增的范围收敛项**：**N6/N10 明确不做**（§8.4 决策 11、§10.3 步骤 2.4），状态记为 `—`（范围外），不再作为“以后再说”的备选项。

**与 `TODO.md` 的优先级错位（需同步修正）**：
- `TODO.md` §2 把“SAIP 完整模板表（FID/文件名/大小/AID/ARR/UST 默认值）”与“`SdKey*`/`MncLen`”记为 **P2**，而 esim42 定为 **N13 / N17 = P1**（且 `TODO.md` 只把它们当“个性化增强”，esim42 把它们当模板上架校验与 MNO-SD 能力）。
- `TODO.md` §2 的 `CancelSession` 显式验签 / `smdpOid` 校验与 Brainpool P256r1 两项，esim42 **未提出要求**（属规范完整性/自研，应标注“非 esim42 阻塞项”）。
- `TODO.md` 中**没有任何 N 编号**条目，第二轮的 17 项需要一并登记（其中 N6/N10 按“范围外”登记）。

---

## 10. 第二轮实施计划（分步）与已定决策

> 本节把 §0.3 的 N 清单与 §3.2 的 C 清单落成可执行步骤，并记录本次复核后收敛的工程决策。
> 图例：`【不做】` = 明确范围外；`【已定】` = 决策已收敛，实施时不再讨论。
> **DoD（每步）**：代码 + 定向测试 + `openapi.json`（如动接口）+ 相关文档同步 + `go vet ./... && go test ./...` 全绿。
> 迁移文件自 **00011** 起追加（当前最大 `00010`），保持追加式，不 squash `00001`（理由同 §9.1）。

### 10.1 批 0：地基与口径（无代码产出）

1. **N11 的规范依据**：以 `refs/SGP.22-v2.7-.pdf` §5.7.6 为准（`additionalEuiccProfilePackageVersions [15] SEQUENCE OF VersionType OPTIONAL`，`VersionType ::= OCTET STRING(SIZE(3))`）。`refs/pysim/pySim/esim/asn1/rsp/rsp.asn` 是删减版、**缺**该字段，不得作为依据。
2. **会话版本列的必要性**：`loadUPP` 在 `GetBoundProfilePackage` 阶段执行，届时只有 `sessions` 行；eUICC 版本仅在 `AuthenticateClient` 的 `ca.Signed1.EuiccInfo2` 可见 → 必须经 `00011` 持久化（见 §10.7）。
3. **choke point 约定**：SAIP 版本校验统一收敛到一个 `service` 函数，禁止只在 handler 内联（否则 CLI 导入等路径会绕过）。

### 10.2 批 1（P0）—— **已落地**（见 §9.4）

#### 步骤 1.1 — N16：SAIP 版本上限 `≤(2,3)`

- **配置**：`internal/config/config.go` 增 `profiles.allowed_saip_versions`（**列表**，默认 `["2.3"]`）并在 `Validate` 中校验格式；`config/config.example.yaml` 同步。比较**只按 `(major, minor)`**，注释写明“V2.3.1 是文档修订号、包内与 V2.3 同形”。
- **唯一 choke point**：新增 `internal/service/saip_version.go`（`SAIPVersion` / `ParseSAIPVersion` / `AllowedSAIPVersion`），覆盖：
  - `internal/api/admin/upp.go` 的 `putUPP`；
  - `internal/api/admin/upp_tools.go` 的 `cloneUPP` / `promoteUPP` / `restoreUPP`；
  - `internal/cli/admin_upp.go` 的 `service.ImportUPPTemplates`（CLI 导入是当前唯一绕过 API 的入口）。
  - `admin.Handler` 增 `AllowedSAIP` 字段，在 `internal/cli/smdpp.go` 构造处注入。
- **契约**：`POST /upp` 超限 → `409 {"code":"saip_version_not_supported", …, "details":{"templateVersion","maxSupported"}}`（`admin.go` 新增 `writeCodeDetails`）；`POST /upp/validate` **保持 `valid:true`** 并返回 `warnings[]`。
- **验收**：上传 `(3,2)`/`(2,4)` → 409；`(2,3)` → 通过；validate 对 `(3,2)` 返回 warning 且仍 `valid:true`；CLI import 同样被拦。

#### 步骤 1.2 — N11：解析 `additionalEuiccProfilePackageVersions` + 版本集合（接口预留）

- **解析**：`internal/rsp/types.go` 的 `EUICCInfo2` 增 `AdditionalEuiccProfilePackageVersions [][]byte`（parse `asn1.Ctx(15, true)`）与 `UICCCapability`；新增 `type Version struct{ Major, Minor int }`、`SupportedVersions()`（`{profileVersion} ∪ additional…`）、`IsV3Capable()`。
- **会话持久化（`00011`）**：`sessions` 增 `euicc_profile_version`、`euicc_supported_versions`（JSON），可选 `uicc_capability`；`store/session.go` 的 `Session`/`Put`/`Get`/`scanSession` 同步；`service/cmae.go` 的 `AuthenticateClient` 在 `Sessions.Put` 前写入，并对 V3-capable 记指标 `rsp42_euicc_v3_capable_total` 与审计。
- **`SelectBestFor` 改版本集合入参**：`internal/store/upp.go` 删除 `major<=0 → AnyForTenant()` 回退；`AnyForTenant`/`Any` 仅保留给管理/列表，下载路径不再使用。**只做接口预留**，不实现双 major 选择逻辑（§8.1 决策 9）。
- **验收**：声明 `(2,3)` + `additional=[{3,2}]` 的 eUICC 产生 `v3-capable-euicc` 标记，esim42 可从 timeline/session 读到版本集合；有单测断言 `major<=0` 回退不存在。

#### 步骤 1.3 — N12：版本不兼容时干净失败

- **逐级校验**：`internal/service/download.go` 的 `loadUPP` 对**四级回落**（订单 pin → 会话 → 租户默认 → 全局默认）**全部**做 `(major, minor)` 校验；全部不通过返回 `ErrProfileVersionNotSupported{euiccProfileVersion, supportedVersions, lowestTemplateVersion}`；会话无版本信息时按“未知版本”**拒绝**（不静默挑选）。
- **错误码**：`internal/rsp/errors.go` 新增具名 `CodeProfileVersionNotSupported = {"8.2.6","3.8"}`（**不复用** `8.8.5/4.10`）；错误在 `buildBPP` 之前返回，**不生成任何 BPP 段**（用测试固化顺序）。
- **可观测**：管理侧稳定码 `profile_version_not_supported` 写入 timeline 与审计；审计 `interface=es9p, function=authenticateClient, outcome=Failed, detail={euiccProfileVersion, supportedVersions, lowestTemplateVersion}`。
- **验收**：注册表仅 `(2,3)` + `profileVersion=(2,1)` 的 eUICC → 可区分失败码、无 BPP、审计/指标可查。

### 10.3 批 2（P1，防数据丢失/误操作）—— **已落地**（N6/N10 除外，见步骤 2.4）

#### 步骤 2.1 — N2：回调队列管理 API

- **存储**：`internal/store/callback.go` 增 `CallbackFilter`、`ListFiltered`、`Requeue`、`RequeueDead`（仅 `dead`/`failed` 可重投；重置 `attempts=0` 并立即入队）。
- **【已定】tenant/iccid 过滤**：先用 SQLite `json_extract(payload_json,'$.tenantId'/'$.iccid')`（modernc.org/sqlite v1.60.1 支持 JSON1，零迁移）；spike 不通过再加列迁移 `00013`。
- **接口**：新增 `internal/api/admin/callbacks.go` 并在 `admin.go` 的 `Mount` 注册：`GET /callbacks`（`payload` 返回**已解析对象**）、`POST /callbacks/{id}/retry`（非 dead/failed → `409 conflict`）、`POST /callbacks/retry-dead`；审计 `retryCallback`。
- **验收**：死信可查、可补投；补投不产生重复的状态推进。

#### 步骤 2.2 — N3：租户删除引用保护

- **存储**：`internal/store/tenant.go` 增 `TenantUsage`、`Usage(id)`、`DeleteWithReassign(id, reassignTo)`（单事务改属后删）。
- **接口**：`internal/api/admin/tenants.go` 的 `getTenant` 增 `usage`；`deleteTenant` 无 `force` 且存在引用 → `409 {"code":"tenant_in_use", "usage":{…}}`；`?force=true&reassignTo=<tenant|"">`，未注册目标 → `400 unknown_tenant`。
- **验收**：误删被拦；force 路径可审计地迁移。

#### 步骤 2.3 — N1：审计单调增量游标

- **存储**：`internal/store/audit.go` 的 `AuditEntry` 增 `ID`，所有 SELECT/scan 补 `id`；新增 `ListAfterID(f, afterID, limit)`（`id > ? ORDER BY id ASC`，排他下界）。
- **接口**：`internal/api/admin/audit.go` 支持 `afterId` + `limit`（默认 500），与 `page`/`size` **互斥**；响应 `{items[].id, nextAfterId, hasMore}`，空批时 `nextAfterId` 原样返回入参。
- **【已定】单调性**：用迁移 `00012` 把 `audit_log` 改为 `AUTOINCREMENT`（普通 rowid 在删除最大行后可能复用，不满足“单调且不回收”）。
- **验收**：增量同步“至少一次 + 无重复”。

#### 步骤 2.4 — N6 / N10：管理 API 监听面收敛与密钥导出护栏 —— **【不做】**

- **决策（§8.4 决策 11）**：本项**明确范围外**，本轮不实施：
  - admin `bind` 默认值**保持现状**（`config/config.example.yaml:19,73` = `0.0.0.0`，`internal/config/config.go` 的默认值不动）；不新增“非 loopback + audit disabled”启动 WARN；
  - 不引入 `X-RSP42-Reveal-Secrets: yes` 护栏；`GET /personalization/export`、`GET /personalization/{iccid}?reveal=1`、`GET /personalization?reveal=1` 维持现状；
  - 不加 `Cache-Control: no-store`，`docs/interfaces.md` 不新增 secret-bearing 标注。
- **理由**：管理 API 无鉴权已是既定部署前提（§0.1-4、§8.1 决策 5），安全边界完全由 esim42 承担；esim42 必须保证该 API 不被反向代理、网关或前端暴露。
- **遗留提示（不构成待办）**：若将来重启该项，护栏应覆盖 `GET /personalization?reveal=1`（`internal/api/admin/personalization.go` 的 `reveal=1` 分支同样能回明文 K/OPc），而不只是 `/export`。

### 10.4 批 3（P1，SAIP 能力）

#### 步骤 3.1 — N15：`ServicesList` 补到 V2.3.1 的 24 项 + TUAK256 修复

- `internal/saip/header.go`：补 `dfLink`(19)/`cat-tp`(20)/`get-identity`(21)/`profile-a-x25519`(22)/`profile-b-p256`(23)（拼写以 `refs/pysim/pySim/esim/asn1/saip/PE_Definitions-3.3.1.asn` 为准）；引入 `svcMax` 作为 `Services()` 的上界；`serviceNames` 同步；**`bertlv` → 规范拼写 `ber-tlv`**（`/upp/{name}/decoded` 的对外契约变更，需同步 esim42 的静态映射与契约快照）。**不为** V3.2 才引入的 5 项预留常量。
- 修 `SvcTUAK256` 只声明、从未置位：按 `PE-AKAParameter` 中 K 的长度（16→TUAK128、32→TUAK256）置位，对齐 pySim。
- 文档：写明 `RebuildMandatoryServices`（服务位）与 `RebuildMandatoryGFSTEList`（GFSTE）的职责边界（C11）。
- **验收**：含 `get-identity` 的模板在 `/upp/{name}/decoded` 的 `services[]` 中可见；24 项表驱动单测通过。

#### 步骤 3.2 — N13：Annex A/B 模板表 + 约束校验 + 测试向量

- 新增 `internal/saip/templates.go`：V2.3.1 的 **13 个模板 OID** + spec-version OID `2.23.143.1.1.2`（V2.3.1 无版本化子弧）；FID/文件名/大小/AID/ARR/UST 默认值。
- 新增 `internal/saip/validate.go`（对齐 pysim `validation.py`）：首个 PE `header`、第二个 `mf`、末位 `end`；单例 PE；可选 PE 顺序；mandatory-services ↔ PE 存在性一致；AKA 算法 ↔ 服务位一致（含 TUAK-128/256）；`identification` 唯一；`File` 的 `doNotCreate` 互斥与 `fileDescriptor` 优先；**`gfste[]` 必须全部落在 13 个模板 OID 内且拒绝带版本子弧**（如 `2.23.143.1.2.13.2`）；非 V2.3.1 PE（`BE`/`BF20`/`BF21`/`BF1F`/`BF22`）带 `mandated` → warning；值域约束（`SIZE(...)`/`INTEGER(0..n)`）。
- **接线**：`service.UPPInspection` 增 `Errors []string`（硬失败）；`/upp/validate` 硬失败 → `valid:false` + `errors[]`；`/upp` 对硬失败拒绝入库。
- **顺带修**：`internal/saip/files.go` 的 `Body()` 忽略 `fillFileOffset`（`SetBody` 保持线性化），补 offset 分片回归测试。
- **向量**：`testdata/upp/` 增 V2.3.1 专用向量（含 DF 5GS、DF SAIP、`get-identity` 服务位）。
- **验收**：缺 `end`/PE 顺序错/带版本子弧 → `/upp/validate` 给出明确错误；现有 TS.48 向量仍全部通过（回归门禁）。

#### 步骤 3.3 — N17：`SdKey*` 与 `MncLen` 个性化

- `internal/saip/personalization`：`Data` 增 `SdKeys`（SD/MNO-SD 密钥集、KVN、key usage qualifier → `PE-SecurityDomain`）与 `MncLen`（`EF.AD` bit 4，FID `6F3A`）；`Engine.Apply` 接线；`csv.go` 补列。K/OPc 仍由 esim42 生成（§8.1 决策 4，rsp42 不提供密钥生成/派生）。
- `internal/api/admin/upp_tools.go` 的 `personalizationSchema` 增字段（与 N4 合并解决“目录 ≠ 模板可绑定字段”）；`docs/coverage.md` 同步。
- **验收**：含 `PE-SecurityDomain` 的模板可注入 SD 密钥集；`EF.AD` 的 MNC 长度可个性化。

### 10.5 批 4（P2）

- **步骤 4.1 — N4**：`/upp/{name}/schema` 的 `fields[]` 增 `applicable`/`targets[]`/`requiredIn[]`/`note`，由 `inspection.files[]/elements[]` 推导；保留 `required`（= `requiredIn` 含 `"render"`）以兼容；解开 `iccid.required=true` 与凭据池流程的冲突。
- **步骤 4.2 — N5**：`/upp/render` 接受 `{name,…}` 或 `{data:"<base64 DER>",…}` 二选一；同给 → `400 invalid_request`；`data` 路径不落库，审计 `function=renderUPP, subject="<ad-hoc>"`。
- **步骤 4.3 — N7**：`openapi.json` 的 `profiles/stats` `groupBy` 补 `profile_type`（`store/stats.go` 已支持，仅补文档）；`sort` enum 补 `tenant`/`-tenant` 并同步 `internal/store/profile.go` 的白名单；删除 `admin.go` 的 catch-all `"error"` 码。`/iccid-pool/stats` 的 `tenant` **已列，无需改**。
- **步骤 4.4 — N8**：`internal/api/admin/ds.go` 增 `POST /events`（省略时生成 `EVT-<…>`；重名 → `409 event_id_in_use`）与 `DELETE /events/{id}`；审计 `function=registerEvent`。
- **步骤 4.5 — N9**：`internal/metrics` 增 `Histogram` 类型 + `Observe` + 桶渲染；middleware 以 chi `RoutePattern()` 作 `route` 标签（防高基数）：`rsp42_admin_http_request_duration_seconds{route,method,status}` 与 `rsp42_es2p_http_request_duration_seconds{function}`。
- **N10【不做】**：见步骤 2.4（随 N6 一并范围外）。

### 10.6 并行：C 清单（代码级一致性）

- **C1【已定】**：**删除** ES2+ `downloadOrder` 的私有 body 成员 `pprIds`（`internal/api/es2plus/handlers.go` 的请求结构与 PPR 覆盖分支）；PPR **只走管理 API / `profiles.ppr_ids`**；`config/config.example.yaml` 中“订单可覆盖 pprIds”的注释一并删除；`docs/interfaces.md` 与 openapi 不再声明该私有扩展。
- **C2**：`resolveProfileType` 对不含 `/` 的值不再静默，记审计/指标 `profileType-unparsed`。
- **C3 / C4**：拆分 `internal/rsp/errors.go` 中 `8.2.1/3.8`（池耗尽 vs 租户 `profile_quota` 用尽）与 `8.2.6/3.7` 的语义错位。
- **C5**：修正 `internal/asn1/doc.go` 的过期陈述，与 N11/N12 同批；与 `TODO.md` §3.1 合并。
- **C6 / C7 / C10 / C11**：分别并入 N13 / N15。
- **C8**：`internal/asn1/tlv.go` 对 BER 不定长与长度字段 >4 字节的拒绝 —— **先核查真实样本**是否出现不定长编码，再决定“实现支持”或“登记为已知边界 + 影响面”（本轮不预设结论）。
- **C9**：`bf1f`(df-5gprose)/`bf22`(ssim) 在 `TODO.md` 登记为**明确范围外**（对应 §0.4）。

### 10.7 迁移文件

| 迁移 | 内容 | 来源 |
|---|---|---|
| `00011_session_euicc_versions.sql` | `sessions` 增 `euicc_profile_version`、`euicc_supported_versions`（JSON），可选 `uicc_capability` | N11 / N12 —— **已落地** |
| `00012_audit_autoincrement.sql` | ~~`audit_log` 重建为 `AUTOINCREMENT`~~ | **不需要**：`audit_log.id` 本就是 `INTEGER PRIMARY KEY AUTOINCREMENT`（`00001_init.sql:109`），N1 只暴露既有 id |
| `00013_callback_columns.sql`（**仅当** `json_extract` spike 不通过） | ~~`es2p_callbacks` 增 `tenant_id`/`iccid` + 索引~~ | **不需要**：`json_extract` 在 modernc.org/sqlite v1.60.1 上实测可用（`internal/store/callback_test.go`），零迁移 |

> 保持追加式：不合并进 `00001_init.sql`（理由同 §9.1）。每条迁移需做“老库升级 + 新库全量”双向验证。

### 10.8 已收敛决策（本轮）

| # | 决策 | 结论 |
|---|---|---|
| 1 | N11/N12 是否新增会话版本列 | **是**，迁移 `00011`（否则 `loadUPP` 阶段无法校验版本） |
| 2 | N2 的 tenant/iccid 过滤实现 | **已定并验证**：`json_extract(payload_json,'$.tenantId'/'$.iccid')`（modernc.org/sqlite v1.60.1 支持 JSON1），零迁移 |
| 3 | N1 的严格单调 | **无需迁移**：`audit_log.id` 已是 `AUTOINCREMENT`；N1 只把既有 id 暴露到接口 |
| 4 | C1 的 `pprIds` | **删除该成员**；PPR 只走管理 API / `profiles.ppr_ids` |
| 5 | C8 的 BER 不定长 | 先核查真实样本，再定“支持”或“登记为已知边界” |
| 6 | N16 的校验覆盖面 | 统一 choke point，覆盖 `clone`/`promote`/`restore` + CLI `upp import` |
| 7 | 密钥端点 reveal 护栏是否覆盖 `GET /personalization?reveal=1` | 若实施则**是**；但 N6/N10 整体**不做**（步骤 2.4），本条随之暂缓 |
| 8 | N6/N10（监听面收敛 + 密钥导出护栏） | **明确不做**（§8.4 决策 11、步骤 2.4） |

### 10.9 建议顺序与验收基线

```
批 0 决策 → ┬─ 批 1（N16 → N11 → N12）      ← esim42 M2 的硬性退出条件
            ├─ 批 2（N2 → N3 → N1）          ← N6 已范围外
            ├─ 批 3（N15 → N13 → N17）
            └─ 批 4（N4 → N5 → N7 → N8 → N9）← N10 已范围外
并行：C1–C11 与文档同步；每批结束跑 make ci
```

- **验收基线**：esim42 侧完成一次端到端（匿名领取 → LPA 下载 → 安装 → 看板可见 → 审计可查 → 取消/回池）的联调，全链路租户归属正确、幂等重放安全；外加 esim42 `02` §9 的 A1–A25（其中 A13–A17 依赖批 3 的 N13/N15/N17）。
- **对外回执**：要求 esim42 修正 `01` §6.5 D2 的标量 `max_saip_version` 表述为列表 `allowed_saip_versions`，否则升级时会引入一次配置迁移。
