# rsp42 ← esim42 对接改造清单（反向差距分析）

> **输入（第三轮复核，2026-10-15）**
> - `../esim42/todo/01`–`06`（2026-10-15 定稿；**不含 `todo/research/`**）。
> - rsp42 基线：`89308b2`（2026-10-15）。上一版本文档基于 `f3232da`；区间内 rsp42 有 73 commits / 234 files，第二轮 N 清单与 C 清单主体落地。
> - 本轮 esim42 已把 rsp42 的接口固化为**可消费的契约矩阵**（`02` §2 与 §3），上一版本文档中的“缺口提案”全部被实现取代；esim42 **不再为 G/N 设计降级路径**。
>
> **本文只回答一件事**：站在 rsp42 的角度，为支撑 esim42 需要改什么、不需要改什么、接口契约长什么样。
> 图例：`[P0]` 阻塞（不改则 esim42 无法安全/正确上线）；`[P1]` 重要；`[P2]` 可选/后续。状态均以本仓库**当前代码**（`89308b2`）为准。
> **历史**：第一轮 G 清单（G2–G20）与第二轮 N 清单（N1–N17）均已在 rsp42 侧落地/收敛（§9、§9.4）。本轮重点转为**剩余缺口 R1–R9（§0.5）**、**对外文档修正请求（§0.6）** 与 **待确认项（§11）**；其中 **R1 与 §0.6 的文档修正、§11 的四项均已闭合**。

---

## 0. 结论摘要

### 0.1 边界原则与部署前提（先划边界，再列改动）

1. **rsp42 是 RSP 层（SM-DP+/SM-DS），不是 BSS 层。** 用户、账号、OAuth、运营商业务、商城、可见性、审批流、前端一律属于 esim42；rsp42 只多认一样东西：**租户（tenant/carrier）归属**，因为资源隔离、审计归属与配额必须落在持有资源的进程里。
2. **esim42 不需要新引入 SAIP 编解码栈。** rsp42 已有 Go 版 SAIP 解析/编码与个性化引擎（`internal/saip`、`internal/saip/personalization`），并已把模板能力（`validate` / `decoded` / `schema` / `render` / `clone` / `promote` / `versions`）以管理 API 外露 —— 这直接消解 `PLAN.md` §4.1 的“Go 主干 + Python 编解码微服务”选型风险，并满足“严禁造轮子”。
3. **订单生命周期走标准 ES2+，非标准的管理动作走 Admin API。** esim42 用 ES2+（mTLS）做 `downloadOrder`/`confirmOrder`/`releaseProfile`/`cancelOrder`，用 `/admin/api/v1` 做库存、模板、池、审计、看板。因此 **ES2+ 也必须具备租户归属、模板绑定、幂等与业务关联能力**，否则 esim42 只能退回“全部走 Admin API”或“一个运营商一套 rsp42 实例”。
4. **部署前提（已与 esim42 确认）：管理 API 保持无鉴权。** esim42 后端与 rsp42 管理 API **同机同网、内网直连**；esim42 前端只经 esim42 后端访问，绝不直连 rsp42。因此管理 API 不引入 Bearer/mTLS/scope，**安全边界由 esim42 承担**（esim42 必须保证该 API 不被反向代理、网关或前端暴露）。原初稿的 G1“管理 API 鉴权”据此**排除**，正式改动清单从 G2 起。
5. **SM-DS 启用（决策 6）**：esim42 走 ES12 事件注册/删除并以 `/events` 做透视，支撑模块 B 的“无激活码推送”。rsp42 需同时部署 `smds` 角色（`RSP42_ROLE=smds`），并补齐事件的时间/租户过滤与注册失败可观测（G20）。
6. **明确不做（决策 7–11，见 §8.4）**：**PostgreSQL/其他数据库后端**、**多副本部署**、**每运营商客户端证书**、**rsp42 侧限流/429**、**管理 API 监听面收敛与密钥导出护栏（N6/N10）**。这些不是“以后再说”的备选项——相关配置与文档已按“仅支持当前形态”收敛。
7. **第三轮口径 + 第四轮标准修订**：SAIP 基线仍为 **V2.3.1（包内编码 `(2,3)`）**；版本上限（N16）与运行期干净失败（N12）已落地（§1bis）。第三轮复核的剩余缺口 **R1–R9（§0.5）** 中，**R1（逐文件默认表 + 值域校验）已落地**，**R2 待真机/一致性工具裁决**，**R9 暂不做**（用户决定），**R8 为部署约束**，R3–R5 非阻塞。第四轮（§12）按 SGP.22 标准修订了 ES2+ 订单函数的行为（F1–F7），**esim42 契约与标准冲突处一律以标准为准**，需要 esim42 同步修正的 4 处见 §12.2。SAIP V3.x 的 PE/模板/feature 覆盖与 SGP.22 Annex F 降级构造（N14）仍在范围外，rsp42 不为其预留代码位或配置开关（见 §0.4）。

### 0.2 本轮结论（第三轮复核 + 标准一致性修订）

| 侧 | 结论 |
|---|---|
| rsp42 | 两轮改造**全部落地或已收敛**。第三轮复核后**遗漏的 R1（值域校验）已落地**，§0.6 的文档修正**已全部完成**；本轮进一步按 **SGP.22 标准**修订了 ES2+ 订单函数（§12），并与 esim42 契约发生冲突时一律以标准为准。仍需 rsp42 动作的只剩 **R2**（待真机/一致性工具裁决）与 **R9**（暂不做，属用户决定）。 |
| esim42 | 转为**契约消费**：以 `internal/api/openapi/openapi.json`（`info.version 0.2.0`）快照 + `openapi-typescript` 生成类型；ES2+ 类型手写并冻结在其 `02` §2.1。esim42 侧的实施不变量与对账任务见其 `02` §7.4/§8。**本轮 rsp42 侧的标准修订要求 esim42 同步修正 4 处契约**，见 **§12.2**（cancelOrder 必填字段、matchingId 字符集、downloadOrder 响应字段、指标名）。 |
| 共同 | 本轮新增的**最强第三方证据**：`refs/simulator-testing/INTEROP-TEST-REPORT.md`（lpac × YggdraSIM）跑通 ES2+ 下单 → SM-DS 发现 → ES9+ → eUICC 安装 → 通知 → `Installed`；BPP 由 pySim 独立解码 + BSP 验签解密通过，个性化值逐项命中。它不替代 esim42 自己的联调，但显著降低 rsp42 侧未知风险。 |

### 0.3 第二轮必改项（N 清单：除 N6/N10/N9/N14 外全部落地）

> 来源：`../esim42/todo/02` §7.2、`01` §8、`03` §3.3/§7、`06` §13.1。第一轮 G2–G20 同样已全部落地（见 §9）。
> **这些不再是“提案”，而是 esim42 必须直接消费的契约。** 逐条实测结论见 §9.4 与 §1bis / §2 对应的 N 小节。

| # | 改动 | 对应 esim42 需求 | 优先级 | 状态 |
|---|---|---|---|---|
| N16 | `/upp`、`/upp/validate` 加 SAIP 版本上限 `≤(2,3)`；新增 `profiles.allowed_saip_versions: ["2.3"]`（**列表形态**）；超限 `409 saip_version_not_supported` | `01` §6.5 D2；`06` D2.11 | **P0** | 已落地 |
| N12 | `loadUPP` 每一级回落都校验版本；无兼容模板时返回明确码且不生成 BPP；审计 `euiccProfileVersion` | `01` §6.5 D3/D5；`06` D2.12 | **P0** | 已落地 |
| N1 | 审计单调游标：`AuditEntry.id` + `GET /audit?afterId=&limit=` | 模块 E 增量审计同步 | P1 | 已落地 |
| N2 | 回调队列管理 API：`GET /callbacks`、`POST /callbacks/{id}/retry`、`POST /callbacks/retry-dead` | 模块 C/E 回调可靠性 | P1 | 已落地 |
| N3 | 租户删除引用保护：`409 tenant_in_use` + `usage`；`?force=true&reassignTo=` | 模块 D 防误删 | P1 | 已落地 |
| N6 | admin `bind` 默认 `127.0.0.1`；`X-RSP42-Reveal-Secrets` 护栏 | 部署约束 | **范围外** | **不做**（§8.4 决策 11） |
| N11 | 解析 `additionalEuiccProfilePackageVersions`；`Version`/`SupportedVersions()`/`IsV3Capable()`；移除 `SelectBestFor` 的 `major<=0` 回退 | SEC；`01` §8.4.1 | P1 | 已落地 |
| N15 | `ServicesList` 补到 V2.3.1 的 24 项（`dfLink`/`cat-tp`/`get-identity`/`profile-a-x25519`/`profile-b-p256`）+ TUAK-256 修复 | `03` §3.1 能力位 | P1 | 已落地 |
| N13 | Annex B 模板表（V2.3.1 的 **14** 个模板 OID，非 13）+ 约束校验 + V2.3.1 测试向量 | 模块 C 模板上架校验 | P1 | 已落地（值域校验已由 R1 补齐） |
| N17 | `SdKey*` 与 `MncLen` 个性化 | MNO-SD 密钥集 / `EF.AD` | P1 | 已落地 |
| N4 | `/upp/{name}/schema` 的 `fields[]` 增 `applicable`/`targets[]`/`requiredIn[]`/`note` | 模块 C 动态表单 | P2 | 已落地 |
| N5 | `/upp/render` 接受未入库模板（`data` base64 DER） | 模块 C 上传向导 | P2 | 已落地 |
| N7 | 契约补全：`profiles/stats` 的 `groupBy` 补 `profile_type`；`sort` 白名单补 `tenant`；删除 catch-all `error` | 模块 C/D 筛选器与 SDK | P2 | 已落地 |
| N8 | SM-DS 事件管理写接口 `POST/DELETE /admin/api/v1/events` | 模块 B 边缘场景 | P2 | 已落地 |
| N9 | HTTP 延迟直方图 `rsp42_*_http_request_duration_seconds` | SLO 看板 | **暂不做** | 见 §0.5-R9 |
| N10 | 密钥端点显式契约（reveal 护栏、`Cache-Control: no-store`、secret-bearing 标注） | 防密钥管道滥用 | **范围外** | **不做**（随 N6） |
| N14 | SGP.22 Annex F 的 `PE-GenericFileManagement` 降级构造 | **esim42 明确范围外**，不预留代码位/开关 | — | 范围外 |

> **优先级口径已统一**：上一版登记的“`TODO.md` 把 SAIP 完整模板表 / `SdKey*`·`MncLen` 记为 P2，而 esim42 定为 N13/N17 = P1”已解决——N13/N17 均已落地；`TODO.md` §2-2 的 R1（值域校验）已由本轮落地并从“未内置”改为“已实现”。`TODO.md` §2 的 `CancelSession` 显式验签 / `smdpOid` 与 Brainpool 两项 esim42 未提出要求（见 §0.5-R4/R5）。

### 0.4 明确“不需要做”的部分（避免把 BSS 逻辑渗进 RSP 层）

| esim42 侧需求 | 归属 | 说明 |
|---|---|---|
| 用户/角色/配额 M（用户可激活上限） | esim42 | SGP.22 无“用户”概念（rsp42 只维护 Profile 库存/订单/安装状态） |
| OAuth 适配器、`dn42.active_mnt` 映射 | esim42 | rsp42 不引入身份体系 |
| Profile 市场可见性、匿名开关、Brand/Logo/APN 指引 | esim42 | 业务属性；rsp42 只提供 `tenant_id` 与稳定模板标识 |
| 运营商提交审批流（下发前人工审批） | esim42 | rsp42 现有语义已够：`Confirmed` 不参与下载，必须显式 `ReleaseProfile`（`internal/service/order.go` 的状态迁移表与 `Confirm`，以及 `internal/service/cmae.go` 的下载资格检查）；ACR 的 `acr_url` 确认是第二个钩子 |
| 用户名额扣减/回滚 | esim42 | 由 esim42 编排 `downloadOrder`/`cancelOrder`；rsp42 只保证幂等与状态机 |
| 二维码渲染/发送（短信、邮件） | esim42 | rsp42 返回 `activationCode`/`qrContent` 字符串即可（`api/admin/profiles.go`） |
| ICCID/IMSI/K/OPc 的**权威**数据管理与订户绑定 | esim42 | rsp42 只做**存储 + 校验 + 分配**；K/OPc 由 esim42 生成、rsp42 只注入（§8.1 决策 4） |
| SAIP V3.x（V3.0–V3.4.1）的 PE、模板与 feature 覆盖（`df-snpn`、`iot`/`opt-iot` 的 IoT Minimal 语义、`df-5gprose`、`ssim`、`usatAppPairing`、5G ProSe 上报 Bit 8、带版本的模板 OID） | esim42 `01` §6.5 D1 + N16 | 基线 V2.3.1；超版本模板在 `/upp` 被拒（N16）。其中 `df-snpn`(be)、`iot`(bf20)、`opt-iot`(bf21) 三个 V3.x 模板 PE **已命名**并标记 `fileBearing`+`templatePE`（仅用于解析/识别，无 V2.3.1 模板 OID）；`df-5gprose`(bf1f)、`ssim`(bf22) **未命名**。抬升上限需重新立项并恢复 `01` §8.4 的四项内容 |
| SGP.22 Annex F 的 `PE-GenericFileManagement` 降级构造（N14） | esim42 `01` §6.5 D4 | 不服务不适配机群，在资格检查阶段干净拒绝；**不预留代码位或配置开关** |
| 双 major 选择逻辑 | esim42 `06` §13.1 | 已改为**未来规划**（不是永久排除）；现阶段只做**零成本接口预留**（`allowed_saip_versions` 列表、`SelectBestFor` 收版本集合、`major<=0` 回退已删），不实现双 major 选择 |
| 管理 API 监听面收敛与密钥导出护栏（N6/N10） | 决策 11（§8.4） | **明确不做**：admin `bind` 保持现状，不引入 `X-RSP42-Reveal-Secrets` 与 `Cache-Control: no-store`；安全边界完全由 esim42 承担 |
| HTTP 延迟直方图（N9） | 用户决定 | **暂不做**（§0.5-R9）；SLO 由 esim42 自己给 rsp42 调用计时承担 |

### 0.5 本轮复核后仍然存在的缺口（R1–R9）

> 编号沿用 esim42 `01` §9 与 `02` §0.4/§7.4。其中 R6/R7 仅在 esim42 的 `todo/research/` 内定义（按约定本项目不引用），不在下表。
> **R1 已于本轮（第三轮之后）落地**：`internal/saip/filetable.txt`（内嵌的 Annex A 逐文件默认表，解析器 `filetable.go`）、`filevalidate.go`（§8.3.3 模板修改规则）、`constraints.go`（ASN.1 `SIZE`/整数域）。R2–R9 的状态仍以本仓库当前代码为准。

| # | 缺口 | 优先级 | 现状证据（rsp42） | 对 esim42 的影响 / 处置 |
|---|---|---|---|---|
| **R1** | SAIP V2.3.1 §9 的**逐文件默认表**与值域校验（`SIZE(...)`/`INTEGER(0..n)`，C10） | **已落地** | `internal/saip/filetable.txt`（内嵌 Annex A 逐文件默认表：14 个模板、307 个数据行，FID/名称/类型/NB Rec/大小/ARR/SFI/Content-Required/参数/服务关联；解析器 `filetable.go`）；`filevalidate.go`（无默认值必须提供、DF/EF 专属参数、文件类型不可改、`fileID`/`shortEFID` 作用域内唯一、`efFileSize` 值域）；`constraints.go`（ProfileHeader/Fcp/ProprietaryInfo/PIN/PUK/AKA/CDMA 的 `SIZE` 域）；`validate_test.go` 的 `TestValidateTS48Vectors` 为 TS.48 回归门禁 | 上传向导可以承诺“结构 + 约束 + 值域”校验，**不再**限制文案；`GET /upp/{name}/decoded` 的 `files[]` 已可按模板判定。**边界**（仍不校验）：Annex A 默认内容模式本身、§9.9 访问规则表内容、TS 102 221 逐 EF 内容语义 —— 见 `docs/interfaces.md`「UPP validation scope」 |
| **R2** | 互操作观察①：`ReplaceSessionKeysRequest`（BF26）用通用 tag `04` 而非 AUTOMATIC TAGS 的 `80/81/82` | **待裁决** | 严格 ASN.1 解码器可能判 `scp03tStructureError(7)`；模拟器（lpac × YggdraSIM）互相适配、E2E 通过（`INTEROP-TEST-REPORT.md`）；已登记进 `docs/coverage.md`「Open interoperability observations」 | 需**真实 eUICC 或 GSMA 一致性工具**裁决；真机联调时重点观察 `StoreMetadata`/`ReplaceSessionKeys` 阶段是否失败；esim42 只需把该失败码落审计并按“下载失败”分支处理 |
| **R3** | 互操作观察②：ASN.1 binding（§6.6）**响应**只发一层 `BF39` | 低 | 与 `asn1tools` 的严格 EXPLICIT tagging 解读不一致；已登记进 `docs/coverage.md` | **仅影响 ASN.1 binding**；esim42 走 JSON binding，不受影响。仅当未来改用 `application/x-gsma-rsp-asn1` 时需先裁决 |
| **R4** | ES9+ `CancelSession` 的 `euiccCancelSessionSignature` 显式验签 / `smdpOid` 校验未做 | 非阻塞 | 目前只校验 `transactionId`；`reason` 仅驱动状态迁移，签名与 `smdpOid` 未校验（`internal/service/cancel.go`） | esim42 未提出要求（`TODO.md` §2-4） |
| **R5** | Brainpool P256r1、BER 不定长（C8）、SAIP V3.x 的 PE tag（C9） | 非阻塞 / 范围外 | `docs/coverage.md` 已登记 Brainpool；C8 为已知边界；V3.x 见 §0.4 | 测试卡默认 NIST；无真实样本触发；V3.x 明确范围外 |
| **R8** | **N6/N10 明确不做**：admin 监听 `bind` 仍 `0.0.0.0`、无 reveal 护栏、无 `Cache-Control: no-store` | **部署约束** | `config/config.example.yaml:19,77` = `0.0.0.0`；无 reveal 头校验 | esim42 的部署 checklist 必须自己兜底：admin 端口只绑 `127.0.0.1` 或仅容器内网；esim42 **不提供** `/personalization/export` 的任何转发路由；K/OPc 只在“凭据录入”时**单向写入**、之后不回读；esim42 侧统一封装 `revealSecrets()`（显式 `reason` + 审计） |
| **R9** | **N9 暂不做**：`/metrics` 无 HTTP 延迟直方图 | P2 | `internal/metrics` 无 Histogram 类型；`/metrics` 只有计数器/仪表 | esim42 自己对每个 rsp42 调用计时（`esim42_rsp_call_duration_seconds{endpoint}`），足以覆盖其 SLO |

### 0.6 向 rsp42 提出的文档/契约修正请求（来自 esim42 `02` §10、`01` §10 问题 13）

> 以下均为**文档层**动作；**本轮已全部完成**（第 1 项是当时唯一的文档-代码漂移）。
> 另有 4 项需与 esim42 确认的语义问题，已写入 `docs/interfaces.md`（详见 §11）。

| # | 项 | 原状 | 处置 |
|---|---|---|---|
| 1 | `docs/interfaces.md` §Quotas 的配额状态码 | 该节写 “`tenants.profile_quota` … the ES2+ answer is `8.2.1/3.8`”，但代码是 **`8.2.5/3.7`**（`ErrQuotaExceeded → CodeNoMoreProfileAvailable`，`TestES2PlusAllocationErrorCodes` 固化），与同文件错误码表自相矛盾 | **已修正**为 `8.2.5/3.7`，并写明“配额耗尽与号池耗尽在 ES2+ 上不可区分，用 `usage` / `/iccid-pool/stats` 区分” |
| 2 | `8.2.6/3.8` 语义过载 | `CodeProfileNotEligible`（EID 不适配 / 订单过期 / 尝试超限）与 N12 的 `CodeProfileVersionNotSupported` 是**同一** subject/reason 对 | **已写明**两种稳定的 `message` 前缀，并由 `TestResolveUPPTemplateVersionSet` 固化 |
| 3 | R2 / R3 的登记 | `docs/coverage.md` 的 “Notable spec deviations” 未覆盖 BF26 tag 与 ASN.1 binding 响应层级 | **已登记**为 `docs/coverage.md`「Open interoperability observations（not yet closed）」 |
| 4 | `/upp/validate` 的能力边界 | 原先只做结构 + 约束；R1 落地后能力已扩展 | **已写明** `docs/interfaces.md`「UPP validation scope」：结构 + 约束 + Annex A 逐文件默认值 + ASN.1 值域，并显式列出**仍不校验**的部分 |

---

## 1. 阻塞级缺口 [P0]（第一轮 G：已全部落地）

> 编号沿用初稿：**G1（管理 API 鉴权）已按部署前提排除**，见 §0.1-4。以下仅保留结论；落地位置见 §9。

| # | 改动 | 状态 |
|---|---|---|
| G2 | 租户（carrier）维度贯穿 `upp_templates / profiles / iccid_pool / iccid_ranges / batches / personalization / audit_log`；ES2+ 租户取自 `header.functionRequesterIdentifier` 映射 | 已落地 |
| G3 | 模板/产品选择走标准 `profileType`（`"<tenant>/<template>"`）；`loadUPP` 按多级候选回落并移除 `Any()` 兜底 | 已落地 |
| G4 | 下载时把实际 EID 回写 `profile.eid`（匿名领取的设备归属；异 EID 复用被拒） | 已落地 |
| G5 | 幂等：Table 24 NOTE 优雅重发 + `Idempotency-Key` HTTP 头；`profiles.external_ref`（仅 Admin 便利字段） | 已落地 |
| G6 | ICCID/IMSI 池：租户隔离、预留 TTL、失败回滚、与个性化解耦（凭据池 `ReservePair`） | 已落地 |
| G19 | ES2+ 标准一致性修正：重发 / `confirmOrder` EID 不一致 `8.1.1/3.10` / 状态码拆分 | 已落地 |
| G20 | SM-DS 事件透视（`tenant`/`iccid`/`matchingId`/`status`/时间范围/排序）+ 注册失败审计与计数 | 已落地 |

---

## 1bis. 第二轮阻塞级缺口 [P0]（N16 / N12：已全部落地）

> 编号来自 esim42 的实际产出（`02` §7.2 与 `01` §8），与第一轮的 G 编号并行、不重号。
> 本节刻意**不重排后续章节编号**：`§4`、`§8.1`、`§8.2`、`§8.4`、`§0.1-4` 被迁移文件、`openapi.json` 描述、`TODO.md` 与源码注释外部引用，重排会使其失效。

### N16. SAIP 版本上限（`/upp`、`/upp/validate`）—— **已落地**

**需求**：esim42 `01` §6.5 D1/D2 把 SAIP 基线定为 **V2.3.1（包内 `(2,3)`）**，并要求 rsp42 拒绝超基线模板。理由：在 V2.3.1 基线下 rsp42 **无法校验 V3.x 模板的 PE/服务语义**（`iotOptions` 必填、PE-IoT 必须紧跟 header、`df-5gprose`/`ssim` 的模板 OID 不在 V2.3.1 name 表语义里），而模板一旦被选中就会被下发。

**落地形态**：配置 `profiles.allowed_saip_versions: ["2.3"]`（**列表而非标量**，为将来加 `"3.2"` 预留，零迁移）；唯一 choke point 在 `internal/service/saip_version.go`（纯比较逻辑已抽到 `internal/saipver`）；`POST /upp` 超限 → `409 saip_version_not_supported` + `details{templateVersion,maxSupported}`；`/upp/validate` 保持 `valid:true` 并写 `warnings[]`；`clone`/`promote`/`restore` 与 CLI `upp import` 同校验。比较**只按 `(major, minor)`**（“V2.3.1 是文档修订号、与 V2.3 同包内同形”）。

**验收**：上传 `(3,2)`/`(2,4)` → 409；`(2,3)` → 通过；`/upp/validate` 对 `(3,2)` 返回 warning 且仍 `valid:true`；CLI import 同样被拦。

### N12. 版本不匹配时必须干净失败—— **已落地**

**需求**：esim42 `01` §6.5 D3/D5：不服务不适配机群，且必须**在下载末期之前**干净失败，而不是让 eUICC 以 `unsupported-profile-version(31)` / `template-not-supported(9)` 拒绝。

**落地形态**：`internal/service/download.go` 的 `loadUPP` 对五级候选（订单 pin → 会话 → 按 eUICC 版本集合选最佳模板 → 租户默认 → 全局默认）**全部**校验版本，显式 pin 不回落；无兼容模板 → `8.2.6/3.8`（`CodeProfileVersionNotSupported`，**不复用** `8.8.5/4.10`），**在生成任何 BPP 段之前**返回；失败写入 ES9+ 审计行（`interface=es9p, function=authenticateClient, outcome=Failed`，detail 含 `euiccProfileVersion/supportedVersions/lowestTemplateVersion`，见 `internal/service/cmae.go` 的 `noteVersionFailure`），该行也出现在 `GET /profiles/{iccid}/timeline`；指标 `rsp42_profile_version_not_supported_total`。迁移 `00011` 持久化会话版本。

**验收**：注册表仅 `(2,3)` + `profileVersion=(2,1)` 的 eUICC → 可区分失败码、无 BPP、审计/指标可查。

---

## 2. 重要缺口 [P1]（两轮均已落地）

> 详细提案与验收标准已被实现取代；下表只保留结论与落地位置（§9 与 §9.4）。状态图例：`[x]` 已落地。

| # | 改动 | 状态 |
|---|---|---|
| G7 | SAIP 模板能力外露（`/schema`、`/validate`、`/render`、`/clone`、`/promote`）+ PLMN/MSISDN/ACC/filePatches 个性化 | `[x]` |
| G8 | 审计 `actor` 语义修复 + 租户维度 + `/audit/stats` `/profiles/stats` `/notifications` + timeline 合并 session/审计 | `[x]` |
| G9 | 回调载荷增 `tenantId/externalRef/matchingId`；`tenants.callback_url` 覆盖全局；投递地址支持 `host:port` | `[x]` |
| G10 | 完整 OpenAPI 3.0 + 稳定错误码 `{code, message}` | `[x]` |
| G11 | `/metrics`（Prometheus） | `[x]` |
| G12 | 并发与存储（`_txlock=immediate`；PostgreSQL/多副本明确不做） | `[x]`（范围已收敛） |
| G19 | ES2+ 标准一致性修正 | `[x]` |
| G20 | SM-DS 事件透视与运维 | `[x]` |
| N1 | 审计单调增量游标 `GET /audit?afterId=&limit=` | `[x]` |
| N2 | 回调队列管理 API（查询/单条重投/批量重投） | `[x]` |
| N3 | 租户删除引用保护（`409 tenant_in_use` + `usage`；`force` + `reassignTo`） | `[x]` |
| N11 | `additionalEuiccProfilePackageVersions` + 版本集合 + 会话持久化 + 删 `major<=0` 回退 | `[x]` |
| N15 | `ServicesList` 24 项 + TUAK-256 修复 + `ber-tlv` 拼写 | `[x]` |
| N13 | Annex B 模板表（14 OID）+ 约束校验 + 测试向量 | `[x]`（值域校验由 R1 补齐） |
| N17 | `SdKey*`（`PE-SecurityDomain.keyList`）与 `MncLen`（`EF.AD`，FID `6FAD`）个性化 | `[x]` |

> N6/N10 → §8.4 决策 11（**范围外**）；N14 → §0.4（**范围外**）。

---

## 3. 可选 [P2] 与代码级一致性（C 清单）

### 3.1 第二轮可选项（N4 / N5 / N7–N10）

| # | 改动 | 状态 |
|---|---|---|
| N4 | `/upp/{name}/schema` 的 `fields[]` 增 `applicable`/`targets[]`/`requiredIn[]`/`note`；`required` 由 `requiredIn` 派生，`iccid` 与凭据池流程解耦 | `[x]`（目录 19 项） |
| N5 | `/upp/render` 接受 `{name}` 或 `{data}` 二选一；`data` 路径不落库 | `[x]` |
| N7 | `profiles/stats` 的 `groupBy` 补 `profile_type`；`sort` 补 `tenant`/`-tenant`；删除 catch-all `error` 码 | `[x]` |
| N8 | SM-DS `POST /events`、`DELETE /events/{id}`（软删） | `[x]`（首期仍由 `ConfirmOrder` 自动注册） |
| N9 | HTTP 延迟直方图 | **暂不做**（R9） |
| N10 | 密钥端点显式契约 | **范围外**（随 N6） |

### 3.2 代码级一致性修复（C 清单）

> 核对 SGP.22 v2.7 原文与代码时实测发现的问题；esim42 未逐条点名，但直接影响其分支判断与契约生成。**C1 被源码注释引用**（`config/config.example.yaml`），编号保留。

| # | 问题 | 状态 / 落地 |
|---|---|---|
| C1 | ES2+ `downloadOrder.pprIds` 与“零 JSON body 扩展”冲突 | **已落地**：删除该私有成员，PPR 只走管理 API / `profiles.ppr_ids`；PPR 被 eUICC `forbiddenProfilePolicyRules` 拒绝时以 `8.2.5/4.3` 应答并补 point-1 进度通知（SGP.22 §5.7.5） |
| C2 | `profileType` 解析静默降级 | **已修**：未解析时计数 `rsp42_es2p_profile_type_unparsed_total` 并写审计 |
| C3 | `8.2.1/3.8` 语义重载 | **已修**：配额/无可用 → `8.2.5/3.7`；ICCID 不可用 → `8.2.1/3.3`；其余 → `8.2/4.2` |
| C4 | `8.2.6/3.7` 语义错位 | **已修**：`CodeProfileUpdateFailed` → `8.2/4.2` |
| C5 | `internal/asn1/doc.go` 陈述过期 | **已修**：doc 重写；并完成依赖收紧，仅 `internal/asn1/construct.go` import bertlv |
| C6 | `FileHandle.Body()` 忽略 `fillFileOffset` | **已修**（并入 N13），补 offset 分片回归测试 |
| C7 | `ServicesList` 命名 `bertlv` vs 规范 `ber-tlv` | **已修**（随 N15）；这是 `/upp/{name}/decoded` 的对外契约变更 |
| C8 | BER 不定长被显式拒绝 | **已核查**：全部 TS.48 向量与 SGP.26 证书以定长解析通过；登记为已知边界（`TODO.md` §2-6），出现真实样本再评估 |
| C9 | V3.4/3.4.1 的 PE tag 常量缺失 | **已登记**：`TODO.md` §2-7 记为**明确范围外**（对应 §0.4）；N13 对带 `mandated` 的非 V2.3.1 PE 给 warning |
| C10 | 无值域约束校验 | **已落地**：N13 实现结构/语义约束，R1 补齐逐文件默认表与 `SIZE`/取值域（`internal/saip/{filetable,filevalidate,constraints}.go`） |
| C11 | `RebuildMandatoryServices` 覆盖不全 | **已修**（随 N15）：`Services()` 覆盖 0–23；职责边界写入 `header_services.go` |

---

## 4. 数据库变更（已落地）

> 本节最后一次作为“草案”的依据是：把租户列合并进 `00001_init.sql`。**该设想未采用**——仓库当时已存在 `00002..00006`，合并等于整库 squash（并使已迁移库的 goose 版本校验失败）。实际落地为**追加式** `00007`–`00011`（见 §9.1）。

| 迁移 | 内容 | 来源 |
|---|---|---|
| `00007_esim42_tenancy.sql` | `tenants` 表 + 各资源 `tenant_id`（G2） | G2 |
| `00008_credentials_pool.sql` | 凭据池：`personalization` 改 `id` 主键、可空 `iccid`、`UNIQUE(tenant, imsi)` | G6 |
| `00009_smds_registration_tenant.sql` | ES12 注册租户（`X-RSP42-Tenant` 头） | G20 |
| `00010_upp_template_versions.sql` | `upp_template_versions` 归档 + 回滚 | G18 |
| `00011_session_euicc_versions.sql` | `sessions` 增 `euicc_profile_version`、`euicc_supported_versions`（JSON）、`uicc_capability` | N11/N12 |

> 本轮（第三轮）**无需新迁移**：N1（审计游标）复用既有 `audit_log.id`（`INTEGER PRIMARY KEY AUTOINCREMENT`）；N2（回调过滤）用 `json_extract(payload_json,…)`（modernc.org/sqlite v1.60.1 支持 JSON1）；N3 只做引用计数与批量改属。原计划中的 `00012_audit_autoincrement.sql` / `00013_callback_columns.sql` **均不需要**。迁移仍保持追加式，每条需做“老库升级 + 新库全量”双向验证。

---

## 5. 管理 API（已落地；权威 = OpenAPI）

> 权威契约：`internal/api/openapi/openapi.json`（OpenAPI **3.0.3**，`info.version 0.2.0`，`//go:embed`；线上 `GET /admin/api/v1/openapi.json`）。当前 **66 个 operation / 52 个 path**（上一版为 61/48）。
> **路径已迁移**：该文档现位于 `internal/api/openapi/openapi.json`（`admin` 与 `dsadmin` 共用），esim42 的快照路径需同步。
> SM-DS 监听器上的同名端点返回**只含 `/events`** 的过滤文档（`openapi.FilteredDoc` 定义在 `internal/api/openapi`，由 `internal/api/dsadmin` 调用）。

上一版 §5 的“变更草案”已全部实现；esim42 侧的可消费矩阵见其 `02` §3。本轮相对上一版的关键差异：

| 维度 | 现状 |
|---|---|
| 错误模型 | `{"code","message"}` + HTTP 状态；具名码定义在 `internal/api/adminhttp/adminhttp.go`（上一版文档写 `admin/admin.go`，已迁包）；删除了 catch-all `error`，兜底为 `request_failed` |
| 租户作用域 | 所有列表/写接口接受 `tenant`；非空 tenant 未注册 → `400 unknown_tenant`；空串 = 平台默认（`tenant_id IS NULL`） |
| 分页 | 统一 `page`/`size`（1–500）；审计另有游标信封 `{items[].id, nextAfterId, hasMore}`，与 `page/size` 互斥 |
| 排序 | 白名单 `created_at\|updated_at\|iccid\|state\|tenant\|installed_at`；`-` 前缀表示**升序**（与常见约定相反） |
| 幂等 | `Idempotency-Key` 用于 `POST /profiles`、`POST /profiles/import`、`POST /batches`；重放带 `Idempotency-Replayed: true`，冲突为 `409 idempotency_key_reused` / `idempotency_key_in_flight` |
| 新增端点 | `/callbacks`（N2）、审计游标 `afterId`（N1）、SM-DS `POST/DELETE /events`（N8）；`/metrics` 在 admin 监听器上但**不在** `/admin/api/v1` 下 |

---

## 6. ES2+ 变更（已落地；**零 JSON body 扩展**）

> 规范依据：ES2+ JSON body 的字段集合是封闭枚举（下载：仅 `eid`/`iccid`/`profileType`），规范**没有**“忽略未知成员”的向前兼容条款；而 SGP.22 §6.2 明确允许**额外 HTTP 头**。因此私有信息只走 HTTP 头，body 一律用标准字段。详见 §8.2。

| 函数 | 变更 | 规范依据 / 状态 |
|---|---|---|
| `downloadOrder` | 模板/产品选择用 `profileType`（约定 `"<tenant>/<template>"`） | §6.5.2.1 + Table 22 NOTE；已落地 |
| `downloadOrder` | 实现 Table 24 NOTE 优雅重发：ICCID 已存在且入参一致 → `Executed-Success` + 原 ICCID，不重复扣池 | 已落地 |
| `downloadOrder` | **移除私有 body 成员 `pprIds`**（C1）；PPR 只走管理 API；PPR 落入 eUICC `forbiddenProfilePolicyRules` → `8.2.5/4.3` + point-1 回调 | 已落地（§5.7.5） |
| `downloadOrder` | 租户归属取自 `header.functionRequesterIdentifier` 映射（决策 3；不采用每运营商证书）；未映射回落平台默认并在审计记 `unmapped` | 已落地 |
| `downloadOrder` | `profileType` 不含 `/` 时不再静默回落（记审计/指标 `profileType-unparsed`） | C2；已落地 |
| `confirmOrder` / `cancelOrder` / `releaseProfile` | 仅按需支持 `Idempotency-Key` HTTP 头；同 key 同 body 回放，5xx 释放 key | §6.2；已落地 |
| `confirmOrder` | EID 与下单不一致 → `8.1.1/3.10` Invalid Association | §5.3.2；已落地 |
| `authenticateClient` | 无兼容模板 → `8.2.6/3.8` + 可读 message，且**不生成任何 BPP 段** | N12；已落地 |
| SM-DP+ 地址 | 接受 `host:port`（`89308b2`） | 已落地 |
| ACR（`HandleAcrRequest`） | 请求体只有 `{header, iccid}`；拒绝 → `8.2.1/1.2` 且不重试；ACR-0 轮换 MatchingID 并返回新激活码（`MATCH-<hex>`，不进 `ACR-` 命名空间）；`profiles.allow_redownload_after_delete`（默认 `false`）控制 delete 通知后是否退回 `Released` | §5.3.8 / §3.1.7；已落地 |
| 全部 | 越权状态码：ICCID → `8.2.1/1.2`；Profile Type/模板 → `8.2.5/1.2` | 已落地 |
| 回调 | 载荷增 `tenantId`、`externalRef`、`matchingId`；`notificationPointId` 新增 `17` = ACR | 纯增量；已落地 |

> **ES2+ 错误码以 `internal/rsp/status/status.go` 为准**（上一版 §6 的表格已被 C3/C4/N12/C1 的拆分取代）。esim42 侧的正确分支见其 `02` §2.6；本轮唯一需要 rsp42 修正的是 `docs/interfaces.md` §Quotas 的漂移（§0.6-1）。

---

## 7. 实施里程碑（第一轮 G / 第二轮 N：均已完成）

| 里程碑 | 内容 | 状态 |
|---|---|---|
| **M1（租户与审计）** | G2 租户维度、G8 actor 修复、G17 文档对齐 | 已完成 |
| **M2（下单与领取闭环）** | G3 `profileType` 选择、G4 EID 回写、G5 重发幂等、G6 ICCID 池加固、G19 标准一致性、G20 SM-DS 事件透视（含 `smds` 角色） | 已完成 |
| **M3（模板与个性化）** | G7 能力外露、G6 凭据池/IMSI 池 | 已完成 |
| **M4（运维与契约）** | G8 统计接口、G10 OpenAPI/错误码、G11 metrics、G12 `BEGIN IMMEDIATE` | 已完成 |
| 第二轮批 1（P0） | N16 → N12（含 N11 接口预留） | 已完成 |
| 第二轮批 2（P1） | N2 → N3 → N1（N6 范围外） | 已完成 |
| 第二轮批 3（P1） | N15 → N13 → N17 | 已完成 |
| 第二轮批 4（P2） | N4 → N5 → N7 → N8（N9 暂不做、N10 范围外） | 已完成 |
| 并行（工程化） | C1–C11 与文档同步 | 已全部处理 |

**验收基线（esim42 侧）**：端到端联调（匿名领取 → LPA 下载 → 安装 → 看板可见 → 审计可查 → 取消/回池），全链路租户归属正确、幂等重放安全；对应其 `02` §9 的 A1–A33（A13–A17 依赖 N13/N15/N17，A26–A33 依赖 N16/N13/N1/N3/N4/N5/N8/N12）。

---

## 8. 已对齐决策

### 8.1 决策表

| # | 问题 | 结论 | 对本文档的影响 |
|---|---|---|---|
| 1 | 租户 ID 由谁生成 | **直接用 esim42 的 Carrier 主键**作为 rsp42 `tenants.id`，不做二级映射 | G2 的 `tenants.id` 语义固定；esim42 的 `carriers.id` 一旦分配即不可变 |
| 2 | 调用通道 | **订单走 ES2+，管理走 Admin API** | G3/G5 必须在 ES2+ 与 Admin 两侧都实现 |
| 3 | 租户归属的承载方式 | **`header.functionRequesterIdentifier` 映射**（标准字段，零协议扩展）；**每运营商客户端证书明确不做**（§8.4） | G2 的解析器由此确定；§6 无 JSON body 扩展；§8.3 仅作历史备查 |
| 4 | K/OPc 是否允许 rsp42 生成 | **esim42 生成，rsp42 只存与注入** | rsp42 不提供密钥生成/派生端点；G7 的 `/schema`、`/render` 只承载字段与校验 |
| 5 | 部署形态 | **同机同网**（esim42 后端 ↔ rsp42 管理 API 内网直连），esim42 前端只经 esim42 后端 | 管理 API **不鉴权**（§0.1-4，原 G1 排除）；存储固定 SQLite 单进程，PostgreSQL 与多副本明确不做（§8.4） |
| 6 | SM-DS 是否启用 | **启用**：esim42 经 rsp42 走 ES12 事件注册/删除，并以 `/events` 做透视 | G20；SM-DS 能力已具备，事件查询/清理已补齐 |
| 7 | SAIP 基线版本 | **V2.3.1（包内编码 `(2,3)`）** | N16/N12（第二轮仅有的两个 P0）已落地；SAIP V3.x 与 Annex F 降级构造（N14）列为范围外（§0.4） |
| 8 | 版本上限的配置形态 | **列表** `profiles.allowed_saip_versions: ["2.3"]`，**不是**标量 `max_saip_version` | 与 esim42 `06` §13.1 R1 一致（零成本预留）；esim42 的 `01` §6.5 D2 已改为列表表述 |
| 9 | 双 major 选择逻辑 | **现阶段不做**，只做接口预留：`SelectBestFor` 收版本集合、移除 `major<=0` 的 `AnyForTenant()` 回退 | N11 的落地形态；esim42 `06` §13.1 已把双 major 登记为“未来规划” |
| 10 | 回调队列是否可重投 | **做**（N2）：新增管理 API，让死信可查、可补投 | rsp42 队列 API + esim42 对账任务共同构成回调可靠性 |
| 11 | 管理 API 监听面收敛与密钥导出护栏（N6/N10） | **明确不做**。admin `bind` 默认值保持现状；不引入 `X-RSP42-Reveal-Secrets: yes`、`Cache-Control: no-store` 与 secret-bearing 标注 | 安全边界完全由 esim42 承担（§0.1-4、§8.4 决策 11） |
| 12 | 第三轮新增缺口 R1–R9 的处置 | **R1 已实施**（Annex A 逐文件默认表 + §8.3.3 规则 + ASN.1 `SIZE` 域，接入 `/upp/validate` 与 `/upp`）；R2 待真机/一致性工具裁决；R3 仅影响 ASN.1 binding；R4/R5 非阻塞；R8/R9 维持“范围外/暂不做” | 见 §0.5 与决策 12（§8.4 后表） |
| 13 | 对外文档修正 | `docs/interfaces.md` 配额码漂移**必须修正**；`coverage.md` 登记 R2/R3；`interfaces.md` 写明 N13 边界 | 见 §0.6（仅文档，不改代码） |

### 8.2 决策 3 的规范依据（备查）

- **ES2+ 不能新增 `tenantId` JSON body 字段**：SGP.22 v2.7 §6.5.2.1 对 `ES2+.DownloadOrder` 的 body schema 只定义 `eid`、`iccid`、`profileType`（Table 22 的 MOC 为 O/C/C）；规范没有 `additionalProperties: false`，也**没有**“接收方 SHALL 忽略未知成员”的向前兼容条款（对比 Activation Code 明确写了 “Device SHALL ignore … further parameters”）。上一版的 `downloadOrder.pprIds` 即此类既有私有扩展，**已按 C1 删除**（v2.7 中 `pprIds` 只出现于 `RulesAuthorisationTable` §5.7）。
- **私有信息放 HTTP 头是规范显式允许的**：SGP.22 §6.2 “HTTP POST request and response MAY contain additional header fields. Their use is out of scope of this specification.” → `Idempotency-Key`、ES12 的 `X-RSP42-Tenant` 等走表头，body 成员不走。
- **承载分工**：租户 ← `functionRequesterIdentifier`（§6.5.1.3，无格式约束）；模板/产品 ← `profileType`（§6.5.2.1 + Table 22 NOTE）；幂等 ← Table 24 NOTE + HTTP 头；`externalRef` ← 不上线，esim42 以 `downloadOrder` 返回的 ICCID 作为自身外键。
- **残留风险（已知并接受）**：`functionRequesterIdentifier` 是调用方自述字段，租户归属实质是“信任 esim42 后端”；在决策 5 的内网单后端前提下可接受。**“运营商绕过 esim42 直连 rsp42”不在支持范围内**：每运营商客户端证书明确不做（§8.4），该拓扑一旦出现，必须改为每运营商独立部署 rsp42。

### 8.3 每运营商客户端证书（**明确不做**——仅作历史备查，不再评估）

- **rsp42 侧：低。** mTLS 管线已存在（`es2p.tls.client_ca_file` + `RequireAndVerifyClientCert`）；身份提取可复用 ES12 `callerOID` 与 `cert.RegisteredIDs`。限制：`client_ca_file` 为**单一 CA**；无 CRL/OCSP（`docs/coverage.md`），吊销只能撤映射/换 CA。
- **esim42 侧：中。** TLS 握手早于 HTTP 请求，无法按请求选证书 → 每运营商一个 `http.Client`/transport；主要成本在**证书生命周期**（签发、分发、密钥保管、轮换、撤销）。
- **结论（已收敛为“不做”）**：决策 3 选择 `functionRequesterIdentifier`，且 §8.4 决策 9 明确**不做**每运营商证书。本节其余内容只保留为历史分析。

### 8.4 明确不做（决策 7–11）

| # | 问题 | 结论 | 落地表现 |
|---|---|---|---|
| 7 | 数据库后端 | **只做 SQLite**。PostgreSQL/MySQL 等**明确不做** | `profiles.repository` 仅接受 `sqlite`；配置校验对其它取值直接报错 |
| 8 | 多副本部署 | **明确不做**。单进程、单数据库文件 | 无 leader 选举、无分布式锁；GC/ticker 在进程内。横向扩容需重新立项 |
| 9 | 每运营商客户端证书 | **明确不做**。ES2+ 租户归属只用 `functionRequesterIdentifier` 映射 | §8.3 降级为历史备查；“运营商直连 rsp42”不在支持范围 |
| 10 | rsp42 侧限流 | **明确不做**（不提供 429 语义） | 限流由 esim42 前置承担；rsp42 只做资源级配额硬校验（`tenants.template_quota` / `profile_quota`） |
| 11 | 管理 API 监听面收敛与密钥导出护栏（N6/N10） | **明确不做**。admin `bind` 默认值保持现状；不引入 reveal 护栏、`Cache-Control: no-store` 与 secret-bearing 标注 | 安全边界完全由 esim42 承担（§0.1-4、§8.1 决策 5）：esim42 必须保证管理 API 不被反向代理、网关或前端暴露 |
| 12 | R1（SAIP §9 逐文件默认表 + 值域校验） | **做，且已落地**：Annex A 表（14 模板 / 307 行）+ §8.3.3 模板修改规则 + ASN.1 `SIZE`/整数域，全部接入 `/upp/validate`、`/upp`、`clone`/`promote`/`restore` | `internal/saip/{filetable,filevalidate,constraints}.go`（表数据在 `filetable.txt`）；`validate_test.go` 的 `TestValidateTS48Vectors` 为 TS.48 回归门禁；边界见 `docs/interfaces.md`「UPP validation scope」 |
| 13 | R2 / R3 的登记 | **已登记**（R2 待真机/一致性工具裁决，R3 只影响 ASN.1 binding） | `docs/coverage.md`「Open interoperability observations」 |

> 说明：前四项此前在本文中写作“不实施/仅备查/未来加固”，容易被读成“以后可能做”；决策 11 为上一轮复核后新增的范围收敛项。现统一收敛为**范围外**：文档不再把它们列为待办，代码也不再为它们预留会被误用的配置语义。

---

## 9. 实施状态（rsp42 侧，已落地）

> 图例：`[x]` 已实现并有测试；`[~]` 部分实现/已登记后续；`[ ]` 未做；`—` 范围外/暂不做。
> **§9 的状态表与 §9.1–§9.3 覆盖第一轮 G 清单；第二轮 N 清单见 §9.4。**

| # | 项 | 状态 | 落地位置 |
|---|---|---|---|
| G2 | 租户维度 | `[x]` | `internal/store/migrations/00007_esim42_tenancy.sql`、`store/tenant.go`、`store/{profile,upp,pool,batch,personalization,audit,events,order}.go`、`api/admin/tenants.go`、`api/es2plus/handlers.go`（`functionRequesterIdentifier` → 租户）、`config.smdpp.es2p.requester_tenants` |
| G3 | `profileType` 选择模板 | `[x]` | `api/es2plus/handlers.go:resolveProfileType`、`service/download.go:loadUPP`（五级候选，移除 `Any()` 兜底）、`tenants.default_upp` |
| G4 | 下载回写 EID | `[x]` | `service/cmae.go` `AuthenticateClient`（EID 为空则绑定；`Allocated → Linked`） |
| G5 | 幂等与业务关联 | `[x]` | `service/inventory.go:sameResend`（Table 24 NOTE）、`api/middleware/idempotency.go`（`Idempotency-Key`，哈希排除易变 `functionCallIdentifier`）、`store/idempotency.go`、`profiles.external_ref` |
| G6 | 池加固与凭据池 | `[x]` | `store/pool.go`（租户隔离、`reserved_until`、`reference`、`profile_id`、`ReleaseExpired`）、`service/inventory.go` 失败回滚、`service/order.go` Cancel/Delete 回池、`store/personalization.go`（`ReservePair`）、`POST /personalization/pool/import` |
| G7 | SAIP 模板能力外露 | `[x]` | `GET /upp/{name}/schema`、`POST /upp/validate`、`POST /upp/render`、`POST /upp/{name}/clone`、`POST /upp/{name}/promote`（`api/admin/upp_tools.go`、`internal/uppinspect`）；个性化新增 PLMN/MSISDN/ACC/任意 EF 覆盖 |
| G8 | 审计与看板 | `[x]` | `api/middleware`（actor 取 mTLS 主体 / `functionRequesterIdentifier` / ES12 caller OID；管理 API 记 `esim42-backend`）、`audit_log.tenant_id`、`GET /audit/stats`、`GET /profiles/stats`、`GET /notifications`、timeline 含 session + 审计事件 |
| G9 | 回调字段与租户路由 | `[x]` | `ProgressInfo` 增 `tenantId/externalRef/matchingId`；`tenants.callback_url` 覆盖；`docs/interfaces.md` 补 `notificationPointId` 语义（含 17=ACR） |
| G10 | OpenAPI + 错误码 | `[x]` | `internal/api/openapi/openapi.json`（OpenAPI 3.0.3，`info.version 0.2.0`，`//go:embed` + 校验测试）、`internal/api/adminhttp` 的 `{code,message}` |
| G11 | 可观测性 | `[x]` | `internal/metrics`，管理监听器 `GET /metrics` |
| G12 | 并发与存储 | `[x]`（范围已收敛） | `store.Open` 统一追加 `_txlock=immediate`；并发 200 次领号测试；PostgreSQL 与多副本明确不做（§8.4 决策 7–8） |
| G13 | ACR 调用方侧接线 | `[x]` | `service.ACRChecker` + `es2plus.CallbackClient.HandleAcrRequest`（Table 32d/32e）；拒绝不重试、传输失败退避重试、`acr_timeout` 兜底；ACR-0 轮换与 delete 通知已接线 |
| G14 | MatchingID 轮换 | `[x]` | `POST /profiles/{iccid}/activation-code?rotate=1` |
| G15 | 配额硬校验 | `[x]` | `template_quota`（409 `quota_exceeded`）与 `profile_quota`（ES2+ `8.2.5/3.7`）硬校验；rsp42 侧限流/429 明确不做 |
| G16 | 聚合与导入补强 | `[x]` | `GET /eids`；`POST /profiles/import` 支持 `text/csv` 与逐行错误报告；事件查询已按 G20 完成 |
| G17 | 文档一致性 | `[x]` | `README.md` / `docs/interfaces.md` / `docs/operations.md` / `docs/coverage.md` 已对齐；§Quotas 的 `8.2.1/3.8` 漂移**已修正为 `8.2.5/3.7`**（§0.6-1） |
| G18 | 模板版本与回滚 | `[x]` | `00010_upp_template_versions.sql` + `GET /upp/{name}/versions`、`POST /upp/{name}/versions/{id}/restore` |
| G19 | ES2+ 标准一致性 | `[x]` | 重发（Table 24 NOTE）、`confirmOrder` EID 不一致 `8.1.1/3.10`、状态码拆分（`8.2.1/3.9` / `8.2.5/3.9` / `8.2.5/1.2` / `8.1.1/2.2` / `8.1/1.2`） |
| G20 | SM-DS 事件透视 | `[x]` | `GET /events` 增 `tenant`/`iccid`/`matchingId`/`status`/时间范围/排序/级联与 OID；ES12 写入携带 `tenant_id`（`X-RSP42-Tenant`）；注册失败写审计并计数；事件过期 GC 与 `event_ttl` 对齐 |

### 9.1 迁移与实施偏差（已确认实施选择）

1. **迁移文件为 `00007`—`00011`**（租户、凭据池、ES12 注册租户、模板版本、会话版本）。
2. **数据库变更未合并进 `00001_init.sql`**。§4 当时的建议基于“单一当前 schema 迁移”的设想；但仓库现状已存在 `00002..00006`，合并意味着整库 squash（并使已迁移数据库的 goose 版本校验失败）。因此改为追加式迁移，且不做任何向后兼容代码。
3. **ES12 的租户归属走 HTTP 头 `X-RSP42-Tenant`**（§6.2 明确允许额外头部），而非新增 ES12 body 成员。服务端另有 `smds.es12.requester_tenants`（caller OID → 租户）作为回落。**esim42 不需要直接调 ES12**（rsp42 smdpp 在 `ConfirmOrder` 时代劳），仅在自建 SM-DP+ 角色时才需要。

### 9.2 明确不做（决策 7–11，见 §8.4）

1. **PostgreSQL / 其他数据库后端**：仅 SQLite。
2. **多副本部署**：单进程、单数据库文件、无 leader 选举/分布式锁。
3. **每运营商客户端证书**：ES2+ 租户归属只用 `header.functionRequesterIdentifier`（§8.3 为历史备查）。
4. **rsp42 侧限流 / 429 语义**：由 esim42 前置承担。
5. **管理 API 监听面收敛与密钥导出护栏（N6/N10）**：admin `bind` 保持现状；安全边界完全由 esim42 承担（§0.1-4、§8.1 决策 5）。

### 9.3 第一轮（G）：P2 状态

**无未做的 P2。** G13–G18 已全部落地。§9.2 列出的五项为**明确不做**（范围外）。

### 9.4 第二轮（N）：实施状态

> 来源：`../esim42/todo/02` §7.2 与 `01` §8。判定为本仓库当前代码（`89308b2`）逐条实测。

| # | 项 | 状态 | 现状证据 |
|---|---|---|---|
| N16 | SAIP 版本上限 | `[x]` | `profiles.allowed_saip_versions`（`internal/config/config.go`、`config/config.example.yaml`）+ 唯一 choke point（`internal/service/saip_version.go` → `internal/saipver`）；`api/admin/upp.go`（`putUPP` 409 `saip_version_not_supported` + `details`）、`upp_tools.go`（`validateUPP` warning、`clone`/`promote`/`restore` 同校验）、`internal/cli/admin/admin_upp.go`（CLI import 同策略） |
| N12 | 版本不兼容干净失败 | `[x]` | `internal/service/download.go` `resolveUPPTemplate`/`loadUPP`（五级候选均校验，显式 pin 不回落）；`ErrProfileVersionNotSupported`；`rsp.CodeProfileVersionNotSupported`（`8.2.6/3.8`）；`CMAE.noteVersionFailure` 写审计并计数；`AuthenticateClient` 提前干净失败；迁移 `00011` |
| N1 | 审计单调游标 | `[x]` | `store.AuditEntry.ID` + 所有 SELECT/scan 补 `id`；`ListAfterID`（排他下界、`id ASC`）；`GET /audit?afterId=&limit=` 响应 `{items[].id, nextAfterId, hasMore}`，与 `page`/`size` 互斥。**无需迁移**：`audit_log.id` 本就是 `INTEGER PRIMARY KEY AUTOINCREMENT` |
| N2 | 回调队列管理 API | `[x]` | `store.CallbackFilter`/`ListFiltered`/`Requeue`/`RequeueDead`（tenant/iccid 走 `json_extract(payload_json,…)`，**无需迁移**）；`api/admin/callbacks.go`：`GET /callbacks`（`payload` 已解析对象）、`POST /callbacks/{id}/retry`（非 dead/failed → 409）、`POST /callbacks/retry-dead`；审计 `retryCallback` |
| N3 | 租户删除引用保护 | `[x]` | `store.TenantUsage`/`Usage`/`DeleteWithReassign`；`api/admin/tenants.go`：被引用 → `409 tenant_in_use` + 顶层 `usage`；`?force=true&reassignTo=`（未注册 → `400 unknown_tenant`，自指 → `400 invalid_request`）；`GET /tenants/{id}` 增 `usage`。esim42 的 `credential_assignments` 需其自行计入 |
| N6 | admin 监听面 / 密钥导出加固 | `—` | **范围外**（§8.4 决策 11）；现状 `config/config.example.yaml:19,77` = `0.0.0.0`，无 reveal 头校验，**不改** |
| N11 | `additionalEuiccProfilePackageVersions` | `[x]` | `internal/rsp/euicc_info.go`（`EUICCInfo2` 解析 `[15]`、`SupportedVersions()`、`IsV3Capable()`）+ `internal/rsp/version.go`；`store.SelectBestFor` 改版本集合入参并移除 `major<=0 → AnyForTenant()` 回退；会话持久化（迁移 `00011`）；指标 `rsp42_euicc_v3_capable_total` |
| N15 | `ServicesList` 24 项 | `[x]` | `internal/saip/header.go` + `header_services.go`：补 `dfLink`(19)/`cat-tp`(20)/`get-identity`(21)/`profile-a-x25519`(22)/`profile-b-p256`(23) + `svcMax`；`bertlv` → `ber-tlv`（对外契约变更，C7）；TUAK-256 按 K 长度 16/32 置位；`services_test.go` |
| N13 | Annex B 模板表 + 约束 + 向量 | `[x]` | `internal/saip/templates.go`（V2.3.1 Annex B = **14 个模板 OID**，`2.23.143.1.2.1`–`.2.14` + spec-version `2.23.143.1.1.2`；无版本化子弧）、`internal/saip/validate.go`（结构/单例/可选顺序/mandatory-services↔PE/AKA↔服务位/identification 唯一/File `doNotCreate`·`fileDescriptor`/GFSTE ⊆ 14 模板且拒绝带版本子弧/非 V2.3.1 PE 带 `mandated` → warning）、修 `files.go` 的 `Body()` `fillFileOffset`；`/upp/validate` 硬失败 → `valid:false`+`errors[]`，`/upp` → `400 invalid_upp`。**范围说明**：原“V2.3.1 §9 逐文件默认表与值域校验未编码”已由 R1 落地补上 |
| N17 | `SdKey*` / `MncLen` | `[x]` | `internal/saip/personalization/personalization.go`：`Data.SdKeys`（完整 `KeyObject`）注入 `PE-SecurityDomain.keyList`；`Data.MncLen` 写 **`EF.AD` = FID `6FAD`**（TS 31.102 §4.2.23，byte-4 低半字节；上一版文档写的 `6F3A` 是 `EF.LI`，已更正）；`csv.go` 增列；`uppFieldSchema` 同步（目录 19 项） |
| N4 | schema 模板级字段可用性 | `[x]` | `api/admin/upp_tools.go`：`uppFieldSchema` 增 `applicable`/`targets[]`/`requiredIn[]`/`note`；`annotateSchema` 按 `inspection` 逐模板解析；`required` 由 `requiredIn` 派生（`iccid` = `["render"]`） |
| N5 | `/upp/render` 未入库模板 | `[x]` | `renderUPP`：`{name}` 与 `{data:"<base64 DER>"}` 二选一，二者同给或都缺 → `400 invalid_request`；`data` 路径不落库，审计 `function=renderUPP, subject="<ad-hoc>"` |
| N7 | 统计 / 排序契约补全 | `[x]` | `openapi.json`：`profiles/stats` 的 `groupBy` 补 `profile_type`、`sort` enum 补 `tenant`/`-tenant`；`store/profile.go` 白名单补 `tenant`；删除 catch-all `"error"` 码（兜底 `request_failed`）；`/iccid-pool/stats` 的 `tenant` 本已列 |
| N8 | SM-DS 事件管理写接口 | `[x]` | `internal/api/dsadmin/dsadmin.go`：`POST /events`（省略 `eventId` 生成 `EVT-<…>`；重名 → `409 event_id_in_use`；`ttl`/`expiresAt` 可控）、`DELETE /events/{id}`（软删）；审计 `registerEvent`/`deleteEvent` |
| N9 | HTTP 延迟直方图 | `—` | **暂不做**（R9）；`internal/metrics` 不新增 Histogram |
| N10 | 密钥端点显式契约 | `—` | **范围外**（随 N6）；现状无 `Cache-Control`、`docs/interfaces.md` 未标注，**不改** |
| N14 | Annex F 降级构造 | `—` | **范围外**（§0.4），不预留代码位/开关 |

**代码级一致性（C1–C11，见 §3.2）**：**C1/C2/C3/C4/C5/C7/C9/C11 已处理**；**C6/C10 并入 N13、C7 并入 N15**；**C8 登记为已知边界**。

**本轮（第三轮）新增**：R1–R9（§0.5）。**R1 已落地**（`internal/saip/{filetable,filevalidate,constraints}.go` + 测试），`TODO.md` §2-2 已由“未内置”改为“已实现”；R2/R3 已登记进 `docs/coverage.md`；C10 随之闭环。剩余：**R2 待真机/一致性工具裁决**、**R9 暂不做**（用户决定），R4/R5 非阻塞，R8 为部署约束。

---

## 10. 第二轮实施计划与已定决策（已完成归档）

> 本节原为分步实施计划与 DoD；截至 `89308b2`，**批 1–4 与 C 清单均已按计划完成**。以下保留顺序、迁移与已收敛决策，作为 §9.4 的索引。

### 10.1 批次与顺序（均已完成）

```
批 0 决策 → ┬─ 批 1（N16 → N11 → N12）      ← esim42 M2 的硬性退出条件
            ├─ 批 2（N2 → N3 → N1）          ← N6 范围外
            ├─ 批 3（N15 → N13 → N17）
            └─ 批 4（N4 → N5 → N7 → N8）      ← N9 暂不做、N10 范围外
并行：C1–C11 与文档同步；每批结束跑 make ci
```

- **批 0（地基与口径）**：N11 的依据以 `refs/SGP.22-v2.7-.pdf` §5.7.6 为准（`additionalEuiccProfilePackageVersions [15] SEQUENCE OF VersionType OPTIONAL`）；会话版本列的必要性（`loadUPP` 执行时只有 `sessions` 行，eUICC 版本仅在 `AuthenticateClient` 可见）；SAIP 版本校验统一收敛到一个 choke point（禁止 handler 内联，否则 CLI 导入会绕过）。
- **N13 的“13 vs 14”**：计划原写 **13**，参照 `refs/Profile interoperability technical specification_V2.3.1 Final.pdf` 核实 Annex B 实际为 **14** 个模板 OID（`2.23.143.1.2.1`–`.2.14`，含 MF `.2.1` 与 DF.CD `.2.2`）+ spec-version `2.23.143.1.1.2`。实现按权威的 14 项进行。

### 10.2 迁移文件（见 §4）

`00011_session_euicc_versions.sql` 已落地；`00012`/`00013` 经复核**不需要**（§4 注）。

### 10.3 已收敛决策（本轮复核确认仍有效）

| # | 决策 | 结论 |
|---|---|---|
| 1 | N11/N12 是否新增会话版本列 | **是**，迁移 `00011`（否则 `loadUPP` 阶段无法校验版本） |
| 2 | N2 的 tenant/iccid 过滤实现 | **`json_extract(payload_json,'$.tenantId'/'$.iccid')`**（modernc.org/sqlite v1.60.1 支持 JSON1），零迁移 |
| 3 | N1 的严格单调 | **无需迁移**：`audit_log.id` 已是 `AUTOINCREMENT`；N1 只把既有 id 暴露到接口 |
| 4 | C1 的 `pprIds` | **删除该成员**；PPR 只走管理 API / `profiles.ppr_ids` |
| 5 | C8 的 BER 不定长 | 先核查真实样本，再定“支持”或“登记为已知边界” |
| 6 | N16 的校验覆盖面 | 统一 choke point，覆盖 `clone`/`promote`/`restore` + CLI `upp import` |
| 7 | 密钥端点 reveal 护栏是否覆盖 `GET /personalization?reveal=1` | 若实施则**是**；但 N6/N10 整体**不做**，本条暂缓 |
| 8 | N6/N10（监听面收敛 + 密钥导出护栏） | **明确不做**（§8.4 决策 11） |
| 9 | N9（HTTP 延迟直方图） | **暂不做**（§0.5-R9）；`/metrics` 保持现有计数器/仪表 |

### 10.4 验收基线

- esim42 侧完成端到端联调（匿名领取 → LPA 下载 → 安装 → 看板可见 → 审计可查 → 取消/回池），全链路租户归属正确、幂等重放安全；对应 esim42 `02` §9 的 A1–A33。
- **对外回执**：要求 esim42 修正 `01` §6.5 D2 的标量 `max_saip_version` 表述为列表 `allowed_saip_versions` —— 该修正**已在 esim42 第三轮文档中完成**（`01` §6.5 D2 现写列表，`06` §13.1 R1 一致），本条关闭。

---

## 11. 待确认事项（rsp42 → esim42）

> 来自 esim42 `02` §10 的待确认项；均**不阻塞**。**四项均已写入 `docs/interfaces.md` 并固定下来**（下表右列），esim42 可直接按其消费。

| # | 问题 | rsp42 侧结论 | 已写入 |
|---|---|---|---|
| 1 | `GET /profiles` 的 `iccid` 过滤是前缀还是精确匹配 | **前缀**匹配（精确查用 `GET /profiles/{iccid}`） | `docs/interfaces.md`「Tenant scoping and filters」 |
| 2 | `POST /tenants` 是否可重复调用（首次部署全量同步） | 是 **create-or-replace**，可重复调用 | 同上 |
| 3 | platform default tenant（`tenant=""` / `tenant_id IS NULL`）的语义 | 是**真实的属主**（平台自营资源与 `promote` 后的全局模板所在），不是“未归属”桶 | 同上 |
| 4 | `usage.personalization` 与 esim42 `credential_assignments` 不一一对应 | `usage` **只统计 rsp42 自己的表**；删除租户前须把 `usage` 与本侧凭据分配表**并行**计入 | `docs/interfaces.md`「Tenant scoping and filters」 |

---

## 12. 标准一致性修订（第四轮：以 SGP.22 为准）

> 来源：以 refs 下的 SGP.22 v2.7、SAIP V2.3.1 与 pySim/lpac/YggdraSIM 做的一次全面交叉测试（见 §12.3 的发现）。
> **原则**：esim42 的契约与标准冲突时，**一律以标准为准**——rsp42 按标准实现，esim42 按 §12.2 修正其契约。
> 下表全部**已落地**并有定向测试。

### 12.1 rsp42 侧的修订

| # | 问题（修订前） | 标准依据 | 修订后行为 |
|---|---|---|---|
| F1 | 文档称未映射 requester「在审计记 `unmapped`」，实际只有日志；esim42 计划据此做健康检查，却无数据源 | —（可观测性承诺） | 未映射回落平台默认时：审计行带 `detail.warning=unmapped` + `detail.requester`，并计数 `rsp42_es2p_tenant_unmapped_total`。`requester_tenants` 为空时不告警（单租户部署无可映射项） |
| F2 | `/audit` 的 `function` 对 ES2+ 记录**完整路径**（`/gsma/rsp2/es2plus/downloadOrder`），`?function=downloadOrder` 匹配不到 | —（契约一致性） | `function` 归一化为函数名（`downloadOrder`）；ASN.1 binding 的单一 `/gsma/rsp2/asn1` 路径由 handler 按解码出的函数名显式设置；管理 API 保持路径 |
| F3 | esim42 文档引用的 `rsp42_downloads_total` 在生产代码中**从不写入**（只在 metrics 单测里出现）；真实计数器是 `rsp42_progress_notifications_total{tenant,point,status}` | —（契约一致性） | 计数器改名为 **`rsp42_downloads_total{tenant,point,status}`**（每产生一条进度通知计一次；重试不重复计数），esim42 的看板名因此可直接命中 |
| F4 | `cancelOrder` 要求标准强制字段 `finalProfileStatusIndicator`，但**缺失与非法都返回 `8.2.1/1.2`**；且不校验“订单是否已下载”、不校验 matchingId/eid 归属、**不删除已登记的 ES12 事件** | Table 28（字段 M）、Table 30（各失败码）、§5.3.3（三项校验 + 事件删除 SHALL） | 缺失 → `8.1.1/2.2`；非法 → `8.1/1.2`；已下载 → `8.2.1/3.3`；matchingId 不符 → `8.2.6/3.10`；eid 不符 → `8.2.1/3.10`；成功后删除该订单的 SM-DS 事件（删除失败不回滚取消，记日志并计入 `rsp42_es12_register_failures_total`） |
| F5 | `profileType` 选择器**无法表达平台默认租户**：`"/<template>"` 被判 `malformed`，因此无法按名选择全局（`promote` 后）模板 | §6.5.2.1（`profileType` 由 Operator 自由定义） | 允许**空前缀** `"/<template>"` 选择平台默认租户（全局）模板；名称仍按调用方作用域解析（自有或全局）。`"/"` 仍为 `8.2.5/3.9`，他人租户前缀仍为 `8.2.5/1.2` |
| F6 | 复用已存在的 `matchingId` 时把**原始 SQLite 错误**（`UNIQUE constraint failed: profiles.matching_id (2067)`）当 `8.2/4.2` 返回，泄漏存储层细节 | Table 27：`8.2.6/3.3` Matching ID — Already in Use (Uniqueness)；§4.1.1（matchingId 字符集） | 唯一索引冲突 → **`8.2.6/3.3`** 且只返回可读 message（不泄漏存储层错误）；`matchingId` 字符集（大写字母/数字/`-`）非法 → `8.1/1.2`；此外按 Table 27，带 `smdsAddress` 时缺 EID → `8.1.1/2.2` |
| F7 | esim42 文档把 `smdpAddress` 列为 `downloadOrder` 的成功响应字段 | Table 23（DownloadOrder 输出**只有 `iccid`**）；`smdpAddress` 是 Table 26 的 ConfirmOrder 可选输出 | rsp42 **不改**（只返回 `iccid`）；已写入 `docs/interfaces.md`，esim42 需修正文档 |
| F8 | 用**不同 `matchingId`** 重发 `confirmOrder` 时，旧 MatchingID 下的 SM-DS 事件登记**不被删除**：同一 ICCID 出现两条事件，而 Profile 只认新 ID（旧激活码可被发现但必定认证失败） | §3.6（事件登记以 MatchingID 为键）、Table 27 的重发 NOTE（重发不应产生额外动作） | 检测到 MatchingID 变更时先 `Registrar.DeleteEvent` 删除旧登记，再按 `smdsAddress` 登记新事件；同一 MatchingID 重发为幂等（不再向 SM-DS 重复登记，避免 `8.9.5/3.3` 被记成注册失败）。**ACR-0 轮换同样被覆盖**：CMAE 新增 `MatchingIDChanged` 钩子，轮换后删除旧登记（新激活码直接交付，不再登记新事件）。实测：`Installed` 且保留事件时执行 `ACR-0-<ICCID>` → `matchingId` 轮换为新 token、`/events` 归零 |
| F9 | `internal/cli/smdpp.go` 构造 `es2plus.Deps` 时**没有注入 `Metrics`**，导致 `rsp42_es2p_tenant_unmapped_total`、`rsp42_es2p_profile_type_unparsed_total`、`rsp42_es12_register_failures_total` **只有 HELP/TYPE、没有取值**（F1 承诺的指标那一半实际不生效） | —（装配缺陷） | 注入 `Metrics: reg`；三个计数器实测开始上报（未映射 requester → `rsp42_es2p_tenant_unmapped_total 1`；opaque `profileType` → `rsp42_es2p_profile_type_unparsed_total{tenant=…} 1`；映射正常的 requester 不计数） |
| F10 | `smdpp.es12.delete_on_install` **只被解析、从未被读取**：安装成功路径无条件删除 SM-DS 事件，配置项形同虚设（文档与示例却把它当成可选项） | §3.6（事件在安装后不再需要，删除是常规行为） | 安装路径改为受 `NotificationDeps.KeepEventOnInstall` 控制（字段取反，零值 = 删除，保持既有/规范默认），CLI 用 `!cfg.SMDpp.ES12.DeleteOnInstall` 注入。实测 `delete_on_install: false` 时事件在安装后保留，随后由 ACR-0 钩子在轮换时清理；`true`（默认）时安装即删除 |

### 12.2 esim42 必须同步修正的契约（对外回执）

1. **`cancelOrder` 必须带 `finalProfileStatusIndicator`**（`Available`/`Unavailable`）——标准 Table 28 为 **M**。esim42 `02` §2.1 目前写作 `{iccid, eid?}`，按此调用会得到 `8.1.1/2.2`。管理 API `POST /profiles/{iccid}/cancel` 不受影响。
2. **`matchingId` 字符集**：只允许大写字母、数字与 `-`（§4.1.1），且**全局唯一**（`profiles.matching_id` 唯一，不按租户）。esim42 生成的可追溯 ID 需满足（ULID 满足）；与既有订单撞号会得到 `8.2.6/3.3`。
3. **`downloadOrder` 响应只有 `iccid`**；不要把 `smdpAddress` 当必填（它属于 `confirmOrder` 的可选输出）。`profileType` 选择全局模板要用 `"/<template>"` 形式。
4. **指标名以 `rsp42_downloads_total{tenant,point,status}` 为准**（不再有 `rsp42_progress_notifications_total`）；完整指标词表见 `docs/interfaces.md`「Metrics」。
5. **`/audit` 的 `function` 是函数名**（不是路径），`groupBy=function` 亦按函数名聚合；未映射租户的行带 `detail.warning=unmapped`。
6. **`confirmOrder` 重发不要换 `matchingId`**：同一订单换 ID 会（正确地）删除旧事件并登记新事件；若只是想重试，请复用同一个 `matchingId`（幂等，不会重复登记）。

### 12.3 本轮交叉测试的发现来源（证据）

| 证据 | 结论 |
|---|---|
| 18 个 TS.48 向量 → `POST /upp/validate` | 18/18 `valid:true`、0 errors；合成违例（版本/无 end/坏 SFI/改文件类型）全部按预期拒绝 |
| Annex A 表 vs pySim 转写（573 条）+ V2.3.1 PDF 复核 | 61 处差异**全部**是 pySim(V3.3.1) 缺陷或 V2→V3 变更；rsp42 表在 V2.3.1 基线上逐条正确 |
| lpac × YggdraSIM 端到端 + pySim BPP 校验 | `Released → Downloaded → Installed`；BPP MAC/解密通过；**R2**（BF26 用 `04` 而非 `80/81/82`）与 **R3**（ASN.1 binding 响应单层 `BF39`）复现 |
| SGP.22 v2.7 原文（Table 23/26/27/28/29/30、§4.1.1、§5.3.3） | 上述 F4/F6/F7 的标准依据 |
| 隔离环境复跑（全新 DB + 独立 YggdraSIM 状态）后的实测 | F1（审计 detail + 计数器）、F2（`?function=` 命中）、F3（`rsp42_downloads_total` 取值）、F4/F5/F6（各状态码）、F8（换 ID 后仅剩一条事件、同 ID 重发不重复登记、**ACR-0 轮换后事件归零**）、F9（三个 ES2+ 计数器开始上报）、F10（`delete_on_install: false` 保留事件 / 默认删除）全部通过；端到端 `Released → Downloaded → Installed` 回归通过 |

---

## 13. 第五轮：esim42 `todo/06` §"待裁决"的裁决与落地

> 来源：esim42 `todo/06` 的 Q1–Q7（该节标题写"四个"、表格实有 7 行，编号亦乱序）。
> 基线：rsp42 `ec29b86`。判定原则与前几轮一致：**以 SGP.22 为准**；多租户隔离是
> rsp42 自己的承诺，按 `docs/interfaces.md`「Tenant attribution」执行。
> 结论中 **Q1/Q2/Q3/Q4/Q6/Q7 由 rsp42 修**，**Q5 属 esim42 建模**（rsp42 无需改）。

| # | 现象（esim42 侧描述） | rsp42 判定 | 处置 | 标准依据 / 证据 |
|---|---|---|---|---|
| **Q7** | `downloadOrder` 用他人租户的池中 ICCID 会被接受 | **Bug（多租户隔离）** | `Inventory.Allocate` 的显式 ICCID 路径改为查 `PoolRepo.Get` 并校验池条目归属；不一致 → `8.2.1/3.3`，池条目的 `tenant_id`／状态不变 | SGP.22 对多租户无定义，这是本仓库 `interfaces.md`「Tenant attribution」与 `../esim42/todo/02` §2.3/§9 A23 的承诺；`PoolRepo.Claim` 只写 `profile_id`，原先会把 A 的号记到 B 的 profile 上 |
| **Q1** | 取消后的 ICCID 在删除 profile 行前无法再次下发 | **Bug（规范一致性）** | 新增 `reusable`/`reallocate`：`Available` 行原地复用（保持 ICCID/IMSI/个性化，改写 eid/profileType/template/externalRef，清空 matchingId/CC/SM-DS/errorReason）；判定条件为 **同租户 + `DownloadAttempts==0` + `InstalledAt==nil`**。附带修复池路径：撞唯一键时不再静默生成池外 ICCID，不可复用 → `8.2.5/3.7` 并交还预约 | Table 29：`Available` = "released back to the inventory and **available for future use**"；状态图 `Available --> Allocated/Linked : ES2+.DownloadOrder`。非复用状态仍 `8.2.1/3.3` |
| **Q2** | `DELETE /tenants/{id}?force=true&reassignTo=` 的唯一键冲突是裸 500 | **Bug（可运维性）** | `DeleteWithReassign` 逐表 SAVEPOINT 探测，按驱动码 `IsUniqueViolation` 收集冲突表并整体回滚；handler 映射 `409 conflict` + `details{reason:reassign_conflict,tables:[...]}` | 冲突索引实际有 **3** 个：`idx_profiles_extref`、**`idx_upp_tenant_name`（esim42 未列，且"两租户都有 default"是常态）**、`idx_perso_tenant_imsi` |
| **Q3** | `iccid_ranges` 不在 `tenantScopedTables` | **Bug（数据完整性）** | 集合加入 `iccid_ranges`；`TenantUsage` 增 `ranges`（`usage.Empty()` 一并计入，否则"只有号段的租户"会在不带 force 的删除下留下悬挂行）；OpenAPI `TenantUsage` 同步 | 号段是租户资源，reassign 后新属主 `GET /iccid-ranges?tenant=` 必须看得到 |
| **Q4** | 重复 IMSI 是裸 500，而 esim42 把 `internal_error` 标为可重试 | **Bug（错误语义）** | `upsertPersonalization` 的 INSERT/UPDATE 唯一键冲突 → `store.ErrConflict`；`PUT /personalization/{iccid}` → `409 conflict` + `details.reason=credential_conflict`；`POST /personalization/import` 改为 per-record `results[]`，一条重复不再废掉整批 | 裸 500 让调用方对**不可能成功**的写入做无意义重试；具名/派生 409 可直接判别 |
| **Q6** | 激活码里的 SM-DP+ 地址（`confirmOrder.smdpAddress` 恒为空串） | **疏漏（3 行）** | `es2plus.Deps` 增 `FQDN`，`confirmOrder` 回填 `smdpp.fqdn`（配置必填，见 `config/validate.go`）；为空时**省略**该字段而非发空串 | Table 26：`smdpAddress` 为 **O**（可选），语义是"本次下载应使用的 SM-DP+ 地址"；本机 `GET /profiles/{iccid}/activationCode` 早已用同一 FQDN 生成完整激活码（含 OID/CC） |
| **Q5** | 全局模板的 claim 无归属运营商（`claims.carrier_id NOT NULL`） | **非 rsp42 问题** | rsp42 无需改：`resolveProfileType` 对 `"/<template>"` 按**调用方作用域**解析（`GetForTenant`），不要求 tenant 为 `""` | esim42 侧建议 seed 保留的 `platform` 运营商；rsp42 侧 profile 的租户仍由 ES2+ requester 映射决定，故平台 claim 若要落到 `""` 需给 esim42 增一个映射到 `""` 的 requester（该决定在 esim42） |

**给 esim42 的对外回执（本轮变更）**：

1. 契约锁需重跑一次：`openapi.json` 的 `TenantUsage` 增了 `ranges`（`components.schemas` 变化），
   `DELETE /tenants/{id}` 的 409 与 `PUT /personalization/{iccid}` 的 409 文档化（`paths` 变化）。
   流程：替换 `packages/rsp-client/src/openapi.snapshot.json` → `pnpm --filter @esim42/rsp-client generate`
   → 更新 `openapi.snapshot.meta.json` 的 `commit`/`digest` → `pnpm rsp:contract` 四项全绿。
   **本轮实测**（`RSP42_OPENAPI=../rsp42/internal/api/openapi/openapi.json pnpm rsp:contract`）：
   仅 `live-match` 漂移，`snapshot-structure`/`types-current` 不漂移，即"只差一次刻意重基线"。
   新 digest = `b2a36175f37d9be80c1c60c091ed3595d9a1f7c2cc3680566e9778edc8a7df95`
   （旧 = `b0ff2e11e89315a003be6f9463d3fb8c26b7a24b23650fdaa1aae1caf1ef3499`，`info.version` 仍 `0.2.0`，
   再次印证 `info.version` 不是变更信号）。
2. 无新增**具名**错误码：两处新语义都用**派生码 `conflict` + `details.reason`**，
   所以 esim42 的 `ADMIN_CODE_MAP` 不需要加条目（esim42 对未登记的 code 会记为
   `unknownCode` 契约漂移告警，这是刻意避开的）。
3. 8.2.1/3.3、8.2.5/3.7 的语义有扩展（见上表 Q1/Q7），esim42 的
   `ES2P_ERROR_MAP` 现有条目（`iccid_unusable`、`quota_or_pool_exhausted`）**不需要改**。
4. `confirmOrder` 现在返回 `smdpAddress`：esim42 可以直接用它拼激活码；
   更完整的形态仍是 rsp42 的 `GET /profiles/{iccid}/activationCode`（带 OID 与 CC 位）。
   **调研（能否删掉 `rsp.smdp_address` 兜底，仅结论不落地）**：
   - 现在可以删。esim42 里该设置只有一处消费者（`claims/routes.ts` 的前置检查 → `template.smdpAddress`），
     而 `orchestrator` 已经是"confirmOrder 的 `smdpAddress` 优先、设置兜底"。
   - 但**不能只删设置**：前置检查同时也是"没地址就不消耗 ICCID"的 fail-fast。删掉它必须补一个
     **confirmOrder 之后**的检查——地址仍为空则回滚（`cancelOrder {Available}`）并以不可重试码失败，
     否则会重现 M3 首轮那种 `state=issued` 但 `activationCode=null` 的残单。
   - 这条运行时检查是必要的，因为 **契约锁覆盖不到它**：锁定的是 rsp42 的管理 OpenAPI
     （`openapi`/`paths`/`components.schemas`），ES2+ 不在其中，所以"某个 rsp42 版本不回
     `smdpAddress`"在 CI 上不可见。
   - 建议形态：删前置检查，把 `rsp.smdp_address` 降级为**可选覆盖/对账项**（设了就以它为准并比对
     rsp42 的返回值，不一致就告警），或直接改用 `GET /profiles/{iccid}/activationCode`。
     完全删设置也可行，代价是失去"对外发布的 FQDN 与 `smdpp.fqdn` 不同"这一合法场景的旋钮。
5. Q1 修好后，esim42 编排里"cancel 后补一发 `DELETE /profiles/{iccid}`"的权宜可以删除；
   A17 的原意（取消的 Profile 的 ICCID 可被再次领取）现在由 rsp42 原生保证。

**本轮验证**（`go build ./... && go vet ./... && go test ./... -count=1`、`gofmt -l cmd internal` 为空）：

| 面 | 新增/扩展的测试 |
|---|---|
| service（DIP 伪造实现） | `TestInventoryExplicitICCIDObeysPoolTenant`（Q7/blocked）、`TestInventoryReallocatesCancelledProfile`（Q1 正/反例 + 他租户） |
| store | `TestDeleteWithReassignReportsUniqueConflicts`（profiles/upp_templates 两类冲突 + 回滚断言）、`TestUsageCountsImportedRanges`（无池条目仍阻塞删除、范围随 reassign 迁移）、`TestPersonalizationDuplicateIMSIIsConflict`（insert 与 update 两条路径、跨租户不冲突） |
| ES2+（真实 SQLite + 真 handler） | `TestDownloadOrderRejectsForeignPooledICCID`（Q7：8.2.1/3.3 + 池条目未改属 + 无 profile 行）、`TestDownloadOrderReusesCancelledICCID`（Q1：同一行、MatchingID 清空、可再次换 EID）、`TestDownloadOrderDoesNotReuseDownloadedProfile`、`TestPooledAllocationReusesCancelledICCID`、`TestPooledAllocationDoesNotMintOutsideThePool`（8.2.5/3.7 + 预约交还 + 不生成池外号）、`TestConfirmOrderReturnsSMDPAddress`（Q6） |
| Admin API | `TestAdminTenantReassignConflict`（409 + `details.tables`，profiles 与 upp_templates 各一）、`TestAdminTenantReassignMigratesRanges`（Q3：usage/阻塞/迁移/可见性）、`TestAdminPersonalizationDuplicateIMSIIsConflict`（Q4：409 + per-record 批量结果） |

**顺带修正的测试夹具缺陷**：`internal/api/es2plus` 的 `newServerWith` 没有把
`st.Pool` 注入 `OrderService`，与生产装配（`internal/cli/smdpp_graph.go`）不一致，
导致"取消订单归还池条目"在测试里从未发生。已按生产装配补齐。

---

## 附：第三轮复核的方法与边界

- **判定基线**：本仓库 `89308b2`；逐条对照 `internal/store/migrations/`、`internal/api/openapi/openapi.json`、`internal/rsp/status/status.go`、`config/config.example.yaml` 与相关测试。
- **输入边界**：仅 `../esim42/todo/01`–`06`；`../esim42/todo/research/` 未纳入本文（按约定）。todo 文档内的 research 引用仅作为 esim42 侧的证据指针，本文不复制其内容。
- **上一版“改造前快照”附录已删除**：第一轮 G 的改造前判定已不再有运维价值，历史见 git；当前状态以 §9/§9.4 为唯一准。
- **本文与 `TODO.md` 的分工**：`TODO.md` 只记录未完成工作，其 §2bis 索引指向本文 §0.3、§9.4、§10；本文是 N 清单与决策的权威出处。
