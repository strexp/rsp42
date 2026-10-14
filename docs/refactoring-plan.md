# 重构计划（SOLID 符合性与目录内聚性）

> 状态：**执行中**。阶段 0–2 已完成，阶段 3 部分完成（见文末「执行记录」）。
> 最后更新：2026-10-14

> 语言约定：与 `TODO.md` 一致，工作/计划类文档使用中文；代码、注释与权威文档
> （`README.md`、`docs/architecture.md`、`docs/interfaces.md` 等）保持英文。
> 本文件的结论若被采纳为权威架构约束，应翻译并合入 `docs/architecture.md`。

## 0. 结论摘要

架构骨架健康：包依赖无环，分层方向基本正确（`cmd → cli → api/service →
{rsp,saip,crypto,cert,kms,store,config}`），`service` 有明确的「消费方定义接口」
意图，数据库用 goose 迁移，无全局可变状态，构建/静态检查/测试全绿。

主要问题集中在两处：**文件级职责内聚**与**依赖倒置收口**。

| 原则 | 评级 | 判断 |
|---|---|---|
| SRP | 偏弱 | 包级内聚尚可，文件级存在大量「上帝文件/混合文件」：组合根、admin、store、cli、saip、cert 各有 3–8 个职责挤在同一文件或同一类型 |
| OCP | 偏弱 | 同一份协议错误码表、路由表、配置默认值、CLI 子命令在 2–3 处平行维护；新增一个 PE/消息/状态码要改多处 |
| LSP | **有真实缺陷** | `OrderService.Transition` 幂等分支吞掉 `mutate`；`Inventory.claim` 吞错；nil 依赖语义不一致；同一领域规则在 ES2+/admin 下语义不同 |
| ISP | 偏弱 | 「构造后字段注入」普遍（跨结构体 68 个导出可变字段）；`ES12Config` 把客户端/服务端字段塞进同一结构；`kms.Provider` 职责捆绑 |
| DIP | 偏弱 | `service`/`api`/`audit`/`api/middleware` 大量依赖 `*store.XxxRepo` 具体类型，与 `docs/architecture.md` 的声明相反；`store → rsp`、`config → rsp` 方向倒挂 |

另有一个**可由配置触发的启动期 panic**（`validateOID` → `asn1.EncodeOID`）和一处
**审计归属恒为空**的中间件顺序缺陷，两者都应最先修。

## 1. 评估方法与基线

- 走查范围：`cmd/rsp42` 与 `internal/**` 全部非测试 Go 文件（22 个包，约 2.9 万行含测试），
  外加 `Makefile`、`Dockerfile`、`config/*.yaml`、`deploy/`、`scripts/`、`.golangci.yml`。
- 基线（本次验证，全绿）：
  - `go build ./...`、`go vet ./...` 通过；
  - `go test ./...` 全部包通过；
  - 包依赖边通过 `go list -f '{{join .Imports "\n"}}'` 提取，无环。
- 统计口径：同名跨包函数扫描、`*_test.go` 之外的调用点计数、导出符号调用点计数。
- 只读分析，未修改任何文件。

## 2. SOLID 逐项发现

### 2.1 SRP — 职责混合

| 位置 | 问题 | 证据 |
|---|---|---|
| `internal/cli/smdpp.go:31` | `cmdSMDpp` 单函数 207 行：解析 flag、加载配置、建日志、装证书/KMS、开库、装配 8 个服务、写 3 个 repo 查询闭包、25 行 GC 闭包（含内联 audit INSERT）、定义指标词表、构造 collectors、装审计中间件、起 3 个 listener | `smdpp.go:65-78`、`87-112`、`260-305` |
| `internal/api/admin/admin.go:31` | `admin.Handler` 是 20 个导出字段、12 个 `*store.*Repo` 的上帝结构体 | `admin.go:33-49` |
| `internal/api/es2plus/` | 一个包同时承担 4 种角色：入站服务端（`handlers.go`）、出站回调客户端（`client.go`）、运营商客户端库（`clientlib.go`）、持久化重试队列（`callback.go`） | 包内文件划分 |
| `internal/cli/server.go` | 一个文件 5 件事：listener+TLS、周期 ticker、HTTP client、KMS/证书加载、serve/shutdown | `server.go:35-221` |
| `internal/store/store.go` | 文件名叫 `store.go`，内容却是哨兵错误 + SQL 时间/NULL 转换 helper；真正的 `Store` 在 `sqlite.go:20` | 文件名与内容不符 |
| `internal/store/models.go` | 一个文件装 3 个聚合：Profile 状态枚举、Profile、EventRecord、Notification | `models.go:6-91` |
| `internal/saip/header.go` | 一个文件混合：Header 模型+解析、ICCID、service 位图、mandatory services 重算、GFSTE 重算、service 名表、PE 名表、AKA 辅助 | 359 行 8 个职责 |
| `internal/api/admin/upp_tools.go:39` | HTTP handler 与领域字段目录（`personalizationSchema`/`Targets`/`annotateSchema`）混在一个文件 | `upp_tools.go:39-130` |
| `internal/api/common/status.go` | 同一文件既是包 doc，又是 JSON binding DTO，又是写响应 helper，又是 request-id ctx key，又是 media type 解析 | 全文 |
| `internal/cert/manager.go:101` | `loadIdentity` 110 行：路径拼装 + PEM/DER 回退 + 6 段近乎相同的 load+validate 块 + KMS 签名者加载；整个 `Manager` 有 39 个函数 | `manager.go:101-211`、`246-351`、`442-515` |
| `internal/saip/personalization/personalization.go:114` | `Engine.Apply` 是 93 行 if 链，执行 12 组独立注入 + header 重建；同文件还含 AKA/PIN/PLMN/MSISDN/SdKey 值编码器与 BCD helper（639 行） | `personalization.go:114-228` |
| `internal/crypto/bpp.go:22` | ECDH/EC-point/随机密钥材料与 `ProtectBPP` 编排同文件，且与 `crypto/ecdsa.go:56-70` 功能重叠 | `bpp.go:22-53` |

### 2.2 OCP — 变体需要改多处

- **协议错误码表两份平行维护**：`internal/api/es9plus/asn1.go:141` 与
  `internal/api/es11/asn1.go:72` 各自一套 `initiateErrorCode`/`authenticateErrorCode`…，
  各自一份 `subjectCode`。新增一个 RSP 状态码要改两处，漏改则静默落到 `127 undefinedError`。
- **同一 CHOICE 遍历复制 4 份**：`rsp/types.go:361`、`rsp/types.go:419`、`rsp/cancel.go:34`、
  `rsp/signing.go:23` 各写一遍「A0 ok / A1 error + INTEGER code」的遍历，约 117 行。
- **ES2+ 请求头提取用类型 switch**：`api/es2plus/handlers.go:422` 对 4 个具体请求类型做
  type-switch 取 `Header`，而通用载体 `common.HeaderRequest`（`api/common/status.go:29`）已存在却无人使用。
- **admin 状态码 taxonomy 硬编码**：`api/admin/admin.go:199` 的 `errCode` switch，加上散落各处的
  自定义 code（`admin.go:398`、`admin.go:402`、`ds.go:167`、`callbacks.go:97`）。
- **CLI 无命令注册表**：新增子命令要同时改 `cli/cli.go` 的 switch、手写 usage、新增文件；
  `--config` 默认值重复 10 次，`--db` 帮助重复 4 次；usage 已与实际 flag 漂移
  （`cli/admin.go:63` 漏 iccid 的 `--note/--state/--tenant/--limit`）。
- **配置默认值三处编码**：Go struct、`config/config.go:321-366` 的 45 行 `SetDefault`、
  `config/config.example.yaml`。
- **SAIP 版本写进标识符**：`saip/templates.go:27`（`V231Templates`）、`saip/validate.go:54`
  （`ValidateV231`）、`saip/header.go:99`（`svcMax`）、`rsp/types.go:180`（`IsV3Capable`）；
  V3.2 的排除规则写在注释里而非数据。
- **一个 PE 最多要改 6 处**：`saip/element.go:10-46`（tag 表、fileBearing 表）、
  `saip/header.go:178-182`（templatePETags）、`:252-267`（serviceNames）、`:302-310`（peNames）、
  `saip/validate.go:23-50`（singleton/ordering/non-baseline）、`saip/templates.go:27-42`。
  例：`TagIoT` 出现在 `element.go:37`、`element.go:45`、`header.go:181`、`header.go:309`。

### 2.3 LSP — 契约缺陷（必须修）

| 严重度 | 位置 | 问题 |
|---|---|---|
| **高** | `service/order.go:92` | `if p.State == to { return p, nil }` 在 `mutate` 之前返回：对已是 `Error` 的 profile 调 `MarkError` 不会写入 `ErrorReason`；对已 `Installed` 调 `MarkInstalled` 不写 `InstalledAt`。调用方无法区分「已应用」与「无操作」。 |
| **高** | `api/middleware/middleware.go:170` + `api/router.go:33` + `cli/smdpp.go:189` | `Audit` 包在 chi router 外面，`RequestScope` 在 router 里面用 `r.WithContext` 生成新 request，导致 `common.ScopeFrom(r.Context())` 在 `Audit` 中恒为 nil → **通用审计行的 Actor/TenantID 恒为空**（handler 级 audit 正常）。 |
| **高** | `service/inventory.go:216` | `claim()` 丢弃 `Pool.Claim` 的错误；失败后 `reserved_until` 仍在，`ReleaseExpired` 会把该 ICCID 置回 `available`，而 profiles 表仍引用它 → 池子开始发永远建不出来的 ICCID。 |
| 中 | `cli/smds.go:76` | SM-DS 会话 TTL 读的是 **SM-DP+** 配置 `cfg.SMDpp.SessionTTL`；`SMDSConfig` 没有 `session_ttl` 字段，配置项被静默忽略，调 DP 会连带改 DS。 |
| 中 | `service/session.go:27` | `Put` 原地修改入参，把明文列替换成密文；同一结构体再次 `Put` 会二次加密，契约未文档化。 |
| 中 | `api/es2plus/handlers.go:307` | ACR 不可用时返回纯文本 501，其余 ES2+ 失败都走 SGP.22 JSON 信封；`middleware.Recover` 的 500 同样是纯文本。 |
| 中 | `service/smds_event.go:98` | `Delete` 把**所有** `GetByKey` 错误（含 DB 故障）映射为 `ErrEventNotFound`，存储故障被报成 404 语义。 |
| 中 | `service/helpers.go:40` | `mustHexLower` 对请求派生的 transactionId 会 panic。 |
| 中 | `store/events.go:76` | 用错误字符串匹配判定唯一冲突，且手写 `contains`/`indexOf` 重新实现 `strings.Contains`；措辞一变，SGP.22「EventID 不可复用」规则就静默失效。 |
| 中 | `rsp/cancel.go:107` | `CancelSessionResponseFromTLV` 失败返回 `-1`，同族 `DecodeCancelSessionResponse` 返回 `(nil, 0, err)`；同一包两种失败契约。 |
| 中 | `asn1/tlv.go:71`、`:83`、`:98`、`node.go:73` | `Find`/`FindAll`/`First` 吞掉 `Children()` 的解析错误 →「字段不存在」与「字段畸形」不可区分；上层 `rsp/bpp.go:71` `groupSegments`、`rsp/types.go:189` `octetList` 因此把畸形分组当空处理。 |
| 中 | 错误词汇表 | ES9+/ES11 映射器只识别 `*rsp.StatusCode`（`api/es9plus/asn1.go:133`）；`*cert.ValidationError`、`*crypto.ErrBadSignature`、`*cmError` 及 `internal/rsp` 内大量未类型化 `fmt.Errorf` 一律降级为 `127 undefinedError`。 |
| 低 | `rsp/download.go:28` | `InitialiseSecureChannelRequest.Encode()` 内部改写 `r.RemoteOpID`（0→1）；编码两次结果依赖调用顺序，`Encode` 不幂等。 |

### 2.4 ISP — 接口过肥

- **`ES12Config` 把两个角色塞进一个结构**：`config/config.go:99` 同时含客户端字段
  （`smds_address`/`forwarding_indicator`/`delete_on_install`）与服务端字段
  （`requester_tenants`），却被 `SMDpp.ES12` 与 `SMDS.ES12` 同时使用 → 每个角色都看到一半无意义字段。
- **构造后字段注入普遍**：跨主要结构体统计到 68 个导出可变字段
  （admin 20 / CMAE 14 / es2plus 12 / notification 8 / ds 5 / es12 4 / es9plus 3 / es11 2）。
  `NewCMAE` 有 11 个位置参数，之后还要再设 8 个字段（`cli/smdpp.go:119-140`）；
  于是到处是 `if h.Audit == nil`、`if h.Tenants != nil` 判空，且语义不统一
  （有的返回 501，有的静默跳过）。`es12.Handler.eventMeta` 更是直接解引用 `h.Tenants` 无判空。
- **`ProfileStore` 5 方法捆绑**：`service/interfaces.go:11` 的 5 个方法被三类消费者各取不相交子集；
  `service/fakes_test.go` 里一个胖 fake 必须实现全部 5 个。
- **DB-only 命令要求全量配置**：`cli/admin_iccid.go:29`、`cli/admin_upp.go:25` 等用
  `RoleDP`/`RolePreflight` 校验，于是 `admin iccid list` 要求 `smdpp.fqdn/oid`、合法 `host_id`、
  所有证书与 KEK 在位 → 纯 SM-DS 主机跑不了自己的池工具。
- **`kms.Provider` 职责捆绑**：`kms/kms.go:8` 把「按路径加载签名者」与「KEK 加密」绑在一起，
  未来 HSM/vault provider 无法实现 `LoadSigner(path)`。
- **`asn1` 类型别名外泄**：`asn1/construct.go:24`（`type Tag = bertlv.Tag`）、`:32`
  （`type Builder = bertlv.TLV`）、`:62-75`（`App`/`Ctx` 返回 `bertlv.Tag`），与
  `asn1/doc.go:6` 声称的「外部调用者无需接触 bertlv」不符——每个签名都携带 bertlv 类型。

### 2.5 DIP — 依赖倒置未收口

`docs/architecture.md` 声明 `api/es2plus` 依赖 `service.ProfileStore`/`OrderAuditor` 而非 `store`，
但实际相反：

- 直接 import `internal/store` 具体类型：`api/admin/admin.go:33-49`（12 个 repo）、
  `api/es12/handlers.go:31`、`api/es2plus/handlers.go:37`、`api/es2plus/callback.go:12`、
  `api/middleware/idempotency.go:36`、`audit/audit.go:36`。
- `service` 自身也在漏：`service/upp.go:37`
  `ImportUPPTemplates(dir string, repo *store.UPPRepo, …)`；`CMAE`/`DSService`/`NotificationService`
  持有具体 `*cert.Manager`、`*SessionService`、`*OrderService`、`*store.AuditRepo`。
- **方向倒挂（分层污染）**：`store/pool.go:11` 与 `store/upp.go:9` 让持久层 import 领域编解码包
  `internal/rsp`（为了 `rsp.LuhnValid` 与 `rsp.Version`）；`config/validate.go:11` 让 `config` 依赖
  `rsp`。架构文档声明的 DAG 中没有这两条边。
- `cli` 直接 import `rsp` 与 `saip/personalization`（`cli/smdpp.go:25`、`:26`），把协议→领域翻译
  放在组合根；组合根还在闭包里做数据访问（`cli/smdpp.go:65-78`）。
- `cert` 依赖 `config`（`cert/config.go:7`、`:13`、`:21`），方向与文档不一致。
- 测试专用工具进入生产二进制：`cli/admin_ops.go:12` import `internal/api/mock` 以实现
  `admin mock-operator`；`internal/api/mock` 未出现在架构文档的包图中。

### 2.6 编解码 / 领域层专项

#### 结论澄清（重要，避免错误重构方向）

1. **不存在 2–3 套 TLV 编解码器，也不要引入生成式依赖**。全仓唯一底层是
   `internal/asn1`；`bertlv` 仅被 `asn1/construct.go:7` 与 `tools.go` 引用；
   `api/es9plus|es11/asn1.go` 只是 HTTP 绑定分发器，全部 decode 委托 `internal/rsp`；
   `api/es2plus` 是纯 JSON。真正的重复在**消息结构层**与少量手写工具函数。

2. **`bertlv` 不能替代 `internal/asn1`**，有 4 条硬约束（已核对库源码）：
   - 长度字段是 `uint16`（`bertlv/length.go:19`），>64 KiB 的 BPP/UPP 外层 TLV 无法表示；
     `asn1.EncodeLength`（`asn1/tlv.go:168`）支持 4 字节。
   - 不保留原始字节（`Bytes()` 重新编码），SGP.22 验签所需的精确字节切片会丢失。
   - `bertlv.NewTag`（`tag.go:12-25`）在 `bits.Len64(value)%7==0` 时产生非最小编码：
     tag 73 编成 `5F 80 49` 而非 `5F 49`，会破坏 OTPk `App(73)`——这正是
     `asn1/construct.go:44` 注释记录并自行实现 `encodeTag` 的原因。
   - `WriteTo` 拒绝 constructed-with-value / primitive-with-children。
   与 `docs/dependencies.md`「RSP/SAIP 编解码手写」的政策一致。

3. **ICCID/BCD 重复的方向**：`rsp/encoding.go` 中除 `LuhnValid`、`LuhnCheckDigit`、`EIDBytes`
   外的 9 个函数**无生产调用方**；存活的 ICCID 实现在 `saip/personalization`
   （`personalization.go:120`、`:126`，被 `service/download.go:191` 调用）。
   → 目标不是「二选一合并」，而是抽叶子包（见下）。

#### 新增问题

| 严重度 | 位置 | 原则 | 证据 | 修法 |
|---|---|---|---|---|
| **高** | `config/validate.go:306` → `asn1/oid.go:12` | 健壮性/契约 | `validateOID` 只校验「非空 + 全数字」，接受 `"2"`、`"9.1.2"` 这类非法 OID；`EncodeOID` 在 `len(parts)<2` 时 `panic`，对首/次弧无范围校验，超 `uint64` 的弧 `ParseUint` 失败再 `panic`。配置 `smdpp.oid: "2"` 可通过启动校验，随后在 `service/download.go:155` 路径 panic | `validateOID` 校验 ≥2 段 + 首弧 0–2 + 次弧 <40（首弧<2 时）+ 数值范围；`EncodeOID` 改返回 error |
| 高 | `rsp/types.go:361`、`:419`、`rsp/cancel.go:34`、`rsp/signing.go:23` | OCP/DRY | CHOICE 遍历复制 4 份约 117 行 | 抽 `decodeChoice(raw, okTag, errTag)` + 每消息字段访问器 |
| 高 | `rsp/bpp.go:43` | DRY | `rsp.tlvBytes` 重实现 `asn1.Node.Encode`，非测试代码中有 47 处调用（download 20 / responses 19 / asn1binding 4 / bpp 3 / signing 1） | 统一委托 `asn1` |
| 中 | `rsp/encoding.go:10` | 死代码 | 9 个导出函数无生产调用方 | 随 `internal/iccid` 抽取一并删除 |
| 中 | `rsp/download.go:191` vs `:127` | 编解码不对称 | `Encode` 写 IconType/Icon/ProfileOwner/PPRIds/ServiceSpecificData，`DecodeStoreMetadataRequest` 只还原 ICCID/SPN/Name/Class/Notifications → 往返静默丢 5 组字段 | 补齐解码，或显式标注「单向编码器」并加往返测试 |
| 中 | `cert/manager.go:101` | SRP | 见 2.1 | 用 `{dir,base,roleOID,keyUsage,eku,rid,dns}` 表 + 一个循环 |
| 中 | `kms/kms.go:8` | ISP | 见 2.4 | 拆 `SignerLoader` / `Sealer` |
| 低 | `crypto/ecdsa.go:73` | 健壮性 | `DerToRaw` 检查了 SEQUENCE 标签与恰好 2 个子元素，但**不检查子元素必须是 INTEGER**，可接受畸形 DER（非验签绕过） | 改用 stdlib `encoding/asn1` 解 `struct{ R, S *big.Int }`，顺带删除 `trimInt`；`RawToDer` 同理 |
| 低 | `asn1/construct.go:24`、`:32`、`:62` vs `asn1/doc.go:6` | 契约/注释失真 | 别名与返回类型外泄 bertlv，与包注释矛盾 | 用自定义 `[]byte` tag 类型，去掉别名 |
| 低 | `cert/eum.go:101` | 复用库 | 手写拍平 RDNSequence | 改用 `crypto/x509/pkix.RDNSequence` |
| 低 | 6 个包 | DRY | `doc.go` 与实现文件顶部重复包注释且措辞已漂移：`rsp`（`types.go:1`）、`crypto`（`ecdsa.go:1`）、`cert`（`chain.go:1`）、`kms`（`kms.go:1`）、`audit`（`audit.go:1`）、`activationcode`（`activationcode.go:1`） | 只保留 `doc.go` |
| 低 | `activationcode/activationcode.go:60`、`:91` | SRP/健壮性 | 纯解析包做 PNG/QR 渲染（拉入 go-qrcode）；`ParseACR` 不校验 ICCID 长度；`Parse`/`String` 允许 OID 为空的 5 段形式 | QR 移到 API/CLI；补长度与字段校验 |
| 低 | `crypto/bpp.go:88` | ISP/可读性 | `ProtectBPP` 有 9 个位置参数，其中 5 个同为 `[]byte`，调用点无法防止错位（编译期无法发现） | 引入 `ProtectInput` 结构体（命名字段） |
| 低 | `rsp/helpers.go:19` vs `saip/header.go:312` | 重复/未用库 | `hexTag` 与 `tagHex` 逐字节相同，且都手写 nibble 循环 | 统一为 `encoding/hex` |

## 3. 目录内聚性检查

| 目录 | 现状 | 需拆出的文件 → 目标位置 |
|---|---|---|
| `internal/api/admin/` | **最严重**：DP 管理面 + DS 管理面 + 领域目录 + 文件导入导出 + OpenAPI + SAIP 解码混在一起 | `ds.go` → `internal/api/dsadmin`（顺带修掉 `MountDS` 却对外提供 DP+ openapi 的问题，`ds.go:30`）；`upp_tools.go:39-107` 字段目录/注解 → `saip/personalization`；`upp_decoded.go` 整文件 → 复用 `service.InspectUPP` 或迁 `saip`；`export.go` → `internal/adminio`；`openapi.go`+`openapi.json` → `api/admin/openapi`；`stats.go` 聚合逻辑 → store/service |
| `internal/api/es2plus/` | 4 种角色同包 | `clientlib.go`+`client.go` → `internal/client/es2p`（与 ES12 客户端 `service/smdsc.go` 位置对齐）；`callback.go` → `internal/client/es2p` 或 `service` |
| `internal/api/common/` | `status.go` 是杂物袋 | 拆 `binding.go`（DTO）、`respond.go`（writer）、`requestid.go`（ctx + media type） |
| `internal/api/es15/` | 只有 `doc.go`，声明一个不存在的包（真实 cascade 在 service） | 删除，doc 合并进 `service`；或指向真实实现 |
| `internal/api/mock/` | 测试专用，却被生产二进制 import（`cli/admin_ops.go:12`、`:165`） | 移到 `internal/testutil/mockoperator` 或用 build tag 隔离 |
| `internal/cli/` | `server.go` 5 职责；`admin_ops.go` 塞了 4 个不相关命令 | `server.go` → `listener.go`/`tlsutil.go`/`kmsload.go`/`run.go`；`admin_ops.go` 拆 4 个文件；新增 `registry.go` 做表驱动命令表 |
| `internal/service/` | 31 个文件，多文件混职责 | `helpers.go` → `cert_verify.go`；`notification.go` → `notification_verify.go` + `iccid.go`；`inventory.go` 的 ICCID 生成 → `iccid.go`；`smdsc.go` 的 `EventMeta` → `eventmeta.go`；`smds_event.go` 的接口 → `interfaces.go`；`upp.go` 的 FS 导入器 → cli/新包；`cmae.go`/`ds.go` 的状态映射 → `status.go`；`interfaces.go` 收拢全部消费方接口 |
| `internal/store/` | `store.go` 名不符实；`models.go`/`stats.go`/`pool.go`/`upp.go` 多聚合 | `store.go` → `errors.go`+`sqlutil.go`；`models.go` 按聚合拆 3 个；`stats.go` 的 `Stats` 各自归位，只留 `query.go`；`pool.go` → `pool.go`+`pool_range.go`；`upp.go` → `upp.go`+`upp_version.go` |
| `internal/saip/` | `header.go` 8 职责 | → `header.go`/`header_services.go`/`gfste.go`/`pe_registry.go` |
| `internal/rsp/` | `types.go` 474 行含 12 个消息结构体（ServerSigned1、EUICCInfo1/2、DeviceInfo、CtxParams、EuiccSigned1、SmdpSigned2、EUICCSigned2、PrepareDownload/Authenticate 的 ok/error CHOICE） | 按 SGP.22 功能拆分；`encoding.go` 的 ICCID/BCD 部分 → `internal/iccid`；`version.go` → `internal/saipver` |
| `internal/cert/` | `manager.go` 同时做加载/校验/选择/访问器 | → `loader.go`/`validate.go`/`identity.go`；`eum.go` 的 RDN 解析 → `x509ext.go` |
| `internal/crypto/` | `bpp.go` 混 ECDH 与 BPP 编排 | → `ecdh.go`（ECDH/EC-point/随机材料）+ `bpp.go`（仅 ProtectBPP/UnprotectBPP） |
| `internal/saip/personalization/` | 单文件 639 行 | → `apply_*.go`（按字段组）+ `sdkeys.go` + `codec.go`；ICCID/IMSI 编码 → `internal/iccid` |
| `internal/activationcode/` | 解析 + ACR + QR 渲染 | ACR 语法 → `acr.go`；QR → API/CLI 层 |
| `internal/kms/`、`internal/logging/`、`internal/metrics/`、`internal/version/`、`internal/audit/`、`internal/asn1/` | 内聚好 | 无需拆分（`audit` 只需接口收口） |

## 4. 重复实现清单

| 重复项 | 份数 | 位置 |
|---|---|---|
| `normalizeICCID`（去尾部 F） | 3+2 | `service/cmae.go:336`、`api/es2plus/handlers.go:479`、`api/admin/admin.go:61`、`store/pool.go:56`、`service/notification.go:217` |
| 手写 hex 编码 | 3+ | `api/admin/export.go:233`（手写 nibble 循环）、`api/es9plus/asn1.go:129`、`api/es11/asn1.go:70`、`rsp/helpers.go:19`、`saip/header.go:312` |
| `subjectCode` / ASN.1 错误码表 | 2 | `api/es9plus/asn1.go:133` vs `api/es11/asn1.go:94` |
| ICCID/BCD/EID 编码 | 3 | `rsp/encoding.go:10-132`（死）vs `saip/personalization/personalization.go:465-517,610-627`（活）vs `cert/eum.go:171` |
| `bytesEq`/`bytesEqual`/`equalBytes` | 3 | `asn1/tlv.go:183`、`saip/element.go:96`、`service/helpers.go:24` |
| `encodeInt` | 2 | `asn1/construct.go:133`、`rsp/helpers.go:5` |
| `tlvBytes` vs `asn1` 编码 | 47 调用点 | `rsp/bpp.go:43` |
| CHOICE ok/error 遍历 | 4（约 117 行） | `rsp/types.go:361`、`:419`、`rsp/cancel.go:34`、`rsp/signing.go:23` |
| 分页样板与 `{items,page,size,total}` 信封 | ~10 | `api/admin/profiles.go:100`、`pool.go:45`、`callbacks.go:56`、`notifications.go:30`、`audit.go:104`、`batches.go:90`、`ds.go:66`、`eids.go:11`；尺寸裁剪有 3 种写法 |
| audit 行构造 | 4 | `api/admin/admin.go:273`、`api/admin/ds.go:203`、`api/es2plus/handlers.go:404`、`api/es12/handlers.go:89` |
| `{code,message}` 错误体 | 2 | `api/admin/admin.go:172` vs `api/middleware/idempotency.go:137` |
| `ProgressInfo` DTO + 投递实现 | 2（1 个已死） | `service/notification.go:20` vs `api/es2plus/client.go:20`；`CallbackClient.HandleDownloadProgressInfo`（`client.go:170`）重复 `CallbackQueue.attempt`（`callback.go:136`）且从未接线 |
| mTLS client 构造 | 2 | `cli/server.go:121` `mtlsClient` vs `server.go:136` `smdsHTTPClient`（同体、同 30s） |
| 角色启动样板（open store / audit wrap / 3 listener） | 2 | `cli/smdpp.go:54-59`、`:176-190`、`:192-236` vs `cli/smds.go:48-53`、`:87-101`、`:103-127`；audit+wrap 段逐字节相同 |
| 重试/退避循环 | 2 | `service/smdsc.go:98` vs `api/es2plus/client.go:99`（同样的 `1<<attempt`） |
| store 的 Where/Order builder 与 `rowScanner` | 5 / 4 | `store/profile.go:171`、`audit.go:109`、`events.go:207`、`callback.go:167`、`notification.go:90`；`rowScanner` 在 `upp.go:203`、`profile.go:18`、`events.go:16`、`callback.go:28` 各声明一次 |
| 事务样板 `Begin`/`defer Rollback`/`Commit`（无 `withTx`） | 4 | `store/pool.go:72`、`:122`、`store/personalization.go:229`、`store/tenant.go:163` |
| 包注释重复 | 6 | 见 2.6 表末行 |

**顺带发现的事务/正确性问题**（重构时一并处理）：

- `store/upp.go:41` `Upsert` 是 UPDATE-then-INSERT 且事务外；`UpsertArchived` =
  `archiveCurrent` + `Upsert` 跨方法三步无事务。
- `store/personalization.go:85` look-then-UPDATE/INSERT 竞态；`store/pool.go:312`
  `DeleteRange` 两条 DELETE 无事务。
- `service/order.go:84` profile 状态机 read-modify-write 无 CAS，核心不变量靠最后写入者获胜。
- `service/cmae.go`、`service/download.go`、`service/cancel.go` 直接写 `p.State`，绕过
  `OrderService.Transition`/`AssertTransition`，`allowedTransitions` 实际不是权威。
- `service/registrar.go:23` 先远端 ES12 注册、后本地落库，本地失败则远端事件成为孤儿（无补偿删除）。
- `service/smds_event.go:46`、`:98` 对查询错误与「不存在」处理不当（见 2.3）。
- `store/sqlite.go:50` `SetMaxOpenConns(1)` 让读也被写串行化，长管理扫描会阻塞 ES9+ 流量
  （属既定部署形态，需在文档中显式化，而非立即改）。

## 5. 已有库复用

1. **`jsonschema/v6` 已声明却全仓零引用**：仅 `tools.go:12` 与 `docs/dependencies.md` 提及，
   而文档称其用于「SGP.22 JSON schema 契约测试」——该测试不存在。二选一：接入请求体校验
   （`api/admin/admin.go:223` 与 `api/common/envelope.go:59` 目前零校验，而 `openapi.json`
   已有 schema，可删掉 `admin/tenants.go:93`、`admin/ds.go:124`、`admin/personalization.go:138`
   的手写 required/enum/TTL/hex 校验），或从 `go.mod` 移除。`yaml.v3` 同样只在 `tools.go:14`
   被 pin，无编译单元引用。**不要两不靠**。
2. **chi 自带中间件**：`middleware.RequestID`/`Recoverer`/`Logger`/`RequestSize`/
   `AllowContentType` 与 `chi.Chain` 在 `api/middleware/middleware.go:19-48`、`:103-151`、
   `:205` 被重写一遍。自定义的 Audit/RequestScope/AdminProtocol/CORS 应保留（有审计语义），
   其余可换回 chi，减少自维护面。
3. **stdlib（go 1.27）**：`cmp.Or` 替代 `firstNonEmpty`（`admin.go:387`）；内建 `min`/`max`
   替代 `clampSize`/`clampPage`；`strings.Contains` 替代 `store/events.go:83` 的手写
   `contains`/`indexOf`；`encoding/hex` 替代全部手写 hex；`bytes.Equal` 替代三处字节比较；
   `sql.Null[T]` 替代 `store/store.go` 的 `nullStr`/`nullTime`/`boolInt`。
4. **`modernc.org/sqlite` 的类型化错误**：唯一冲突判定改用驱动的 `*sqlite.Error`/错误码 +
   `errors.As`，不要匹配错误字符串。
5. **`mapstructure/v2`** 目前只服务 config；query→filter 的手写解码
   （`admin/profiles.go:67`、`admin/ds.go:69`、`admin/audit.go:50`、`admin/callbacks.go:58`）
   可用它统一。
6. **`golang.org/x/sync`**：`errgroup` 已用于 `cli/server.go:180`（好）；`service/registrar.go:38`
   的串行 ES12 删除可用 `errgroup.SetLimit` 收敛；`store/idempotency.go:39` 的 in-flight 去重
   可考虑 `singleflight` 语义。
7. **viper 用法有真实缺陷（是「正确使用 viper」，不是换库）**：`AutomaticEnv` + `Unmarshal`
   只遍历 viper 已知的键，**既不在 `setDefaults` 也不在 YAML 中的键，环境变量会被静默丢弃**。
   已验证：`RSP42_SMDPP_SERVER_ES9P_PORT` 生效（在 defaults 中），而 `RSP42_KMS_KEK_FILE`、
   `RSP42_SMDPP_SERVER_ES9P_TLS_CERT_FILE` 被忽略。README 与 `config/config.go:4` 承诺
   「所有值可用 `RSP42_` 覆盖」，容器路径（`Dockerfile:25`）恰好是纯环境变量部署 → 会静默
   退回默认值。修法：对每个键 `v.BindEnv`，或让 `setDefaults` 由 defaults 结构体驱动
   （顺带消除三处默认值编码）。
8. **`uuid` 已依赖但 service 未用**：`service/smdsc.go:129` 手拼
   `fmt.Sprintf("ES12-%d", time.Now().UnixNano())`；`service/cmae.go:330`、
   `service/smds_event.go:134` 手写 `randomToken`。
9. **CLI 不引入 cobra**：13 个子命令、无位置参数/补全需求，stdlib `flag` 足够；`pflag` 虽作为
   viper 间接依赖存在于 `go.sum`，直接 import 仍需改 `go.mod` 且收益不大。真正要修的是
   表驱动命令注册表 + 单一 `addGlobalFlags`。
10. **版本注入失效**：`internal/version` 文档称可由 ldflags 注入，但 `Makefile:16` 只给
    `-s -w`、`Dockerfile:9` 也没注入 → `rsp42 version` 永远输出 `dev/none/unknown`。
11. **`asn1.EncodeLength` 被用在非 ASN.1 的 LV() 字段**（`crypto/kdf.go:40`、`crypto/bsp.go:37`、
    `:188`）：线上正确，但让密码学原语依赖编解码包；本地 `lv()` helper 可解耦。
12. 合理保留的依赖：`aead/cmac`（stdlib 无 CMAC）、`skip2/go-qrcode`、`goose`、`chi`、`viper`、
    `testify`、`modernc.org/sqlite`。

## 6. 重构计划

**总原则**：先修正确性与接缝（不改行为），再机械去重（可验证），再收口接口，最后才动物理目录。
每个阶段结束都必须 `build/vet/test` 全绿；**不要**在一次提交里同时改结构和行为。

### 阶段 0：护栏（0.5–1 天）

- 为下列行为补特征化测试（characterization tests），作为后续重构安全网：
  - `OrderService.Transition` 幂等路径当前语义（`order.go:92`）；
  - `middleware.Audit` 的 actor/tenant 落库断言（先固化「现状为空」再改）；
  - `Inventory.Allocate` 在 pool claim 失败时的行为；
  - admin 各 list 接口的分页/错误体契约（扩展现有 `admin_test.go` helper）。
- 固化基线：`make build vet test`、`gofmt -l cmd internal` 为空、`go list` 依赖边快照。
- 产出「接口白名单」清单（哪个消费者需要哪些 store 方法），作为阶段 3 的输入。
- 验证：新增测试全部通过。风险：无。

### 阶段 1：P0 正确性与接缝修复（1–2 天）

1. **OID panic 路径**（最高优先，配置可触发崩溃）：修严 `config/validate.go:306`；`asn1/oid.go:12`
   改返回 error。验证：新增非法 OID 的配置单测 + `EncodeOID` 错误路径单测。
2. **审计 scope 断裂**：把 `middleware.Audit` 挪进 `api/router.go:27` `base()` 的
   `RequestScope` 之后，或让 `RequestScope` 在外层创建 `*common.Scope` 并把指针交给 Audit；
   删除 `cli/smdpp.go:185`、`cli/smds.go:96` 的重复 `wrap`。验证：断言 audit 行 Actor/TenantID 非空。
3. **`Transition` 幂等语义**：先应用 `mutate`（及 `InstalledAt`）再做幂等返回，或返回
   `applied bool`；同步让 `CMAE`/`download`/`cancel` 走 `Transition` 而非直写 `p.State`。
4. **池一致性**：`service/inventory.go:216` `claim` 返回错误并让分配失败/回滚；
   `store/pool.go:175` `ReleaseExpired` 增加 `profile_id IS NULL` 条件；生成 ICCID 的重试
   只在唯一冲突时 `continue`。
5. **配置修复**：`cli/smds.go:76` 改为 `cfg.SMDS.SessionTTL`（新增字段 + 默认值）；
   viper 补 `BindEnv`；`store/models.go:35` 的 `CCHash // encrypted` 注释改对
   （Profile 是明文 SHA-256，Session 才加密）。
6. **错误语义统一**：ES2+ ACR 改用 `common.WriteCode` 信封、`Recover` 返回 JSON 500；
   `store/events.go:76` 改驱动类型化错误；`mustHexLower` 改返回 error；
   `service/smds_event.go:46`/`:98` 用 `errors.Is(err, store.ErrNotFound)` 区分。
7. **单一 body 上限**：`base()` 的 1 MiB 已让 es9plus/es11 的 4 MiB 与 admin 的 8 MiB 失效
   （`admin.go:24`、`es9plus/handlers.go:15`）——上限放进 `api.Options`，删除各包 `maxBody` 常量。
8. **`Encode()` 去副作用**：`rsp/download.go:28` 的 `RemoteOpID` 默认值移到构造/显式规范化。

- 验证：每项都有新增或既有单测；`make ci` 全绿。风险：低（行为变更仅限已认定为缺陷处）。

### 阶段 2：机械去重与复用（1–2 天）

1. 抽 `api/common` 的 `ParsePage`/`ListEnvelope[T]`/`WriteErrorBody`/`DecodeJSON`/`HexUpper`/
   `AuditRow`；约 10 处 list handler 改用它。
2. 新增 `api/asn1bind`：统一 es9plus/es11 的 DER 分发、`subjectCode`、错误码表（表驱动 + 角色参数）。
3. `rsp`：抽 `decodeChoice`；`tlvBytes` 统一委托 `asn1`；`responses.go:87` 硬编码 tag 归一为
   `asn1.Ctx/App`；`Code` 表加唯一性/别名测试（`rsp/errors.go` 现有 4 组重复值：`8.2.1/1.2`、
   `8.2/4.2`、`8.2.5/3.9`、`8.2.6/3.8`）。
4. `saip`：引入 PE descriptor 表，消除「一个 PE 改 6 处」；`templates.go`/`validate.go` 按版本索引。
5. 去重：`hexTag`/`tagHex`/`hexUpper` → `encoding/hex`；`bytesEq` 三处 → `bytes.Equal`；
   `encodeInt` 两处合一；`normalizeICCID` 五处合一。
6. `ProgressInfo` 合并为一份，删除已死的 `CallbackClient.HandleDownloadProgressInfo`；
   统一重试循环。
7. store：引入 `withTx`；单一 `rowScanner`；`*Cols` 常量；`scanNotification`；
   `Upsert`/`UpsertArchived`/`DeleteRange` 收进事务或改 `ON CONFLICT DO UPDATE`。
8. chi 内置中间件替换自实现（保留 Audit/RequestScope/AdminProtocol）。
9. 删除死代码与死导出（见附录 B）。
10. 库决策：`jsonschema/v6` 接入校验或删除；`yaml.v3` 处理；query→filter 用 mapstructure；
    `sql.Null[T]`；uuid。
11. 清理 6 个包的重复包注释。

- 验证：纯机械改动，靠阶段 0 测试与同名函数扫描归零对照。风险：低。

### 阶段 3：接口与契约收口（DIP/ISP，2–3 天）

1. **消费方定义接口**：在 `api/admin`、`es12`、`es2plus`、`api/middleware`、`audit` 各自声明
   所需最小接口（`AuditWriter{Insert}`、`IdempotencyStore{Claim,Complete,Abort}`、
   `UPPReader`、`EventStore`…），构造参数从 `*store.XxxRepo` 换成接口；`service` 侧补
   `AuditSink`、`ES12Client`、`OrderTransitions`、`CertProvider`，并把全部端口收进 `interfaces.go`。
2. **消除构造后注入**：为 `CMAE`、`NotificationService`、`es2plus.Handler`、`admin.Handler`、
   `CallbackQueue` 引入 `Options`/`Deps` 结构（构造即完整、构造期做 nil 校验），删除散落判空；
   68 个导出可变字段改私有或一次性 Options；`ProtectBPP`/`UnprotectBPP` 改输入结构体。
3. **拆 `admin.Handler`**：按资源域拆 `ProfileAPI/UPPAPI/PoolAPI/TenantAPI/CallbackAPI/AuditAPI`。
4. **依赖方向修正**：新建 `internal/iccid`（Luhn + ICCID/BCD/EID）与 `internal/saipver`（`Version`）
   两个叶子包，令 `store`/`config`/`saip/personalization` 不再 import `rsp`；
   `service.ImportUPPTemplates` 改吃接口并把 FS IO 移出 service；`cert → config` 改为传入普通结构体
   或由调用方定义 `cert.OptionsSource`。
5. **契约收口**：`asn1.Find/FindAll/First` 暴露解析错误或提供 `FindErr`；
   `rsp` 错误统一到 `rsp.Code`/`StatusCode`；`CancelSessionResponseFromTLV` 改返回 error；
   `StoreMetadataRequest` 往返补齐或显式标注单向。
6. **配置分段校验**：为各子配置加 `Validate()`，`Config.Validate(role)` 只编排；admin DB 命令
   只校验所需子配置；`ES12Config` 拆成 `ES12ClientConfig`/`ES12ServerConfig`；
   `kms.Provider` 拆 `SignerLoader`/`Sealer`；`asn1` 去掉 bertlv 别名。

- 验证：编译期断言接口实现关系（沿用 `service/dip_test.go` 写法）；`cli/wire_test.go` 用 fake
  替代真实 SQLite。风险：中（触及大量构造点），按依赖链小步推进。

### 阶段 4：目录与组合根拆分（3–5 天，纯移动 + 重命名）

1. **组合根**：`cli/server.go` 拆 `listener.go`/`tlsutil.go`/`kmsload.go`/`run.go`；抽 `runRole()`
   共享 open-store/audit-wrap/serve 样板；`cmdSMDpp`/`cmdSMDS` 降到约 30 行；指标词表与 collector
   移入各自包（`service`/`store` 暴露 `Describe`/`Collect`）；`admin_ops.go` 拆 4 个命令文件；
   引入表驱动命令注册表 + 单一 `addGlobalFlags`。
2. **admin 包**：抽 `internal/api/dsadmin`（`ds.go`）；字段目录移 `saip/personalization`；
   `upp_decoded.go` 复用 `service.InspectUPP`；`export.go` 移 `internal/adminio`；`openapi` 独立子包。
3. **es2plus 包**：`internal/client/es2p` 承接 `clientlib.go`/`client.go`/`callback.go`；
   删除或重定向 `api/es15`（doc-only）。
4. **store 包**：`store.go` → `errors.go`+`sqlutil.go`（`Store` 挪入或改名 `db.go`）；
   `models.go`/`stats.go`/`pool.go`/`upp.go` 按聚合拆分。
5. **service 包**：按阶段 3 的接口收口后拆文件（`iccid.go`/`cert_verify.go`/
   `notification_verify.go`/`status.go`/`token.go`/`eventmeta.go`）。
6. **saip/rsp/cert/crypto**：`saip/header.go` 拆 4 文件；`rsp/types.go` 按消息族拆；
   `cert/manager.go` 拆三段、`cert/eum.go` RDN 解析移 `x509ext.go`；`crypto/bpp.go` 拆 `ecdh.go`。
7. **activationcode**：ACR 语法拆 `acr.go`；QR 移出。
8. **mock 隔离**：`internal/api/mock` → `internal/testutil/mockoperator` 或 build tag。

- 验证：只搬文件；每搬一个包跑一次 `make ci`。风险：中（导入路径大面积变动），逐包小步提交
  便于 `git revert`。

### 阶段 5：测试与工程化收尾（可选）

- 统一测试 helper（`newTestServer`/`tlvOf`/`concat`/`do`/`mustJSON`/`itoa`）到 `internal/testutil`。
- 统一 Makefile 与 Dockerfile 的构建参数（ldflags 已开始漂移）；固定基础镜像与
  `golangci-lint` 版本；用 `-ldflags` 注入 `version`。
- 按 `docs/dependencies.md` 政策登记或移除依赖（`jsonschema` 决策）。
- 修复 `metrics` 的两个缺陷：未知指标名静默自动注册（`metrics.go:61-64`、`:76-79`）；
  `%q` 标签转义不是合法 Prometheus 转义（`metrics.go:143`）。

## 7. 明确不做

- **不用** ASN.1 编译器/生成码替代 `internal/rsp`、`internal/saip`（违反
  `docs/dependencies.md` 政策，且是签名字节级需求）。
- **不引入** cobra/pflag（13 个子命令规模不划算）。
- **不做** PostgreSQL/多副本的存储抽象（`docs/esim42-integration-gaps.md` §8.4 已决策）。
- **不换** `metrics` 为 `prometheus/client_golang`（固定部署形态的既有决策），只修上述两个缺陷。
- **不合并** `store` 与 `service`，也不为「消除 import」而搬迁数据模型（接口收口即可）。
- **不在同一提交里既搬目录又改行为**。

## 8. 验收标准

1. 每阶段结束：`go build ./... && go vet ./... && go test ./...` 全绿，
   `gofmt -l cmd internal` 为空。
2. 同名跨包函数扫描中，`normalizeICCID`/`hexUpper`/`subjectCode`/`bytesEq`/`encodeInt`
   等重复归零。
3. `internal/api/*`、`internal/audit`、`internal/api/middleware` 不再 import `internal/store`
   具体 repo 类型（`store` 的纯数据模型在必要时通过接口暴露）。
4. `internal/store` 与 `internal/config` 不再 import `internal/rsp`。
5. `docs/architecture.md` 的包依赖声明与实际 `go list` 一致（当前两处不符：api→store、config→rsp）。
6. 新增构建依赖必须同步登记 `docs/dependencies.md`；文档更新在代码稳定后单独提交。
7. 附录 A 的 P0 项全部有对应测试。

## 附录 A：问题优先级总表（Top 25）

| # | 优先级 | 位置 | 问题 | 所属阶段 |
|---|---|---|---|---|
| 1 | P0 | `config/validate.go:306` → `asn1/oid.go:12` | 非法 OID 通过配置校验后 panic | 1 |
| 2 | P0 | `api/middleware/middleware.go:170` + `api/router.go:33` | 通用审计 Actor/TenantID 恒为空 | 1 |
| 3 | P0 | `service/order.go:92` | 幂等分支吞掉 `mutate`（ErrorReason/InstalledAt 丢失） | 1 |
| 4 | P0 | `service/inventory.go:216` + `store/pool.go:175` | claim 吞错导致 ICCID 池污染 | 1 |
| 5 | P0 | `cli/smds.go:76` | DS 误读 DP 的 session TTL | 1 |
| 6 | P0 | `config/config.go:291` | `RSP42_*` 环境变量对未在 defaults/YAML 的键静默失效 | 1 |
| 7 | P0 | `api/es2plus/handlers.go:307`、`middleware.go:109` | 非 JSON 信封的 501/500 | 1 |
| 8 | P0 | `store/events.go:76` | 字符串匹配判定唯一冲突 | 1 |
| 9 | P0 | `api/admin/admin.go:24` 等 | body 上限被 `base()` 覆盖，配置无效 | 1 |
| 10 | P1 | `store → rsp`、`config → rsp` | 分层倒挂 | 3 |
| 11 | P1 | `rsp/encoding.go:10` + `saip/personalization:465` | ICCID/BCD 重复 + 死代码 | 2/3 |
| 12 | P1 | `api/admin/admin.go:31` | admin 上帝 Handler（12 个具体 repo） | 3/4 |
| 13 | P1 | `api/es2plus/` | 服务端/回调/客户端/队列同包 | 4 |
| 14 | P1 | `api/admin/ds.go` | DS 管理面混在 DP admin 包 | 4 |
| 15 | P1 | `api/es9plus/asn1.go` vs `api/es11/asn1.go` | 分发器与错误码表两份 | 2 |
| 16 | P1 | `rsp/types.go:361` 等 4 处 | CHOICE 遍历复制 4 份 | 2 |
| 17 | P1 | `saip` 六处表 | 一个 PE 最多改 6 处 | 2 |
| 18 | P1 | `cli/smdpp.go:31`、`cli/smds.go:25` | 角色样板重复 + 207 行组合根 | 4 |
| 19 | P1 | `asn1/tlv.go:71` 等 | 解析错误被吞，畸形与缺失不可区分 | 3 |
| 20 | P2 | `store/models.go`、`store.go`、`stats.go`、`pool.go`、`upp.go` | 多聚合同文件 | 4 |
| 21 | P2 | `saip/header.go`、`rsp/types.go`、`cert/manager.go`、`personalization.go` | 单文件多职责 | 4 |
| 22 | P2 | `api/admin/upp_tools.go:39`、`upp_decoded.go`、`export.go`、`openapi.go` | 领域逻辑与 IO 混在 handler 层 | 4 |
| 23 | P2 | `rsp/download.go:127` vs `:191` | StoreMetadata 编解码不对称 | 3 |
| 24 | P2 | `crypto/ecdsa.go:73` | DER 子元素未校验 INTEGER | 2 |
| 25 | P2 | 6 个包 | 重复包注释 | 2 |

## 附录 B：死代码与死导出清单

已核实的完全无用（生产与测试均无调用）：

- `crypto.UnprotectBPP`（`crypto/bpp.go:132`，注释声称「用于测试与互操作验证」但从未执行）
- `rsp.ACRRetryDelay`（`rsp/download.go:186`）
- `saip.TemplateForOID`（`saip/templates.go:53`）
- `asn1` 导出：`Uint`、`OID`、`Str`、`BitString`、`MustTag`（`asn1/accessors.go:27,42,45,56,78`）、
  `Null`、`Enumerated`、`TagOID`、`TagEnumerated`、`TagUTF8String`、`TagNull`、`TagBitString`
  （`asn1/construct.go:92-122`）、`MustParseNode`（`asn1/node.go:121`）

仅被自身测试引用（生产无用）：

- `asn1.BitSet`（`asn1/accessors.go:65`）
- `rsp.EIDString`、`rsp.ICCIDFromEFBytes`（`rsp/encoding.go:72,119`）

`rsp/encoding.go` 中无生产调用方的 9 个函数（保留存活者 `LuhnValid`、`LuhnCheckDigit`、`EIDBytes`）：

- `NibbleSwap`、`BCDToDigits`、`DigitsToBCD`、`EIDString`、`ValidEID`、`ICCIDHeaderBytes`、
  `ICCIDFromHeaderBytes`、`ICCIDEFBytes`、`ICCIDFromEFBytes`

> 注意：`asn1.Int` 有 16 处调用，是活代码，不属于死导出。

---

## 执行记录（按提交顺序）

每个提交独立通过 `go build ./... && go vet ./... && go test ./...`（23 个包全绿）。

### 阶段 0：护栏

- 阶段 0 的意图（为将改动的行为补特征化/回归测试）并入阶段 1 的各项修复，逐项新增测试，不再单独提交。

### 阶段 1：P0 正确性与接缝修复（全部完成）

| 提交 | 内容 |
|---|---|
| `9a81105` | `asn1.EncodeOID` 不再 panic，改为返回 error 并校验 X.690 §8.19 弧规则；`config.validateOID` 委托同一实现，非法 `smdpp.oid`/`smds.oid` 无法再通过校验后在生成 BPP 时崩溃；`rsp.ConfigureISDPRequest.Encode` 返回 error；删除死导出 `asn1.OID` |
| `49bd963` | `middleware.Audit` 移入 `base()` 的 `RequestScope` 之内（`api.Options.Audit`），修复通用审计行 actor/tenant 恒空；admin 路由显式不启用该中间件，避免 health/metrics 刷审计 |
| `3a7b647` | `OrderService.Transition` 在所有调用上执行 `mutate` 并传入 `stateChanged`；重发时刷新 release flag / 失败原因，`InstalledAt` 只在首次安装写入，下载计数只在真实状态迁移时递增 |
| `eaa262a` | `Inventory.claimReservation` 返回错误并回滚已创建的 profile；池预留释放失败上报；生成 ICCID 只在唯一冲突时重试；`store.IsUniqueViolation` 用驱动错误码替代字符串匹配；`ReleaseExpired` 不再回收已归属 profile 的条目 |
| `222e7ae` | `bindEnvs` 从 `Config` 的 mapstructure tag 反射出全部键并 `BindEnv`，`RSP42_*` 覆盖不再漏键；新增 `smds.session_ttl`（默认 30m，校验为正）并让 SM-DS 使用它而非 `smdpp.session_ttl`/`event_ttl`；修正 `Profile.CCHash` 的错误注释 |
| `8d824cf` | `middleware.Recover` 返回 JSON 500 并记录堆栈；保留的 ES2+ `handleAcrRequest` 存根返回 JSON；`mustHexLower` → `hexLower` 返回 error；`EventService.Register/Delete` 用 `errors.Is(store.ErrNotFound)` 区分存储故障 |
| `1e79110` | 请求体上限单一来源 `api.Options.BodyLimit`（`common.ReadJSON/ReadRaw` 从请求上下文取预算），删除 es9plus/es11/es12/es2plus/admin 各自的 `maxBody`；`middleware.Idempotency` 按路由预算缓冲，admin 用 8 MiB |
| `5ff4472` | `InitialiseSecureChannelRequest.Encode` 不再改写 receiver，`Encode`/`SignedBytes` 共用 `remoteOpID()`，签名与编码不可能不一致 |

### 阶段 2：去重与复用（全部完成）

| 提交 | 内容 |
|---|---|
| `66a88da` | 新增 `internal/api/asn1bind`：DER 信封、媒体类型闸门、`subjectCode`、`hexUpper` 与表驱动 `CodeFor`；es9plus/es11 只保留各自的分发与数值错误表 |
| `099393b` | admin 的 `parsePage` + `writeListEnvelope[T]`，10 处分页/信封样板收敛，契约不变 |
| `a566f09` | `store/tx.go` 的 `withTx`/`dbtx`/`rowScanner`；`upp_templates` 改 `ON CONFLICT DO UPDATE`；`UpsertArchived`、`PersonalizationRepo.Upsert`、`PoolRepo.DeleteRange` 进事务 |
| `7b001fe` | 清理死导出（`crypto.UnprotectBPP` 除外，见下）、删 `rsp/encoding.go` 死函数、`bytes.Equal`/`asn1.IntBytes`/`encoding/hex` 替代手写 helper、去掉 6 个包重复的包注释 |
| `7e2d7f7` | `internal/rsp/choice.go` 统一 CHOICE 解码（4 份 → 1 份）；`tlvBytes` 保留并加测试说明「为何不能改用 `asn1.Marshal`」 |
| `4554474` | `saip` 单一 `peDescriptor` 注册表替代 5 张平行表，TS.48 向量与 GFSTE 重建逐字节不变 |
| `05556c4` | `service.ProgressInfo` 成为唯一 DTO，删除 `es2plus.ProgressInfo` 与未接线的 `CallbackClient.HandleDownloadProgressInfo` |
| `2629a96` | 新增叶子包 `internal/saipver` 与 `internal/iccid`；`store`、`config` 不再 import `internal/rsp` |
| `53d6f84` | 删除 `rsp` 的 Luhn 包装，codec 包只剩真正的消费者 |

**与计划的偏差（有意，已记录）**

1. `crypto.UnprotectBPP` 未删除，改为**恢复并测试**：它是 `ProtectBPP` 的唯一逆运算，是验证「生成的 BPP 能被解回原文」的途径。现由 `TestProtectBPPRoundTrip`（多段 UPP + 可选 BF26）与 `TestProtectBPPWithoutReplaceSessionKeys` 覆盖。
2. `rsp.tlvBytes` **未**统一到 `asn1.Marshal`：实测 `asn1.Marshal`（bertlv）在内容 >65535 字节、或构造型 tag 带原始内容时 panic，而 `tlvBytes` 正是为 BF36 信封与 `[n]` 分段组而存在。已用测试固定该边界，并在 `asn1.Marshal` 上写明限制。
3. `saip` 的 PE 注册表保留了旧的 4 处不一致（bf1f/bf22 无名字但有 post-baseline 名、post-baseline 模板 PE 非 singleton 等），只统一存储方式，不改数据；唯一可见变化是 singleton 错误改为按描述符顺序确定输出（错误集合不变）。
4. 阶段 2 未做的两项：`jsonschema/v6`/`yaml.v3` 依赖的去留决策（需确认是否接入请求校验，见阶段 2 第 10 条）、`es2plus` 与 `service/smdsc.go` 的重试循环合并。

### 阶段 3：接口与契约收口（进行中）

已完成（按提交顺序）：

| 提交 | 内容 |
|---|---|
| `2629a96` | `saipver`/`iccid` 叶子包；`store`/`config` 不再 import `rsp` |
| `9305542` | `RoleAdminStore` + 分段校验（`LogConfig`/`KMSConfig`/`ProfilesConfig` 各自 `Validate()`，`validateCommon`/`validateDP` 委托），CLI 数据库类命令不再要求证书/FQDN |
| `907efa4` | `asn1.Find/FindAll/First` 契约写明并新增 `FindErr`；`splitChoice` 返回解析错误并在 4 个解码器传播；`CancelSessionResponseFromTLV` 改 `(int64, bool)`；`StoreMetadataRequest` 解码补齐（往返测试断言重编码一致） |
| `efeb252` | `asn1.Tag` 改为 `[]byte`、`Builder` 改为本包不透明类型（bertlv 仅剩 `construct.go` 一个 import）；`kms.Provider` 拆 `SignerLoader`/`Sealer`，cert 用前者、session/personalization 用后者 |
| `30c1664` | `middleware.IdempotencyStore`、`audit.AuditSink`、`es12.AuditWriter` 由消费方定义，配 typed-nil 守卫与编译期断言 |
| `8beaac1` | `es2plus` 的 `UPPValidator`/`AuditWriter`/`MetricCounter`/`IdempotencyStore` 接口 |
| `e35ca88` | 删除 doc-only 的 `internal/api/es15`，doc 并入 `service.CascadeClient` |

待办：`admin.Handler` 的 12 个具体 repo 字段收口（需与阶段 4 的包拆分一起做）；`Options`/`Deps` 注入以消除「构造后字段赋值」（跨结构体 68 个导出可变字段）；`rsp` 错误词汇统一到 `rsp.Code`；`admin_ops.go` 混合命令拆分与配置 profile；`jsonschema/v6`/`yaml.v3` 去留；`es2plus` 与 `service/smdsc.go` 重试循环合并。

### 阶段 4：目录与组合根拆分（进行中）

已完成：

| 提交 | 内容 |
|---|---|
| `e35ca88` | 删除 doc-only 的 `internal/api/es15`，doc 并入 `service.CascadeClient` |
| `b6d708c` | 测试专用的 mock operator 从 `internal/api/mock` 移到 `internal/testutil/mockoperator` |
| `1e758db` | 新增 `internal/api/adminhttp`（JSON/错误体/`ErrCode`/分页/`ParseID`/`ParseTime`/`TenantFilter` 等），admin 全部改用；`normalizeICCID` 三处副本删除改用 `iccid.Normalize` |
| `bf0960c` | `admin/ds.go` → `internal/api/dsadmin`（消费方定义 `EventStore`/`AuditSink`）；`openapi.json` 移入 `internal/api/admin/openapi`，新增 `Doc()`/`FilteredDoc()`；**SM-DS admin 不再对外提供 DP+ OpenAPI 文档**（改为按 `/events` 过滤、标题为 SM-DS 的文档） |
| `d1fd0f6` | `cli/server.go` 按职责拆为 `listener.go`/`run.go`/`kmsload.go`；`serveAll` 的信号处理改为循环，第二次信号强制退出（原先第二次信号被忽略、卡住的进程只能 SIGKILL） |
| `316a1dc` | 删除 admin 中因 DS 拆出而失效的 `Events` 依赖 |

待办：`cli` 的 `cmdSMDpp` 组合根拆分与表驱动命令注册表；`es2plus` 客户端代码 → `internal/client/es2p`；`store`/`service`/`saip`/`rsp`/`cert` 的文件级拆分；`admin.Handler` 的 12 个具体 repo 字段收口（现已有 `adminhttp`/`dsadmin` 前置，宜与按资源域拆分一起做）。

### 阶段 5：测试与工程化收尾（进行中）

已完成：

| 提交 | 内容 |
|---|---|
| `29a1098` | 指标注册表拒绝未声明名称（panic 并报出名字），修好标签转义（Prometheus 只接受 `\\`、`\"`、`\n`），指标词表移入 `service.DescribeMetrics`/`es2plus.DescribeMetrics` |
| `6d4490a` | `make build` 注入 `-X` 版本元数据（此前 `rsp42 version` 恒为 dev/none/unknown）；Makefile 与 Dockerfile 共用 `make build`，消除构建参数漂移；镜像 pin 到 `golang:1.27-bookworm`/`alpine:3.22`（已用 Docker Hub API 校验 tag 存在）；CI 的 golangci-lint pin 到 v2.14.0 |
| `f5eae0b` | 重复测试 helper（`MustHex`×3、`Concat`×3、`TLV`/`HexTag`×2、`itoa`）统一到 `internal/testutil`；该包只被 `_test.go` 引用，不进二进制 |
| `b6d708c` | mock operator 迁入 `internal/testutil`（见阶段 4） |

待办：`docs/architecture.md` 的包清单与依赖方向需按当前 `go list` 更新（新增 `internal/api/adminhttp`、`internal/api/asn1bind`、`internal/api/admin/openapi`、`internal/api/dsadmin`、`internal/iccid`、`internal/saipver`、`internal/testutil`，并写明 `store`/`config` 不再依赖 `rsp`）；`jsonschema/v6` 与 `yaml.v3` 的去留（**需用户决策**）；`es2plus` 与 `service/smdsc.go` 的重试循环合并；`admin_ops.go` 拆分。

### 执行期间确认的额外结论

- `asn1.Marshal`（bertlv）在内容 >65535 字节或构造型 tag 带原始内容时 panic；`rsp.tlvBytes` 因此必须保留（已加测试与注释）。
- `DecodeStoreMetadataRequest` 原本无生产调用方且丢失 5 组字段，现补齐并加了往返测试。
- `internal/api/es15` 只有包注释、无任何 import，已删除。
