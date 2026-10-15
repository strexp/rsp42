# 重构计划（SOLID 与目录内聚性，第二轮）

> 状态：**执行中**。进度见文末「执行记录」。
> 最后更新：2026-10-15

> 语言约定：与 `TODO.md` 一致，工作/计划类文档使用中文；代码、注释与权威文档
> （`README.md`、`docs/architecture.md`、`docs/interfaces.md` 等）保持英文。
> 本文件的结论若被采纳为权威架构约束，应翻译并合入 `docs/architecture.md`。

## 0. 约束与范围

本轮的**唯一目标**是结构调整：复用、去耦合、修正目录内聚性。

**硬约束：不得改变项目行为。** 因此：

- 只做搬移、重命名、拆分文件、抽取接口、消除重复实现；
- **不做**任何会改变可观察行为的修正——包括事务边界收口、并发语义变更、
  契约/错误码修正、配置默认值重构、启动校验增强；
- 分析中发现的行为缺陷全部记录在 §6，**本轮不修**，留给后续单独评审；
- 每个阶段结束必须 `go build ./... && go vet ./... && go test ./...` 全绿，
  并单独提交，便于 `git revert`。

拆分深度采用**保守档**：只移出错位文件、拆 god 文件/类型、收口接口，
**不新建** `service/*`、`store/*` 子包（避免端口归属与循环依赖）。

## 1. 评估方法与基线

- 走查 `cmd/rsp42` 与 `internal/**` 全部 182 个非测试 Go 文件（约 35.6k 行）与 83 个测试文件，
  外加 `Makefile`、`config/`、`docs/`、`.golangci.yml`。
- 静态检查：`go vet ./...` = 0；`golangci-lint run`（仓库配置）= 0；
  额外启用 `dupl,gocyclo,funlen,interfacebloat,nestif` 得到 54 项复杂度/重复告警。
- 依赖方向用 `go list -deps` 与源码 `import` 扫描交叉验证。
- 基线（本轮验证，全绿）：`go test ./...` 全部包通过。

## 2. 结论摘要

架构骨架健康：包依赖无环、分层方向基本正确、`bertlv` 只被 `internal/asn1/construct.go`
直接引用且类型不外泄、无 `init()` 副作用、`cmaeCore` 的「共享握手 + 各角色错误码映射」
是标准的 OCP 做法、持久化边界的 DIP（消费方定义接口 + 编译期断言）是真做了。

问题集中在两处：**目录/文件级职责内聚**与 **DIP 收口不彻底**。

| 原则 | 评级 | 判断 |
|---|---|---|
| SRP | 偏弱 | 6 个文件级「上帝文件」；6 处领域规则混进持久层；传输层承载领域推导 |
| OCP | 局部失分 | `es2plus` 的 header 分派是封闭类型 switch；`cert` 角色校验器四份平行 |
| LSP | 本轮无发现 | 无继承层次；接口由结构体结构化满足 |
| ISP | 基本合格 | `admin/deps.go` 是范本；例外是 `UPPStore` 11 方法、ES handler 未接口化 |
| DIP | 半途 | 存储缝已收口，但接口签名泄漏 `store` 模型；ES handler 依赖 `*service.X` 具体类型；`cert → config` 方向倒挂 |

## 3. 问题清单（按目录）

严重度：**H** 高、**M** 中、**L** 低。`(行为)` 标记表示修复会改变可观察行为，本轮只记录。

### 3.1 `internal/service`（28 文件 / 3694 行）——混入 6 类非编排职责

| 严重度 | 位置 | 问题 | 目标 |
|---|---|---|---|
| H | `service/smdsc.go:55` | 出站 ES12/ES15 HTTP 客户端（`net/http`）位于「无 HTTP」包；`Register`/`Delete` 硬编码 `context.Background()` | `internal/client/es12` |
| H | `service/cert_verify.go:14,24,38,52` | 证书解析/EID 提取/链校验，`cert` 已有 `VerifySignatureChain` | `internal/cert` |
| H | `service/upp_inspect.go:51,118` | SAIP 解析 + `ValidateV231` + admin JSON DTO；`RenderUPP` 与 `CMAE.loadUPP` 重复 parse→apply→encode | `internal/uppinspect` |
| M | `service/iccid_decode.go:5,14` | ICCID BCD 解码 + `hexDigit`，`internal/iccid` 就是为此建的叶子包 | `internal/iccid` |
| M | `service/address.go:18,37` | `FQDN[:Port]` 匹配（§4.1），纯函数 | `internal/rsp` |
| M | `service/download.go:28`（414 行） | ES9+ 编排 + SCP03t BPP 组装 + BF25 编解码 + 模板版本策略 + 个性化加载 | 文件内拆分（本轮） |
| M | `service/metrics.go:9` | 声明 `rsp42_downloads_total`，实际 emit 在 `client/es2p/callback.go:82` | 声明移近 emitter |

**做得好、不要破坏**：`cmae_core.go` 的共享握手；`acr_check.go` 的注入式设计；
`order.go` 声明式状态机；`interfaces.go` 的小接口；无全局可变状态、无 `init()`。

### 3.2 `internal/store`（23 文件 / 3285 行）——领域规则混居

| 严重度 | 位置 | 问题 | 本轮处理 |
|---|---|---|---|
| H | `store/pool.go:128` | 分配策略写成 SQL（`WHERE state='available' ORDER BY iccid LIMIT 1`） | **(行为)** 只记录 |
| H | `store/upp.go:131` | 版本排序写成 SQL，并在 repo 内调用 `saipver.Max` | **(行为)** 只记录 |
| H | `store/tx.go:20` | `withTx` 接 `*sql.DB`，跨聚合无法原子提交；service 手写补偿 | **(行为)** 只记录 |
| M | `store/stats.go:47,80` | 跨聚合报表：`ProfileRepo.Stats` 与 `AuditRepo.Stats` 同文件 | 拆回 `profile.go`/`audit.go` |
| M | `store/notification.go:22,56` | `dupl` 判定两段完全重复；无 `scanNotification` | 抽 `scanNotification` |
| M | 8 个文件 | `COUNT(*)+LIMIT/OFFSET` 分页样板复制粘贴 | 泛型 `listPage[T]` |
| M | 28 处 | 手写 `for rows.Next()` 循环 | 泛型 `queryAll[T]` |
| M | `store/tenant.go:142` | `tenantScopedTables` 跨 5 表级联更新 | **(行为)** 只记录 |
| M | `store/callback.go:174` | `json_extract(payload_json,'$.tenantId')` 解析他层 wire JSON | **(行为)** 只记录 |
| L | `store/*_model.go` | 模型文件拆分不一致（3 个有 `_model.go`，其余内联） | 统一（纯搬移） |
| L | `store/migrations/00008:47` | `iccid_pool.imsi` 死列，`poolCols` 不含、无代码读写 | 只记录（动 schema 属行为） |

**做得好**：`errors.go` 用驱动结果码而非字符串匹配；`dbtx`/`rowScanner` 微接缝；
`const xCols` + 单 `scanX` 惯例；动态 SQL 参数化 + 标识符白名单；租户作用域统一。

### 3.3 `internal/api/*`——传输层合同混入领域与跨面依赖

| 严重度 | 位置 | 问题 | 目标 |
|---|---|---|---|
| H | `api/es2plus/handlers.go`（639 行） | 依赖定义 + 路由 + DTO + 5 handler + 租户解析 + 授权 + 审计 + 错误映射 + writer 同文件 | 同包拆多文件 |
| H | `api/dsadmin/dsadmin.go:19` | SM-DS 管理面 import SM-DP+ 的 `admin/openapi` | `internal/api/openapi` |
| M | `api/admin/upp_tools.go:40,70` | SAIP 字段目录 + `annotateSchema` 放在 HTTP 包 | `internal/uppinspect` |
| M | `api/admin/upp_decoded.go:41` | 重复实现 `service.InspectUPP` 的子集 | 复用 `uppinspect` |
| M | `api/admin/profiles.go:310,372` | 跨 4 仓储聚合时间线；直接改写 `MatchingID` 绕过 `OrderService` | `service` |
| M | `api/admin/batches.go:117` | 9 次顺序 `ListFiltered` 代替已有 `Stats(filter,"state")` | 复用 `Stats` |
| M | `api/admin/admin.go:149-172` | 9 段从 `adminhttp` 搬走后残留的孤儿注释 | 删除 |
| M | `api/admin/tenants.go:40` 等 10 处 | `Validate()` 已要求非 nil，501 分支不可达 | 删除 |
| M | `api/es12/handlers.go:71` | **(行为)** 不校验强制 header，而 ES2+ 校验 | 只记录 |
| M | ES handler 包 | 依赖 `*service.CMAE`/`*EventService` 等具体类型 | 各包 `deps.go` 窄接口 |
| L | `api/admin/export.go:234` | 手写 `hexUpper`，与 `asn1bind.HexUpper` 重复 | `common.HexUpper` |
| L | `api/adminhttp/adminhttp.go:89` vs `api/common/envelope.go:94` | 两个 `ReadJSON` 语义不同 | 统一 |

**做得好**：`admin/deps.go` 的窄接口 + 编译期断言；`internal/api` 无 SQL/无 FS/无 `init()`；
基于 `jsonschema` 的契约测试；body 上限单一来源；`asn1bind` 只共享媒体类型/信封/状态映射。

### 3.4 `internal/rsp`（18 文件 / 2063 行）——编解码包承担全接口状态码词表

| 严重度 | 位置 | 问题 | 目标 |
|---|---|---|---|
| H | `rsp/errors.go:30,58` | `StatusXxx` 与 `CodeXxx` 两套同义注册表（5 组重复值），包外引用 151 次 | `internal/rsp/status` |
| M | `rsp/bpp.go:43` | `tlvBytes` 在 rsp 里绕过 `asn1` 手写 tag+length（bertlv 限制外泄） | `asn1.RawTagged` |
| L | `rsp/helpers.go:5,15` | `concat`（应 `bytes.Join`）、`firstChild`（`t.First()` 的转发） | 删除/替换 |
| L | `rsp/download.go:387` | BPP 元素 + LPA 请求解码 + ACR 构造器同文件 | 文件内拆分 |

### 3.5 `internal/saip` 与 `internal/saip/personalization`

| 严重度 | 位置 | 问题 | 目标 |
|---|---|---|---|
| M | 目录级 | 模型/编解码（`element`/`files`/`header`）与 校验/模板表（`validate`/`filevalidate`/`constraints`/`filetable`）同目录 | 保守档不建子包，仅在文档中登记分层 |
| M | `personalization/csv.go:33` | 领域包内 `os.Open`（惰性、请求路径可达） | **(行为)** 只记录 |
| M | `saip/validate.go:38` + `filevalidate.go:63` + `constraints.go:45` | 同一条 FCP/Annex-A 规则分散三文件（`shortEFID` 校验两次） | **(行为)** 只记录 |
| L | `saip/files.go:86` | 手写大端整数（应 `encoding/binary`） | 替换 |

### 3.6 `internal/cli`（18 文件 / 1811 行）——组合根混入数据访问与策略

| 严重度 | 位置 | 问题 | 目标 |
|---|---|---|---|
| H | `cli/admin_mockoperator.go:9` | 非测试文件 import `internal/testutil/mockoperator`，`go list -deps ./cmd/rsp42` 确认其进入生产二进制，违反 `docs/architecture.md` | 迁 `internal/mockoperator`（真实 dev 包），命令保留 |
| H | `cli/admin_db.go:136` | `rekeySessions` 复制 service 的加密字段清单、非事务、漏 `Perso.K/OPc` | **(行为)** 只记录 |
| M | `cli/admin_gc.go:38`、`admin_iccid.go:46`、`admin_db.go:186`、`admin_upp.go:39`、`admin_smdsevent.go:44` | 命令直接调仓储并定义策略 | `service`（本轮只做无行为变化的搬移） |
| M | 目录级 | 组合根 + TLS/生命周期 + 9 个 admin 命令 + 派发同包 | `internal/cli/admin` 子包 |
| M | 9 个命令 | 硬编码 `"config/config.yaml"`，绕过 `cli.go:13` 常量 | 统一 |

### 3.7 跨包重复与库复用

| 重复项 | 份数 | 位置 |
|---|---|---|
| `strings.ToUpper(hex.EncodeToString(...))` / `hexUpper` | 7+ | `asn1bind.go:49`、`admin/export.go:234`、`admin/personalization.go:51`、`service/upp_inspect.go:67`、`admin/upp_decoded.go:60,74`、`service/cmae_core.go:176`、`service/notification.go:136` |
| 十进数字→BCD 编码 | 3 | `rsp/encoding.go:10`、`cert/eum.go:171`、`saip/personalization/fields_codec.go:49` |
| CSV 表头索引 | 2 | `api/admin/export.go:194`、`saip/personalization/csv.go:32` |
| 手写 TLV 编码 | 2 | `rsp/bpp.go:43`、`testutil` |
| 恒等/薄包装 | 3 | `crypto/ecdsa.go:53`（`pub.Bytes()`）、`rsp/helpers.go:5`、`saip/files.go:86` |
| 分页信封/尺寸裁剪 | ~10 | `api/admin/*`、`api/dsadmin` |

**已有库未用足**：`chi` 的 `middleware.NewWrapResponseWriter` 可替代 `api/middleware/middleware.go:51`
的 `statusWriter`；`sync.OnceValue` 可替代 `api/admin/openapi/openapi.go:24` 的 `sync.Once` + 可变 map；
`encoding/binary`、`bytes.Join`、`encoding/hex` 可替代上述手写。

## 4. 重构计划

**总原则**：先立护栏 → 再机械搬移 → 再包边界 → 最后去重收口 → 文档对齐。
每个阶段一个提交，阶段内可再分小提交；每次提交前后 `go test ./...` 必须全绿。

### 阶段 0：护栏（不改结构）

1. 新增 `internal/archcheck/arch_test.go`：用 `go/parser` 静态断言架构不变量——
   - `internal/testutil`（含子包）只允许被 `_test.go` 引用；
   - 依赖边白名单：禁止 `cert → config`、`store → rsp`、`config → rsp`、
     叶子包（`asn1`/`iccid`/`saipver`/`kms`/`logging`/`metrics`/`version`）→ 任何上层；
   - `github.com/euicc-go/bertlv` 只允许被 `internal/asn1` 直接引用。
2. 记录依赖边基线（供后续对照）。

验证：新增测试通过；`go vet`、`golangci-lint` 不变。

### 阶段 1：机械搬移（零行为变化；每项一个提交）

1. `internal/testutil/mockoperator` → `internal/mockoperator`；更新 `cli/admin_mockoperator.go`
   与 2 个测试的 import。`admin mock-operator` 命令行为不变。
2. 删除 `internal/cert/config.go`；`cert.Options` 的配置映射移入组合根
   （`internal/cli/kmsload.go`）。`cert` 不再依赖 `config`。
3. `service/cert_verify.go` → `internal/cert`（`ECDSAKey`/`ParseCertificateList`/
   `EIDFromCert`/`ValidateEUICCChain`）；更新 `cmae_core.go`、`cmae.go`、`download.go`、
   `notification_verify.go` 的调用。
4. `service/iccid_decode.go` → `internal/iccid.DecodeBCD`；删除 `hexDigit`；
   更新 `notification_verify.go:34`。
5. `service/upp_inspect.go`（整文件）→ `internal/uppinspect`；更新 `api/admin/upp.go:112`、
   `upp_tools.go:140,167,242`。
6. `service/address.go` → `internal/rsp`（`AddressMatches`/`SplitHostPort`）；
   更新 `cmae_core.go`。
7. `service/smdsc.go` → `internal/client/es12`（含 `EventMeta`、`HeaderXxx` 常量、`ES12Error`）；
   更新 `service/interfaces.go`、`registrar.go`、`smds_event.go`、`notification.go`、
   `api/es2plus/handlers.go`、`api/es12/handlers.go`、`cli/smdpp.go`。
   `service` 不再 import `net/http`。
8. `rsp/bpp.go` 的 `tlvBytes` → `asn1.RawTagged`；`internal/testutil` 内同款编码器一并收敛。
9. `api/common.HexUpper` 统一 `asn1bind.HexUpper` 与 `api/admin/export.go:hexUpper`。
10. 死代码/死导出清理（已核实生产与测试均无引用）：`middleware.Chain`、
    `asn1bind.SubjectCode`、`store.UPPRepo.GetByName/SelectBest/Any`、
    `store.PersonalizationRepo.BindPair`、`store.ICCIDPoolEntry.Expired`、
    `api/admin/admin.go:149-172` 孤儿注释。
11. `rsp` 状态码词表抽取为 `internal/rsp/status` 叶子包（合并 `StatusXxx`/`CodeXxx` 双份）；
    `rsp` 与 11 个外部文件改引用。**独立提交**，便于回滚。

验证：每项 `go build/vet/test` 全绿；`archcheck` 的 `bertlv` 与 `testutil` 断言开始生效。

### 阶段 2：目录与包边界（零行为变化；纯搬移/拆文件）

12. `internal/api/admin/openapi` → `internal/api/openapi`；更新 `api/admin`、`api/dsadmin`、
    契约测试与 `docs/architecture.md` 的引用。
13. `api/es2plus/handlers.go`（639 行）同包拆为
    `deps.go`/`routes.go`/`requests.go`/`decode.go`/`errors.go`/`download_order.go`/
    `confirm_order.go`/`cancel_order.go`/`release_profile.go`/`acr.go`/`tenants.go`。
14. `internal/cli` 的 9 个 admin 命令 + 派发表 → `internal/cli/admin`；`cli` 保留 `Main`、
    顶层命令表、`listener.go`/`run.go`/`kmsload.go`/`smdpp*.go`/`smds.go`。
15. `api/admin` 内聚：SAIP 字段目录 + `annotateSchema` → `internal/uppinspect`；
    `profileTimeline` → `service`；`batches.go` 复用 `Stats`；删除不可达 501 分支。
16. `store` 文件内聚：`stats.go` 的 `Stats` 方法回归各自聚合文件；
    内联模型统一到 `*_model.go`（纯搬移，不改语义）。

验证：每搬一个包/文件跑一次 `go build/vet/test`；`gofmt -l` 为空。

### 阶段 3：去重与接口收口（零行为变化）

17. `store`：泛型 `queryAll[T]`/`listPage[T]` 收敛 28 处行循环与 8 处分页样板；
    抽 `scanNotification`；`audit.go` 抽 `auditCols`。SQL 文本逐字保持。
18. 各 ES handler 包新增 `deps.go`：以窄接口替换 `*service.CMAE`（4 方法）、
    `*service.DSService`、`*service.EventService`、`*service.OrderService`、`*service.Inventory`、
    `*service.TenantResolver`；组合根传实现；加编译期断言（仿 `admin/deps.go:189`）。
19. `api/adminhttp.ReadJSON` 与 `api/common.ReadJSON` 语义统一（body 上限已由中间件统一）。
20. `client/es2p` 的包级 `atomic.Int64`（`clientlib.go:20`）改为 per-`Client` 字段。

验证：接口收口后 `cli` 仍能构造全部 handler；`go test ./...` 全绿。

### 阶段 4：文档对齐

21. `docs/architecture.md`：按新目录树更新「Packages」「Dependency direction」
    「Directory responsibilities」；修正失效断言（testutil 不进二进制——本轮修好后成立；
    service 测试全部用 fake——实际 6 个测试开真 SQLite；编译期仓库断言——实际只有 fake 有）。
22. 在本文档「执行记录」登记 §6 的行为缺陷清单与后续建议。

## 5. 验收标准

1. 每个提交：`go build ./... && go vet ./... && go test ./...` 全绿，`gofmt -l cmd internal` 为空。
2. `internal/archcheck` 的三条不变量成立：`testutil` 不进二进制、无向上依赖边、`bertlv` 单点引用。
3. 重复项归零：`hexUpper`/`HexUpper` 单一实现；`rsp.tlvBytes` 与 `testutil` 手写编码器消失；
   store 行循环/分页样板收敛为泛型助手。
4. `internal/api/*` 的 ES handler 依赖窄接口而非 `*service.X` 具体类型。
5. `internal/service` 不再 import `net/http`；`internal/cert` 不再 import `internal/config`。
6. `docs/architecture.md` 的包依赖声明与实际 `go list` 一致。

## 6. 本轮不执行（行为变更，需单独评审）

以下问题在分析中已确认，但修复会改变可观察行为，故本轮只登记：

| 位置 | 问题 | 为何不在本轮 |
|---|---|---|
| `store/pool.go:121` | 分配策略在 SQL 中，且 `Reserve` 是「选号+更新」单事务 | 拆开需要工作单元，否则引入并发双重分配（`pool_test.go` 的 200 并发测试会失守） |
| `store/upp.go:126` | 版本排序在 SQL，`saipver.Max` 在 repo 内 | 同上，改动即改选择语义 |
| `store/tx.go:20` | 无跨聚合工作单元，service 手写补偿（`inventory.go:198,238`） | 事务边界即行为 |
| `store/upp.go:41`、`pool.go:320`、`personalization.go:85` | 多步写无事务 / look-then-update 竞态 | 收进事务会改变失败时的可观察状态 |
| `store/callback.go:219` | `Requeue` 读后无条件写，并发重复 | 改为条件更新即行为变更 |
| `cli/admin_db.go:136` | `rekey` 漏 `personalization` 的 `K`/`OPc`、非事务、静默跳过坏行 | 修复会改变 KEK 轮换的可观察结果 |
| `api/es12/handlers.go:71` | 未校验 §6.5.1.3 强制 header | 会开始拒绝此前接受的请求 |
| `internal/audit/audit.go:42` | `audit.sink` 取值未校验，非法值静默关闭审计 | 会开始在启动期失败 |
| `internal/config/env.go` + `setDefaults` | 不在 defaults/YAML 的键，`RSP42_*` 环境变量静默失效 | 会改变配置生效结果 |
| `store/sqlite.go:49` | `SetMaxOpenConns(1)` 串行化读；WAL/busy_timeout 仅在配置默认值 | 并发/持久化行为 |
| `saip/validate.go`+`filevalidate.go`+`constraints.go` | 同一条 Annex-A 规则分散三文件，`shortEFID` 校验两次 | 合并会改变校验顺序与报错集合 |
| `saip/personalization/csv.go:33` | 领域包在请求路径上 `os.Open` | 需先定义新的 ingestion 边界 |
| `store/migrations/00008:47` | `iccid_pool.imsi` 死列 | schema 变更 |
| `api/es2plus/handlers.go:~500` | ACR 不可用时 501 纯文本，非 SGP.22 信封 | wire 行为 |

## 7. 执行记录

| 阶段 | 提交 | 状态 |
|---|---|---|
| 0 护栏 | — | 待开始 |
| 1 机械搬移 | — | 待开始 |
| 2 包边界 | — | 待开始 |
| 3 去重与接口 | — | 待开始 |
| 4 文档对齐 | — | 待开始 |
