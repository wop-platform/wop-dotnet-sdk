# 贡献指南（CONTRIBUTING）

感谢参与 **WOP 商户官方 .NET SDK**（`Wop.Sdk`）的开发！本仓库是 WOP 网关商户侧官方客户端库，
实现对齐 [WOP SDK 规格 v1.0-ratified](https://github.com/wop-platform/gtsp-wop-gateway/blob/main/docs/wop-sdk-spec.md)（功能面 F1–F9、验收 A1–A7、工程约定 §4）。
协议核心（套件解析、canonicalRequest、结构化签名、content-digest、L2 数字信封、验签解密）与 HttpClient 适配层均在 98% 覆盖率门禁之内。

## 1. 开发环境

| 项 | 要求 |
|----|------|
| .NET SDK | **8.0.x**（CI 与本地一致；`netstandard2.0` 目标的引用程序集由 `Microsoft.NETFramework.ReferenceAssemblies` 自动补齐） |
| 目标框架 | `net8.0` + `netstandard2.0` 多目标（`src/Wop.Sdk/Wop.Sdk.csproj`） |
| 密码依赖 | [BouncyCastle.Cryptography](https://www.nuget.org/packages/BouncyCastle.Cryptography) 2.5.1（唯一指定路径，E5；禁止引入其他密码库） |
| 测试栈 | xUnit 2.9.2 + Microsoft.NET.Test.Sdk 17.11.1 + coverlet.msbuild 6.0.2 |
| 解决方案 | 根目录 `Wop.Sdk.sln`（`src/Wop.Sdk` + `tests/Wop.Sdk.Tests`） |

本地若 dotnet 不在 PATH（macOS/Linux 默认安装路径），先执行：

```bash
export PATH="$HOME/.dotnet:$PATH"
```

## 2. 构建与测试

命令与 `.github/workflows/ci.yml` **逐字一致**（CI 即唯一真源，勿凭记忆写命令）：

```bash
# ① 还原
dotnet restore

# ② 构建（零警告容忍：-warnaserror + csproj 内 TreatWarningsAsErrors）
dotnet build --no-restore -warnaserror

# ③ 测试 + 覆盖率门禁（行 & 分支双阈值）
dotnet test --no-build \
  /p:CollectCoverage=true \
  /p:Threshold=98 \
  /p:ThresholdType=both \
  /p:CoverletOutputFormat=opencover
```

- **覆盖率门禁**：coverlet 按 `ThresholdType=both` 同时校验**行覆盖率与分支覆盖率**，任一低于 **98%** 即测试步骤失败；工作目标为 100%。
- **警告即错误**：任何编译警告都会使构建失败，提交前先本地跑通上述三步。
- 覆盖率闭合必须在**全部语义变更之后**做终局测量——中途达标的数字会被后续分支稀释。

## 3. 黄金向量纪律（不可妥协）

`tests/Wop.Sdk.Tests/fixtures/crypto-vectors.json` 是与网关 CI 同源的黄金向量副本，是**协议正确性的唯一锚点，禁止手改**。

- 正向量必须**字节级**一致：digest、AES-256-GCM / SM4-GCM（固定 key/iv）、RSA3072/4096 签名、SM2 签名与加密、OAEP 解包、SM2 解密。
- 负向量必须全部拒绝：tamper、63/65 字节签名、带 `=` 的 base64url、跨族 digest/dek、C1C2C3 顺序密文、MGF1-SHA1 陷阱（OAEP 显式双 SHA-256 钉子）、DER 签名、off-curve 公钥点。
- **新增协议行为**：必须先在网关真源（`gtsp-wop-gateway`）更新向量并重新导出 fixture 副本，再同步本仓全量消费测试；不允许为迁就实现反向修向量。
- 拒绝行为（负向量）也要有测试钉住——"拒绝"本身是契约。

## 4. 编码规范

C# 惯例（本仓已定型，沿用勿另起炉灶）：

- `Nullable` enable、`ImplicitUsings` disable、`LangVersion latest`、`TreatWarningsAsErrors` true。
- 多目标代码用 `#if` 条件编译隔离，polyfill 收敛在 `src/Wop.Sdk/Compatibility/`（参考 `Polyfills.cs`、`KvpDeconstruct.cs`），不散落业务文件。
- 测试经 `InternalsVisibleTo Include="Wop.Sdk.Tests"` 触达内部类型；公共 API 面保持最小。
- 命名与包内一致性优先：类型名对齐概念 API（`WopClient` / `RequestDraft` / `VerifyResult` 等）。

对齐 spec 功能面（改动即回归对应测试）：

| 面 | 要求 |
|----|------|
| F1 套件 | 三套件解析与跨族/非法拒绝 |
| F2 canonicalRequest | 5 段 `\n`；header 值 Java-URLEncoder 语义（空格→`%20`） |
| F3 结构化签名 | 出向商户私钥加签；响应与回调平台公钥验签 |
| F4 content-digest | `alg 小写hex` 恰一空格；算法随套件族；无 body 头缺席（D2），有 body 必传必入签 |
| F5 L2 数字信封 | AES-256-GCM / SM4-GCM；DEK 载荷 `alg$key$iv`；RSA-OAEP（双 SHA-256 + 空 label）/ SM2(C1C3C2) |
| F6 校验顺序 | 验签 → digest 复核 → DEK 解包 → alg 族比对 → bulk 解密，**顺序固定** |
| F7 字节格式 | base64url 无填充（拒收 `=`）；SM2 签名裸 r‖s 64B；SM2 密文 C1C3C2；十六进制一律小写（D10） |
| F9 防重放 | CSPRNG nonce、毫秒时间戳、expiredSeconds 组装 |
| I7 错误模糊 | 配置/解析类错误**明确**（`CONFIG`/`SUITE_PARSE`/`SUITE_UNSUPPORTED`/`PROTOCOL`/`DIGEST_MISMATCH`/`ALG_MISMATCH`）；验签失败 `VERIFY_FAILED`、解密失败 `DECRYPT_FAILED` 对外文案钉死不区分原因（防 oracle） |

## 5. 提交规范

Conventional Commits，正文（body）用中文：

```
feat(transport): 新增连接池生命周期配置

- SocketsHttpHandler PooledConnectionLifetime 可配置
- 补充连接复用边界测试
```

类型限定：`feat` / `fix` / `test` / `docs` / `chore`（协议行为变更用 `feat` 或 `fix`，并在 body 指明对应功能面编号，如 "F6"）。

## 6. PR 流程

1. 基于最新 `main` 创建分支，提交 PR 到 `main`。
2. CI 必须全绿：**构建零警告 + 行&分支覆盖率 ≥ 98% + 向量合规测试全绿**——三项缺一不可，不合并红灯 PR。
3. 至少一名 reviewer 复核通过；涉及协议核心（`src/Wop.Sdk` 下签名/digest/信封/校验顺序）的变更必须说明对应 spec 条款与测试锚点。
4. 触碰 fixture 的 PR 一律拒绝（见 §3）。

## 7. 发布流程

- 版本号遵循 SemVer。发布 = 打 tag `vX.Y.Z` 并推送，触发 [.github/workflows/release.yml](.github/workflows/release.yml)：
  checkout → 装配 .NET 8 → 复用 CI 同款 restore/build/test（全绿才继续）→ `dotnet pack -c Release`（包版本取自 tag）→ `dotnet nuget push` 至 `https://api.nuget.org/v3/index.json`。
- NuGet API Key 通过 GitHub Secrets 的 `NUGET_TOKEN` 注入，**仓库内绝不出现明文凭证**。
- 发布步骤位于测试全绿之后：任何前置失败即中止，不留半发布状态。
- 包元数据（`PackageId` / `Description` / `PackageTags` / `PackageProjectUrl` 等）维护在 `src/Wop.Sdk/Wop.Sdk.csproj`。
