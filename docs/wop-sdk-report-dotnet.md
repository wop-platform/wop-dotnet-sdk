# wop-dotnet-sdk 交付报告

日期：2026-08-29 · 仓库：`github.com/wop-platform/wop-dotnet-sdk`（main，10 commits[含外部 2 条 docs]，未推送）

## 1. 交付物

- **解决方案** `Wop.Sdk.sln`：`src/Wop.Sdk`（**net8.0 + netstandard2.0 多目标**）+ `tests/Wop.Sdk.Tests`（net8.0，xUnit + coverlet.msbuild）
- **依赖白名单**：运行时仅 `BouncyCastle.Cryptography 2.5.1`（Portable.BouncyCastle 后继包）；`System.Memory` 仅 netstandard2.0 目标的编译期补充；测试栈 xUnit/Microsoft.NET.Test.Sdk/coverlet.msbuild 常规
- **协议核心**：suite 解析（F1 三套件 + 跨族/非法拒绝）、canonicalRequest（F2，Java-URLEncoder 语义）、结构化 x-wop-sign（F3）、x-wop-content-digest（F4/D2/I1/I5）、L2 数字信封（F5：AES/SM4-GCM ct‖tag + OAEP 显式双 SHA-256 空 label / SM2 C1C3C2 裸拼）、F6 顺序校验管线、I7 模糊化、F9（CSPRNG nonce/毫秒时间戳/expiredSeconds）
- **API**：`WopClient.Builder().AppKey().Suite().MerchantPrivateKey().PlatformPublicKey()...Build()`；`BuildRequest/VerifyResponse/VerifyCallback/Execute`；`RequestDraft/VerifyResult/WopException(WopErrorCode)`
- **Transport**：`IWopTransport` + `HttpClientTransport`（`HttpMessageHandler`/`HttpClient`/baseUrl 三构造，DelegatingHandler 可插拔；流式限额 11MB、ResponseHeadersRead 防双缓冲）
- 密钥分发契约 D12：RSA SPKI/PKCS8（Base64/PEM）、SM2 `04‖X‖Y` 65B（on-curve 前置守卫）/ d 32B 标量
- 工程：中文默认 `README.md` + `README.en.md`（四段：快速开始/密钥准备/L0+L2/向量自测）、MIT `LICENSE`、`.github/workflows/ci.yml`（dotnet 8 + `-warnaserror` + 覆盖率门禁 98 行+分支）、`.gitignore`、conventional commits ×8

## 2. 关键技术决策（BC C# 与 Java/Go BC 的行为差异，均已实证）

| # | 差异 | 决策 |
|---|------|------|
| 1 | C# BC `SM2Signer` 默认输出 DER 71B | 构造 `new SM2Signer(PlainDsaEncoding.Instance, new SM3Digest())`（注意 C# 参数顺序与 Java 相反：encoding 在前）拿裸 r‖s 64B（D9） |
| 2 | C# BC `BigInteger(bitLength, Random)` 经 `Random.NextBytes(Span<byte>)` 采样（非 byte[] 重载） | `FixedScalarRandom : SecureRandom` 同时覆写两个 `NextBytes` 重载，以 I2OSP 左补零语义填充 → fixed-k 字节级产出对齐向量（sign/encrypt 双向实证） |
| 3 | C# BC `ECCurve.DecodePoint`/`ECPublicKeyParameters` 强制 on-curve 校验（Java/Go 不校验） | 不绕过——该行为正是 I5 曲线守卫的免费实现；负测试：off-curve 65B 点/错前缀/63B/66B/坐标≥p 全部配置类明确拒绝 |
| 4 | 任务书"63B 签名"负向量 | 定长前置校验（384/512/64B）先于族路由，63/65B 与 DER（0x30 开头 70B）均前置拒绝 |

## 3. 验收自证（原文粘贴）

### 3.1 全量测试绿（含向量 conformance）

```
$ dotnet test /p:CollectCoverage=true /p:Threshold=98 /p:ThresholdType=both
Test run for .../Wop.Sdk.Tests/bin/Debug/net8.0/Wop.Sdk.Tests.dll (.NETCoreApp,Version=v8.0)
A total of 1 test files matched the specified pattern.

Passed!  - Failed:     0, Passed:   266, Skipped:     0, Total:   266, Duration: 528 ms - Wop.Sdk.Tests.dll (net8.0)
```

266 个测试含：`VectorConformanceTests`（fixture 全量 23 条向量 + 完整性哨兵）、`InvariantsTests`（I1–I7 每条不变式至少一个负向量）、`WopClientTests`（F6 顺序/I2/I3/I7/D2/tamper/回调/L2 往返）、`TransportTests`（自定义 Handler 无网络/上限/错误注入）、`CoverageCloseTests`（分支闭合）。

### 3.2 覆盖率报告原文（行 + 分支，门禁 98 双指标通过）

```
  [coverlet]
  Calculating coverage result...
   Generating report '.../tests/Wop.Sdk.Tests/coverage.json'

+---------+--------+--------+--------+
| Module  | Line   | Branch | Method |
+---------+--------+--------+--------+
| Wop.Sdk | 99.37% | 98.98% | 95.45% |
+---------+--------+--------+--------+

+---------+--------+--------+--------+
|         | Line   | Branch | Method |
+---------+--------+--------+--------+
| Total   | 99.37% | 98.98% | 95.45% |
+---------+--------+--------+--------+
| Average | 99.37% | 98.98% | 95.45% |
+---------+--------+--------+--------+
```

> 终局测量于全部语义变更之后（含传输层流式限额修正）；net8.0 目标实测，netstandard2.0 同源构建 0 警告（`dotnet build -warnaserror` 0 warning/error）。

### 3.3 README 双语存在性

```
$ ls README.md README.en.md LICENSE .github/workflows/ci.yml tests/Wop.Sdk.Tests/fixtures/crypto-vectors.json
.github/workflows/ci.yml
LICENSE
README.en.md
README.md
tests/Wop.Sdk.Tests/fixtures/crypto-vectors.json
```

### 3.4 git log（conventional commits，未推送）

```
a489298 fix(codec): base64url 非规范尾随位显式校验（与 Go RawURLEncoding.Strict() 对拍一致）+ 信封 SkipValue 字符串感知（串内结构字符不参与边界判定）
7c81aec docs: 中文默认 README + 英文 README（快速开始/密钥准备 D12/L0+L2/向量自测四段）、MIT LICENSE、GitHub Actions CI（dotnet 8 + 覆盖率门禁）
cdc7ff2 test(coverage): 分支闭合至 99.37% 行/98.98% 分支（可达分支全测 + 删不可达防御代码 + 传输层流式限额修正）
5cacbbd feat(client): WopClient 门面（Builder/BuildRequest/VerifyResponse/VerifyCallback/Execute + F6 管线）与 HttpClientTransport（DelegatingHandler 可插拔）
b5b33d2 test(vectors): 黄金向量 conformance 总套件（digest/messageEncrypt/signature/keyEncrypt/dekPayload/formatRules 全量 + 负向量锚点）
ff7f1c0 feat(crypto): 密钥解析（D12 契约 + I5 曲线守卫）与密码层（RSA/SM2 签名、AES/SM4-GCM、OAEP/SM2 C1C3C2 DEK 包装、fixed-k 向量钩子）
7dd1376 feat(protocol): canonicalRequest、结构化 x-wop-sign、content-digest（D2/I5）、L2 信封/加密指令头、DEK 载荷解析
8d37e40 feat(core): Codec（base64url 严格/小写hex/TrimAll/URLEncoder 语义）、AlgorithmSuite（F1 套件解析与四维推导）、WopException（I7 模糊错误模型）
530a7df chore: 初始化解决方案脚手架（net8.0+netstandard2.0、xUnit+coverlet、向量 fixture 副本）
```

## 4. spec 条款 → 测试反向核对矩阵

| 条款 | 测试锚点 |
|------|----------|
| D2 无 body 缺席 / 有 body 必产必入签 | `BuildRequest_无body_digest缺席`、`I1_digest未入签_即使签名本身有效也拒绝`、`VerifyResponse_有body缺digest头_明确拒绝`、`VerifyResponse_无body无digest_合法通过` |
| D2 值结构（恰一空格/小写/64hex） | `Parse_结构非法_协议类拒绝` ×8、`FormatRules_全量`（header-double-space / uppercase-hex / wrong-hex-len） |
| D9 SM2 三钉 | `Signature_SM2_fixedK_产出字节级一致`（86 字符）、`Signature_DER编码_负向量拒绝`、`KeyEncrypt_C1C2C3顺序_负向量必须拒绝` |
| D10 OAEP 双 SHA-256 | `KeyEncrypt_MGF1SHA1陷阱_负向量必须拒绝` |
| D10 小写 hex / tag 尾拼 / 严格 b64url | `LowerHex_小写无连字符`、`MessageEncrypt_AES/SM4_向量字节级一致`、`DecodeB64Url_负向量必须拒绝`、`FormatRules`（b64url-with-padding / illegal-char） |
| D12 密钥格式 | `KeyCodecTests` ×21（SPKI/PKCS8/PEM/位数强校验/SM2 65B/d 范围/dG=公钥交叉验证） |
| I1 digest 入签 | `I1_digest未入签…`（spec §10.1：即使签名本身有效也拒） |
| I2 先验签后解密 | `I2_验签失败时报DecryptFailed绝不可能`（L2 + 坏签名 → 恒 VERIFY_FAILED） |
| I3 alg 比对在 bulk 前 | `I3_跨族DEK_拒绝码为AlgMismatch非DecryptFailed`、`VerifyResponse_dekAlg跨族_AlgMismatch_I3` |
| I4 IV 生成点唯一 | `I4_两次出站IV必不相同` + `SealEnvelope` 内单一生成点（代码结构） |
| I5 族互斥三处 | suite：`Parse_非法组合支持类拒绝`；digest 标签：`I5_跨族digest标签_值正确也拒绝`；dek alg：见 I3；曲线守卫：`ParseSm2PublicKey_非法点_配置类拒绝` ×5 |
| I6 原子装配 | `Builder_未配置套件/密钥…`（缺件即拒，无半装配窗口） |
| I7 模糊化 | `I7_模糊文案唯一`、`Signature_tamper_负向量模糊拒绝`、`VerifyResponse_验签失败_模糊且先于解密_I2_I7`（断言固定文案"签名验证失败"/"解密失败"） |
| F6 顺序 | `WopClientTests.VerifyResponse_*` 系列按管线步骤逐层断言（结构前置→验签→digest→解包→族比对→bulk） |
| F7 定长前置 | `Signature_63B_65B_负向量定长前置拒绝` |
| A1/A2 向量字节级 | `VectorConformanceTests` ×20（fixture 哨兵防漂移） |
| F6 严格 base64url（非规范尾随位，与 Go Strict 对拍 7/7） | `DecodeB64Url_非规范尾随位_拒绝` ×3 + `DecodeB64Url_规范尾随位_接受` ×4 |
| 信封容忍未知字段（串内结构字符） | `Envelope_未知字段内结构字符_不误判` ×4 |

## 5. 与其他语言 SDK 的一致性

- 协议常量、canonicalRequest、sign 头格式、F6 顺序、错误分类与文案逐一对齐 Go 版参考实现（`wop-go-sdk`）；差异仅在 .NET 惯用映射（Builder 模式、enum ErrorCode、`IReadOnlyDictionary` 头集合）
- SM2 签名 ZA 的 userId `1234567812345678` 与向量/网关一致；fixed-k 产出与 gateway 向量（`CryptoVectorConformanceTest` 生成的 expectedSigB64u / cipherB64u）**逐字节相等**
- 排除手抄事故：测试一律从 fixture JSON 读取密钥/向量，无硬编码密码材料（开发中两次手抄 typo——公钥 P/Z 与 `\x0Bb` C# 贪婪转义——均已定位为测试侧输入错误并根除该模式）

## 6. 交付后增补（2026-08-29 下午）

- **base64url 非规范尾随位**升格为 spec 层向量（gateway commit 18836a2，formatRules 8→12）；本仓同步消费 4 条新向量（`b9ef340`）：noncanonical 拒 + canonical 字节级断言（`AA`→0x00、`TWE`→"Ma"），与 Go `RawURLEncoding.Strict()` 对拍 7/7。
- **RFC 8259 转义集补全**（`8aba297`）：`ReadString` 支持 `\uXXXX`（含代理对），修复 .NET `System.Text.Json` 默认序列化非 ASCII 场景的互操作拒收；键名转义语义等价（`"\u0065ncrypted"` 即 `encrypted`）有测试钉死。
- 终局门禁（全部变更后）：**272 全绿，99.2% 行 / 98.82% 分支**（Threshold=98 双指标通过）。
- 六仓横向审查（含本仓第三方复核）见 `/tmp/wop-sdk-audit-cross-lang.md`：本仓无残留缺口；Java/TS/Python/PHP 四仓尾随位宽容（PHP 尚被测试固化）+ 传输层限额缺失 + fixture 静默滞后；PHP 另有 L2 信封协议形态缺失（双向裸密文，无法与真实网关 L2 互通）。

## 7. 遗留与建议

- 未推送（按任务书）；CI 待 GitHub 远端启用后首跑
- `dotnet pack` 打包元数据已在 csproj（0.1.0 / MIT / wop-platform），发布流程另行处理
- netstandard2.0 目标已通过 0 警告构建；其运行时路径未在 netstandard2.0 宿主单独跑过测试套件（测试项目单 net8.0，与 Go 单目标等价），如需 NET Framework 4.6.1+/netstandard2.0 宿主矩阵可在 CI 增 job
