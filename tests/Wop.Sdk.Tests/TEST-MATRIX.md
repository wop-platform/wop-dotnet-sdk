# WOP 商户 SDK 测试用例矩阵（.NET 仓）

> 交付日期：2026-08-29 · 依据：`wop-specs/sdk/wop-sdk-spec.md`（v1.0-ratified + 附录 D1–D5）
> 方法：从商户使用场景出发（网关定位 = 商户侧安全对接的协议核心封装），沿 F1–F9 功能面 ×
> 概念 API（BuildRequest / VerifyResponse / VerifyCallback / Execute）展开，
> 每个场景映射现有 xUnit 测试与 SpecFlow Gherkin 场景（feature 内 @tag 即 spec 条款号）。

## 1. 场景 × 用例矩阵

| # | 商户使用场景 | spec 条款 | 危险面（错则后果） | xUnit 锚点 | Gherkin 场景 |
|---|---|---|---|---|---|
| S1 | 商户选择国际套件 RSA3072/4096 接入 | F1 | 套件解析错 → 全链路算法漂移 | `AlgorithmSuiteTests`、`WopClientTests.Builder_*` | @F1 商户以 RSA3072 套件构建客户端 |
| S2 | 商户选择国密套件 SM2-SM3 接入（.NET 全支持，Q7） | F1 | 同上 + 国密路由错 | `SuiteRows` 双族 Theory ×全量 | @F1 商户以国密 SM2 套件构建客户端 |
| S3 | 商户配错套件/漏配密钥（明确报错可自查） | F1/I6 | 半装配状态 → 运行时才炸 | `Builder_非法套件_拒绝` 等 | @F1 非法套件组合被明确拒绝、@I6 缺少必填配置被原子拒绝 |
| S4 | 商户发 L0 POST（签名+摘要，body 必产 digest 且入签） | F2/F3/F4/I1 | digest 缺签 → 中间人换体不察 | `BuildRequest_L0_头齐全且幂等` | @F2 @F3 @F4 @I1 商户发起 L0 签名请求 digest 必产且入签 |
| S5 | 商户发 GET/空体（digest 必须缺席） | F4/D2 | 无 body 强造 digest → 网关拒收 | `BuildRequest_无body_digest缺席` | @F4 @D2 无 body 请求 digest 缺席 |
| S6 | 商户重试/重放同一请求（幂等，确定性） | §2 概念 API | 随机性泄漏到头 → 缓存/审计失效 | 同输入两次构建一致断言 | @F2 @F9 同输入请求幂等可重放 |
| S7 | 商户每次请求独立 nonce（防重放） | F9 | nonce 重复 → 重放检测失效 | `I4_两次出站IV必不相同` 等 | @F9 出站 nonce 每次不同 |
| S8 | 商户发敏感数据 L2 全文加密 | F5 | 信封/DEK 格式错 → 网关解不开 | `BuildRequest_L2_*`、向量 `MessageEncrypt/KeyEncrypt` | @F5 商户发起 L2 加密请求 |
| S9 | 商户校验平台 L0 响应（先验签后一切） | F6/I2 | 顺序错 → oracle/信息泄露 | `VerifyResponse_L0_合法通过` | @F6 @I2 商户校验平台 L0 响应通过 |
| S10 | 商户校验平台 L2 响应并解密 | F6/I3/D8 | alg 族比对在 bulk 解密前 | `VerifyResponse_L2_解密回原文` | @F6 @I3 商户校验平台 L2 响应并解密回原文 |
| S11 | 商户收到攻击者篡改签名的响应 | F6/I7 | 区分失败原因 → padding-oracle | `VerifyResponse_验签失败_模糊且先于解密` | @F6 @I7 商户拒收篡改签名的响应 |
| S12 | 商户收到被剥 digest 的有体响应 | F4/D2 | 缺完整性锚仍放行 | `VerifyResponse_有body缺digest头_明确拒绝` | @F4 @D2 商户拒收缺 digest 的有体响应 |
| S13 | 商户收到跨族 digest 标签响应 | I5 | 值正确但族不符 → 算法混搭 | `I5_跨族digest标签_值正确也拒绝` | @F6 @I5 商户拒收跨族 digest 标签 |
| S14 | 商户收到带 `=` 填充/非法字符签名的报文 | F7/D1 | 宽容解码 → 跨语言漂移 | `DecodeB64Url_负向量必须拒绝`、`FormatRules` | @F7 @D1 商户拒收带填充的 base64url 签名 |
| S15 | 商户接收平台异步回调（URI 取 path、恒 POST） | F6/§2 | canonical URI 取错 → 验签恒败 | `VerifyCallback_通过_取回调path去query` | @F6 商户校验平台回调通过 |
| S16 | 商户收到非法回调 URL | §2 | 崩溃而非明确拒绝 | `VerifyCallback_非法URL_拒绝`、根路径新增 | @F6 非法回调 URL 被明确拒绝 |
| S17 | 商户一站式调用（可插拔 transport / DelegatingHandler） | Q1/§1.1 | 传输耦合 → 无法接自有栈 | `Execute_*`、`TransportTests` | @Q1 商户一站式调用网关 |
| S18 | 商户跑向量自测确认 SDK 未被篡改 | F8/A1/A2 | 字节漂移 → 网关互通失败 | `VectorConformanceTests`（fixture 全量+哨兵） | —（fixture 属单测层，Gherkin 不重复） |
| S19 | 大响应体防失控读（11MB 流式限额） | D4 | 整体缓冲 → OOM | `Transport_超长流触发LimitStream断流` | — |
| S20 | 平台响应容忍未知字段/字符串感知边界 | D3 | 解析器误判 → 拒合法响应 | `Envelope_未知字段内结构字符_不误判` ×4 | — |

## 2. 矩阵覆盖完整性核对（条款 → 测试反向核对）

- F1 套件：S1–S3（含 TS/PHP 不适用项，.NET 双族全支持）
- F2 canonical：S4/S6（Java-URLEncoder 语义由 `CanonicalAndSignHeaderTests` + 向量钉死）
- F3 sign：S4/S11
- F4 digest：S4/S5/S12/S13
- F5 信封：S8/S10
- F6 入向管线：S9–S13/S15/S16
- F7 线上字节：S14（+ `VectorConformanceTests` 全量）
- F8 向量：S18
- F9 防重放：S6/S7
- D1 尾随位：S14（+ `TrailingBitAndSkipStringTests` 7/7 对拍 Go Strict）
- D2/D3/D4：S5/S12、S20、S19
- I1–I7：S4(I1)/S9(I2)/S10(I3)/I4(xUnit)/S13(I5)/I6(S3)/S11(I7)
- 概念 API 四入口：S4–S8（BuildRequest）、S9–S14（VerifyResponse）、S15/S16（VerifyCallback）、S17（Execute）
