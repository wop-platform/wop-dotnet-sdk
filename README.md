# wop-dotnet-sdk

[![NuGet](https://img.shields.io/nuget/v/Wop.Sdk)](https://www.nuget.org/packages/Wop.Sdk/) [![Release](https://img.shields.io/github/v/release/wop-platform/wop-dotnet-sdk)](https://github.com/wop-platform/wop-dotnet-sdk/releases)
[![CI](https://github.com/wop-platform/wop-dotnet-sdk/actions/workflows/ci.yml/badge.svg)](https://github.com/wop-platform/wop-dotnet-sdk/actions/workflows/ci.yml) [![License: MIT](https://img.shields.io/github/license/wop-platform/wop-dotnet-sdk)](LICENSE)
[![.NET](https://img.shields.io/badge/.NET-net8.0%20%7C%20netstandard2.0-512BD4?logo=dotnet&logoColor=white)](https://dotnet.microsoft.com/) ![CodeRabbit Pull Request Reviews](https://img.shields.io/coderabbit/prs/github/wop-platform/wop-dotnet-sdk?utm_source=oss&utm_medium=github&utm_campaign=wop-platform%2Fwop-dotnet-sdk&labelColor=171717&color=FF570A&link=https%3A%2F%2Fcoderabbit.ai&label=CodeRabbit+Reviews)



WOP 网关商户侧官方 .NET SDK：封装协议核心（套件解析、canonicalRequest、结构化签名、
content-digest、L2 数字信封、验签解密）与 HttpClient 适配层，商户无需理解线上字节格式即可安全对接网关。

- 目标框架：`net8.0` + `netstandard2.0`（多目标）
- 密码依赖（唯一指定路径，E5）：[BouncyCastle.Cryptography](https://www.nuget.org/packages/BouncyCastle.Cryptography)（Portable.BouncyCastle 后继包）
- 算法套件（F1）：`WOP-RSA3072-SHA256` / `WOP-RSA4096-SHA256` / `WOP-SM2-SM3`（国密双套件全支持）
- 协议真源：[crypto-strategy-spec.md](https://github.com/wop-platform/wop-specs/blob/main/crypto/crypto-strategy-spec.md)（v0.3-reviewed）+ [wop-sdk-spec.md](https://github.com/wop-platform/wop-specs/blob/main/sdk/wop-sdk-spec.md)（v1.0-ratified）
- 向量真源：[crypto-vectors.json](https://github.com/wop-platform/wop-specs/blob/main/crypto/crypto-vectors.json)（本仓 fixture 为字节级副本，禁手改）

## 快速开始

```bash
dotnet add package Wop.Sdk   # 0.1.0（或源码引用 src/Wop.Sdk）
```

```csharp
using Wop.Sdk;

var client = WopClient.Builder()
    .AppKey("your-app-key")
    .Suite("WOP-RSA3072-SHA256")            // 或 WOP-SM2-SM3
    .MerchantPrivateKey(merchantPrivateKey)  // PEM 或 Base64 单行（D12）
    .PlatformPublicKey(platformPublicKey)
    .Build();

// ① 构造请求草稿（纯计算、零网络 IO；幂等——除 CSPRNG 值外同输入同输出）
RequestDraft draft = client.BuildRequest(
    "POST", "/api/v1/pay",
    Encoding.UTF8.GetBytes("{\"orderNo\":\"20260829001\",\"amount\":100}"),
    SecurityLevel.L0);                       // L0 明文 / L2 全文数字信封

// ② 自带 HTTP 栈：直接消费 draft.Headers / draft.WireBody
//    或使用 SDK 适配层（DelegatingHandler 可插拔）：
var transport = new HttpClientTransport(
    new SocketsHttpHandler { PooledConnectionLifetime = TimeSpan.FromMinutes(5) },
    "https://wop-gateway.example.com");
var (result, response) = client.Execute(transport, "POST", "/api/v1/pay", body, SecurityLevel.L0);
if (result.Ok)
{
    var plaintext = Encoding.UTF8.GetString(result.Plaintext!);
}
```

## 密钥准备（D12 分发契约）

密钥入参为字符串（PEM 或 Base64 单行），SDK 内部解析；解析失败返回配置类**明确**错误（帮助集成自查）。

| 套件 | 商户私钥 | 平台公钥 |
|------|----------|----------|
| `WOP-RSA3072-SHA256` | PKCS#8 DER（Base64/PEM），3072 位 | X.509 SubjectPublicKeyInfo DER（Base64/PEM） |
| `WOP-RSA4096-SHA256` | PKCS#8 DER，4096 位 | SPKI DER |
| `WOP-SM2-SM3` | d = 32 字节大端标量（Base64，范围 [1, n-1]） | 未压缩点 `04‖X‖Y` 共 65 字节（Base64，on-curve 校验前置） |

注意：
- RSA 密钥位数与套件声明强校验（3072/4096 不匹配即拒绝）。
- SM2 公钥点不在 sm2p256v1 曲线上直接拒绝（I5 曲线守卫）。
- .NET `BitConverter.ToString` 默认大写带连字符——本 SDK 全部十六进制统一**小写**（D10）。

## L0 + L2 示例

```csharp
// L0 明文：签名 + digest 完整性防线（digest 是 L0 唯一完整性防线，D2）
var l0 = client.BuildRequest("GET", "/api/v1/orders?status=PAID", null, SecurityLevel.L0);
// GET / 空 body：x-wop-content-digest 头缺席（不定义"空串的摘要"中间态）

// L2 全文数字信封：CSPRNG CEK + IV（I4：IV 生成点唯一，同一密钥下永不复用）
// → AES-256-GCM / SM4-GCM 全文加密（密文 = ciphertext‖tag 尾拼）
// → DEK 载荷 alg$key$iv 经 RSA-OAEP（显式双 SHA-256 + 空 label）/ SM2(C1C3C2) 包装
// → 线上体 {"encrypted":"<base64url>"}，指令头 x-wop-encrypt: L2;dek=<base64url>
var l2 = client.BuildRequest("POST", "/api/v1/transfer", secretBody, SecurityLevel.L2);

// 验证网关响应（F6 固定顺序：验签 → digest 复核 → DEK 解包 → alg 族比对 → bulk 解密）
VerifyResult r = client.VerifyResponse("POST", "/api/v1/transfer", responseHeaders, responseBody);

// 验证平台回调（canonical URI 取回调 URL 的 path，方法恒 POST）
VerifyResult c = client.VerifyCallback(callbackUrl, headersFromBody, rawBody);
```

错误处理（I7 模糊化纪律）：
- **明确**（可编程自查）：配置类 `CONFIG`、套件解析 `SUITE_PARSE`/`SUITE_UNSUPPORTED`、协议格式 `PROTOCOL`、
  摘要不匹配 `DIGEST_MISMATCH`、dek alg 跨族 `ALG_MISMATCH`
- **模糊**（防 oracle，文案钉死不区分原因细节）：验签失败 `VERIFY_FAILED`（"签名验证失败"）、
  解密失败 `DECRYPT_FAILED`（"解密失败"）——GCM tag 失败 / 密钥不符 / DEK 解包失败对外同句

## 向量自测（conformance）

测试消费与网关 CI 同一份黄金向量副本（`tests/Wop.Sdk.Tests/fixtures/crypto-vectors.json`，禁止手改）：

```bash
export PATH="$HOME/.dotnet:$PATH"
dotnet test /p:CollectCoverage=true /p:Threshold=98 '/p:ThresholdType="line,branch"'
```

覆盖面：
- 正向量**字节级**一致：digest、AES-256-GCM / SM4-GCM（固定 key/iv）、RSA3072/4096 签名、
  SM2 签名与加密（fixed-k 产出逐字节对齐向量）、OAEP 解包、SM2 解密
- 负向量全部拒绝：tamper、63/65B 签名、带 `=` 的 base64url、跨族 digest/dek、C1C2C3 顺序密文、
  MGF1-SHA1 陷阱（OAEP 双 SHA-256 钉子）、DER 签名、off-curve 公钥点
- 覆盖率门禁：行 + 分支 ≥ 98%
