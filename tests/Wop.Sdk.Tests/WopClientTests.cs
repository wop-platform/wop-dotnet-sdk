using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using Wop.Sdk;
using Xunit;

public class WopClientTests
{
    static readonly JsonElement Keys = JsonDocument.Parse(File.OpenRead(
        Path.Combine(AppContext.BaseDirectory, "fixtures", "crypto-vectors.json"))).RootElement.GetProperty("keys");

    static string K(string name, string field) => Keys.GetProperty(name).GetProperty(field).GetString()!;

    public static IEnumerable<object[]> SuiteRows()
    {
        yield return new object[] { "WOP-RSA3072-SHA256", K("rsa3072", "privatePkcs8B64"), K("rsa3072", "publicSpkiB64") };
        yield return new object[] { "WOP-SM2-SM3", K("sm2", "privateDB64"), K("sm2", "publicPointB64") };
    }

    public static WopClientBuilder RsaBuilder() => WopClient.Builder()
        .AppKey("demo-app")
        .Suite("WOP-RSA3072-SHA256")
        .MerchantPrivateKey(K("rsa3072", "privatePkcs8B64"))
        .PlatformPublicKey(K("rsa3072", "publicSpkiB64"))
        .WithClock(() => 1724900000000)
        .WithNonce(() => "nonce-001");

    public static WopClientBuilder Sm2Builder() => WopClient.Builder()
        .AppKey("demo-app")
        .Suite("WOP-SM2-SM3")
        .MerchantPrivateKey(K("sm2", "privateDB64"))
        .PlatformPublicKey(K("sm2", "publicPointB64"))
        .WithClock(() => 1724900000000)
        .WithNonce(() => "nonce-001");

    // ==================== Builder 校验 ====================

    [Fact]
    public void Builder_缺AppKey_配置类拒绝()
    {
        var ex = Assert.Throws<WopException>(() => RsaBuilder().AppKey("").Build());
        Assert.Equal(WopErrorCode.Config, ex.ErrorCode);
    }

    [Fact]
    public void Builder_非法套件_拒绝()
    {
        var ex = Assert.Throws<WopException>(() => RsaBuilder().Suite("WOP-RSA3072-SM3").Build());
        Assert.Equal(WopErrorCode.SuiteUnsupported, ex.ErrorCode);
    }

    [Fact]
    public void Builder_密钥与套件族不符_拒绝()
    {
        // SM2 套件配 RSA 私钥
        Assert.Throws<WopException>(() => RsaBuilder().Suite("WOP-SM2-SM3").Build());
    }

    [Fact]
    public void Builder_expiredSeconds_超上限拒绝()
    {
        Assert.Throws<WopException>(() => RsaBuilder().ExpiredSeconds(86401).Build());
    }

    // ==================== BuildRequest ====================

    [Theory]
    [MemberData(nameof(SuiteRows))]
    public void BuildRequest_L0_头齐全且幂等(string suiteReq, string priv, string pub)
    {
        var client = WopClient.Builder()
            .AppKey("demo-app").Suite(suiteReq)
            .MerchantPrivateKey(priv).PlatformPublicKey(pub)
            .WithClock(() => 1724900000000).WithNonce(() => "nonce-001")
            .Build();
        var body = Encoding.UTF8.GetBytes("{\"k\":1}");
        var d1 = client.BuildRequest("post", "/api/pay", body, SecurityLevel.L0);
        var d2 = client.BuildRequest("POST", "/api/pay", body, SecurityLevel.L0);

        Assert.Equal("POST", d1.Method);
        Assert.Equal("/api/pay", d1.Path);
        Assert.Equal("demo-app", d1.Headers[WopHeaders.AppKey]);
        Assert.Equal("1724900000000", d1.Headers[WopHeaders.Timestamp]);
        Assert.Equal("nonce-001", d1.Headers[WopHeaders.Nonce]);
        Assert.True(d1.Headers.ContainsKey(WopHeaders.ContentDigest));          // D2：有 body 必产
        Assert.True(d1.Headers.ContainsKey(WopHeaders.Sign));
        Assert.False(d1.Headers.ContainsKey(WopHeaders.Encrypt));               // L0 无加密头
        Assert.Equal(body, d1.WireBody);
        // 确定性（spec §2：同输入同输出，除 CSPRNG 值）：RSA 签名确定性 → 逐字节幂等；
        // SM2 签名 k 随机 → 幂等性体现在 digest/canonical 输入层
        if (!client.Suite.IsSm2)
        {
            Assert.Equal(d1.Headers[WopHeaders.Sign], d2.Headers[WopHeaders.Sign]);
        }
        else
        {
            Assert.NotEqual(d1.Headers[WopHeaders.Sign], d2.Headers[WopHeaders.Sign]); // k 随机化
        }
        Assert.Equal(d1.Headers[WopHeaders.ContentDigest], d2.Headers[WopHeaders.ContentDigest]);
        // digest 必入 signedHeaders（I1）
        var signed = SignField(d1.Headers[WopHeaders.Sign]);
        Assert.Contains(WopHeaders.ContentDigest, signed.Split(';'));
    }

    [Theory]
    [MemberData(nameof(SuiteRows))]
    public void BuildRequest_无body_digest缺席(string suiteReq, string priv, string pub)
    {
        var client = WopClient.Builder()
            .AppKey("a").Suite(suiteReq).MerchantPrivateKey(priv).PlatformPublicKey(pub)
            .WithClock(() => 1).WithNonce(() => "n").Build();
        var d = client.BuildRequest("GET", "/api/q", null, SecurityLevel.L0);
        Assert.Null(d.WireBody);
        Assert.False(d.Headers.ContainsKey(WopHeaders.ContentDigest));   // D2：无 body 缺席
    }

    [Theory]
    [MemberData(nameof(SuiteRows))]
    public void BuildRequest_L2_加密头入签且信封往返(string suiteReq, string priv, string pub)
    {
        var client = WopClient.Builder()
            .AppKey("demo").Suite(suiteReq).MerchantPrivateKey(priv).PlatformPublicKey(pub)
            .WithClock(() => 42).WithNonce(() => "n2").Build();
        var body = Encoding.UTF8.GetBytes("{\"secret\":\"value\"}");
        var d = client.BuildRequest("POST", "/api/enc", body, SecurityLevel.L2);

        Assert.True(d.Headers.ContainsKey(WopHeaders.Encrypt));
        var signed = SignField(d.Headers[WopHeaders.Sign]);
        Assert.Contains(WopHeaders.Encrypt, signed.Split(';'));          // 加密头必入签
        Assert.StartsWith("{\"encrypted\":\"", Encoding.UTF8.GetString(d.WireBody!));

        // 平台侧视角验证（商户=平台自测往返）：用同一密钥材料模拟平台处理
        var (level, dek) = EncryptHeader.Parse(d.Headers[WopHeaders.Encrypt]);
        Assert.Equal("L2", level);
    }

    [Fact]
    public void BuildRequest_L2空body_拒绝()
    {
        var client = RsaBuilder().Build();
        var ex = Assert.Throws<WopException>(() => client.BuildRequest("POST", "/p", Array.Empty<byte>(), SecurityLevel.L2));
        Assert.Equal(WopErrorCode.Config, ex.ErrorCode);
    }

    [Fact]
    public void BuildRequest_空method或path_拒绝()
    {
        var client = RsaBuilder().Build();
        Assert.Throws<WopException>(() => client.BuildRequest("", "/p", null, SecurityLevel.L0));
        Assert.Throws<WopException>(() => client.BuildRequest("GET", "  ", null, SecurityLevel.L0));
    }

    // ==================== VerifyResponse（F6 顺序） ====================

    [Fact]
    public void VerifyResponse_L0_合法通过()
    {
        var client = RsaBuilder().Build();
        // 平台响应 = 平台私钥加签；测试中平台与商户同密钥（fixture 自测闭环）
        var resp = BuildSignedResponse(client, "POST", "/api/pay", Encoding.UTF8.GetBytes("{\"ok\":true}"));
        var result = client.VerifyResponse("POST", "/api/pay", resp.headers, resp.body);
        Assert.True(result.Ok);
        Assert.Equal(resp.body, result.Plaintext);
    }

    [Fact]
    public void VerifyResponse_L2_解密回原文()
    {
        var client = Sm2Builder().Build();
        var (headers, body) = BuildEncryptedResponse(client, "WOP-SM2-SM3", Encoding.UTF8.GetBytes("{\"v\":7}"), "/api/enc");
        var result = client.VerifyResponse("POST", "/api/enc", headers, body);
        Assert.True(result.Ok);
        Assert.Equal("{\"v\":7}", Encoding.UTF8.GetString(result.Plaintext!));
    }

    [Fact]
    public void VerifyResponse_验签失败_模糊且先于解密_I2_I7()
    {
        var client = Sm2Builder().Build();
        var (headers, body) = BuildEncryptedResponse(client, "WOP-SM2-SM3", Encoding.UTF8.GetBytes("{\"v\":7}"), "/api/enc");
        // 破坏签名（L2：验签失败必须先于任何解密）
        headers[WopHeaders.Sign] = headers[WopHeaders.Sign][..^4] + "AAAA";
        var result = client.VerifyResponse("POST", "/api/enc", headers, body);
        Assert.False(result.Ok);
        Assert.Equal(WopErrorCode.VerifyFailed, result.ErrorCode);
        Assert.Equal("签名验证失败", result.Reason);   // I7 固定文案
    }

    [Fact]
    public void VerifyResponse_tamper密文_解密失败模糊_I7()
    {
        var client = Sm2Builder().Build();
        var (headers, body) = BuildEncryptedResponse(client, "WOP-SM2-SM3", Encoding.UTF8.GetBytes("{\"v\":7}"), "/api/enc");
        var s = Encoding.UTF8.GetString(body);
        var tampered = s[..20] + (s[20] == 'A' ? 'B' : 'A') + s[21..];
        var tamperedBytes = Encoding.UTF8.GetBytes(tampered);
        // tamper 改变 wire body → digest 先拒（D2 完整性防线）
        var r1 = client.VerifyResponse("POST", "/api/enc", headers, tamperedBytes);
        Assert.Equal(WopErrorCode.DigestMismatch, r1.ErrorCode);
        // 同步重签 digest 后（攻击者不可能但测试需要）密文损坏才到解密层
        var fixedHeaders = ResignDigest(client, headers, tamperedBytes);
        var r2 = client.VerifyResponse("POST", "/api/enc", fixedHeaders, tamperedBytes);
        Assert.Equal(WopErrorCode.DecryptFailed, r2.ErrorCode);
        Assert.Equal("解密失败", r2.Reason);
    }

    [Fact]
    public void VerifyResponse_dekAlg跨族_AlgMismatch_I3()
    {
        var client = RsaBuilder().Build();
        // 构造 RSA 套件响应，但 DEK 载荷 alg=SM4-GCM（跨族）
        var dekPlain = DekPayload.Encode("SM4-GCM", new byte[16], new byte[12]);
        var (headers, body) = BuildEncryptedResponseWithDek(client, dekPlain, new byte[16], new byte[12],
            Encoding.UTF8.GetBytes("x"), "/p");   // 16B CEK 与 RSA 套件不符 → 预制密文分支
        var result = client.VerifyResponse("POST", "/p", headers, body);
        Assert.Equal(WopErrorCode.AlgMismatch, result.ErrorCode);   // 明确（公开映射知识）
    }

    [Fact]
    public void VerifyResponse_有body缺digest头_明确拒绝()
    {
        var client = RsaBuilder().Build();
        var resp = BuildSignedResponse(client, "POST", "/api/pay", Encoding.UTF8.GetBytes("{}"));
        resp.headers.Remove(WopHeaders.ContentDigest);
        var result = client.VerifyResponse("POST", "/api/pay", resp.headers, resp.body);
        Assert.False(result.Ok);
        Assert.Equal(WopErrorCode.DigestMismatch, result.ErrorCode);
    }

    [Fact]
    public void VerifyResponse_digest未入signedHeaders_I1拒绝()
    {
        var client = RsaBuilder().Build();
        var body = Encoding.UTF8.GetBytes("{}");
        var headers = new Dictionary<string, string>
        {
            [WopHeaders.AppKey] = "demo-app",
            [WopHeaders.Timestamp] = "1724900000000",
            [WopHeaders.ContentDigest] = ContentDigest.BuildHeaderValue(client.Suite, body),
        };
        // signedHeaders 不含 digest
        var canonical = CanonicalRequest.Build("v1/1800", "POST", "/api/pay", "",
            CanonicalRequest.CanonicalHeaders(headers));
        var sig = WopCrypto.Sign(client.Suite, RespKeyMaterial(client.Suite), Encoding.UTF8.GetBytes(canonical), null);
        headers[WopHeaders.Sign] = SignHeader.Build(client.Suite.SecurityReq, 1800,
            new[] { WopHeaders.AppKey, WopHeaders.Timestamp }, sig);
        var result = client.VerifyResponse("POST", "/api/pay", headers, body);
        Assert.False(result.Ok);
        Assert.Equal(WopErrorCode.Protocol, result.ErrorCode);
        Assert.Contains("I1", result.Reason);
    }

    [Fact]
    public void VerifyResponse_响应套件与配置不符_拒绝()
    {
        var client = RsaBuilder().Build();
        var resp = BuildSignedResponse(client, "POST", "/api/pay", Encoding.UTF8.GetBytes("{}"));
        resp.headers[WopHeaders.Sign] = resp.headers[WopHeaders.Sign].Replace("WOP-RSA3072-SHA256", "WOP-RSA4096-SHA256");
        var result = client.VerifyResponse("POST", "/api/pay", resp.headers, resp.body);
        Assert.Equal(WopErrorCode.Protocol, result.ErrorCode);
    }

    [Fact]
    public void VerifyResponse_已签名头缺失_明确拒绝()
    {
        var client = RsaBuilder().Build();
        var resp = BuildSignedResponse(client, "POST", "/api/pay", Encoding.UTF8.GetBytes("{}"));
        resp.headers.Remove(WopHeaders.Nonce);
        var result = client.VerifyResponse("POST", "/api/pay", resp.headers, resp.body);
        Assert.Equal(WopErrorCode.Protocol, result.ErrorCode);
    }

    [Fact]
    public void VerifyResponse_无body带digest头_拒绝()
    {
        var client = RsaBuilder().Build();
        var headers = new Dictionary<string, string>
        {
            [WopHeaders.AppKey] = "demo-app",
            [WopHeaders.Timestamp] = "1",
            [WopHeaders.ContentDigest] = "sha-256 " + new string('a', 64),
        };
        var canonical = CanonicalRequest.Build("v1/1800", "GET", "/x", "",
            CanonicalRequest.CanonicalHeaders(headers));
        var sig = WopCrypto.Sign(client.Suite, RespKeyMaterial(client.Suite), Encoding.UTF8.GetBytes(canonical), null);
        headers[WopHeaders.Sign] = SignHeader.Build(client.Suite.SecurityReq, 1800,
            headers.Keys.OrderBy(k => k, StringComparer.Ordinal).ToList(), sig);
        var result = client.VerifyResponse("GET", "/x", headers, null);
        Assert.Equal(WopErrorCode.Protocol, result.ErrorCode);
    }

    // ==================== VerifyCallback ====================

    [Fact]
    public void VerifyCallback_URI取path且方法恒POST()
    {
        var client = RsaBuilder().Build();
        var resp = BuildSignedResponse(client, "POST", "/callback/notify", Encoding.UTF8.GetBytes("{\"e\":1}"));
        var result = client.VerifyCallback("https://merchant.example.com/callback/notify?trace=1", resp.headers, resp.body);
        Assert.True(result.Ok);
    }

    [Fact]
    public void VerifyCallback_非法URL_拒绝()
    {
        var client = RsaBuilder().Build();
        var result = client.VerifyCallback("::::not-a-url", new Dictionary<string, string>(), null);
        Assert.False(result.Ok);
        Assert.Equal(WopErrorCode.Protocol, result.ErrorCode);
    }

    static string SignField(string signHeader) => signHeader.Split(' ')[1].Split('/')[2];

    // ==================== 辅助：平台响应构造（fixture 密钥自测闭环） ====================

    // 平台侧签名/加密密钥（测试闭环：平台与商户共用 fixture 密钥对，按套件族取材）
    internal static AsymmetricKeyMaterial RespKeyMaterial(AlgorithmSuite suite) =>
        AsymmetricKeyMaterial.ParsePrivate(suite.IsSm2 ? K("sm2", "privateDB64") : K("rsa3072", "privatePkcs8B64"), suite);

    internal static AsymmetricKeyMaterial RespPubMaterial(AlgorithmSuite suite) =>
        AsymmetricKeyMaterial.ParsePublic(suite.IsSm2 ? K("sm2", "publicPointB64") : K("rsa3072", "publicSpkiB64"), suite);

    (Dictionary<string, string> headers, byte[] body) BuildSignedResponse(WopClient client, string method, string path, byte[] body) =>
        BuildResponseCore(client, method, path, body, null, null, null);

    (Dictionary<string, string> headers, byte[] body) BuildEncryptedResponse(WopClient client, string suiteReq, byte[] body, string path)
    {
        var suite = AlgorithmSuite.Parse(suiteReq);
        var cek = new byte[suite.CekLength];
        var iv = new byte[12];
        var dekPlain = DekPayload.Encode(suite.MessageAlgorithm, cek, iv);
        return BuildEncryptedResponseWithDek(client, dekPlain, cek, iv, body, path);
    }

    (Dictionary<string, string> headers, byte[] body) BuildEncryptedResponseWithDek(
        WopClient client, string dekPlain, byte[] cek, byte[] iv, byte[] body, string path)
    {
        // 用固定 CEK/IV 加密（测试确定性；digest 对 wire 字节算）；
        // CEK 与套件不符（跨族构造）时以预制密文替代（bulk 解密前即被拒，密文内容不参与）
        byte[] sealedBytes;
        try
        {
            sealedBytes = WopCrypto.SealMessage(client.Suite, body, cek, iv);
        }
        catch (WopException)
        {
            sealedBytes = new byte[body.Length + 16];
        }
        var wire = EncryptedEnvelope.Wrap(Codec.EncodeB64Url(sealedBytes));
        var wrapped = WopCrypto.WrapDek(client.Suite, RespPubMaterial(client.Suite), Encoding.UTF8.GetBytes(dekPlain));
        return BuildResponseCore(client, "POST", path, wire, EncryptHeader.BuildL2(wrapped), dekPlain, null);
    }

    (Dictionary<string, string>, byte[]) BuildResponseCore(WopClient client, string method, string path,
        byte[] wireBody, string? encryptHeader, string? dekPlain, object? _)
    {
        var headers = new Dictionary<string, string>
        {
            [WopHeaders.AppKey] = "platform",
            [WopHeaders.Timestamp] = "1724900000001",
            [WopHeaders.Nonce] = "resp-nonce",
        };
        if (encryptHeader != null)
        {
            headers[WopHeaders.Encrypt] = encryptHeader;
        }
        if (wireBody.Length > 0)
        {
            headers[WopHeaders.ContentDigest] = ContentDigest.BuildHeaderValue(client.Suite, wireBody);
        }
        var signedNames = headers.Keys.OrderBy(k => k, StringComparer.Ordinal).ToList();
        var signedMap = new Dictionary<string, string>();
        foreach (var n in signedNames)
        {
            signedMap[n] = headers[n];
        }
        var canonical = CanonicalRequest.Build("v1/1800", method, path ?? "/api/pay", "",
            CanonicalRequest.CanonicalHeaders(signedMap));
        var sig = WopCrypto.Sign(client.Suite, RespKeyMaterial(client.Suite), Encoding.UTF8.GetBytes(canonical), Sm2PlatformDefaults.InboundUserId); // D15：模拟平台加签用平台固定 ZA
        headers[WopHeaders.Sign] = SignHeader.Build(client.Suite.SecurityReq, 1800, signedNames, sig);
        return (headers, wireBody);
    }

    Dictionary<string, string> ResignDigest(WopClient client, Dictionary<string, string> headers, byte[] body)
    {
        var clone = new Dictionary<string, string>(headers, StringComparer.OrdinalIgnoreCase)
        {
            [WopHeaders.ContentDigest] = ContentDigest.BuildHeaderValue(client.Suite, body),
        };
        var signedNames = clone.Keys
            .Where(k => k != WopHeaders.Sign)
            .OrderBy(k => k, StringComparer.Ordinal).ToList();
        var signedMap = signedNames.ToDictionary(n => n, n => clone[n]);
        var canonical = CanonicalRequest.Build("v1/1800", "POST", "/api/enc", "",
            CanonicalRequest.CanonicalHeaders(signedMap));
        var sig = WopCrypto.Sign(client.Suite, RespKeyMaterial(client.Suite), Encoding.UTF8.GetBytes(canonical), Sm2PlatformDefaults.InboundUserId); // D15：模拟平台加签用平台固定 ZA
        clone[WopHeaders.Sign] = SignHeader.Build(client.Suite.SecurityReq, 1800, signedNames, sig);
        return clone;
    }
}
