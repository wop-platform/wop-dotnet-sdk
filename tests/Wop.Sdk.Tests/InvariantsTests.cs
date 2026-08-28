using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Wop.Sdk;
using Xunit;

/// <summary>协议不变式（spec §10.1）：每条至少一个负向量证明违反时 SDK 会拒绝/防护。</summary>
public class InvariantsTests
{
    static WopClient RsaClient() => WopClientTests.RsaBuilder().Build();
    static WopClient Sm2Client() => WopClientTests.Sm2Builder().Build();

    // I1：digest 必入 signedHeaders —— body 与签名之间唯一绑定桥梁
    [Fact]
    public void I1_digest未入签_即使签名本身有效也拒绝()
    {
        var client = RsaClient();
        var body = Encoding.UTF8.GetBytes("{\"a\":1}");
        var headers = new Dictionary<string, string>
        {
            [WopHeaders.AppKey] = "platform",
            [WopHeaders.Timestamp] = "1",
            [WopHeaders.Nonce] = "n",
            [WopHeaders.ContentDigest] = ContentDigest.BuildHeaderValue(client.Suite, body),
        };
        // 签名覆盖除 digest 外的头 —— 签名对被签内容有效，但 digest 被排除
        var signedNames = new[] { WopHeaders.AppKey, WopHeaders.Timestamp, WopHeaders.Nonce }.OrderBy(x => x, StringComparer.Ordinal).ToArray();
        var canonical = CanonicalRequest.Build("v1/1800", "POST", "/p", "",
            CanonicalRequest.CanonicalHeaders(signedNames.ToDictionary(n => n, n => headers[n])));
        var sig = WopCrypto.Sign(client.Suite, WopClientTests.RespKeyMaterial(client.Suite), Encoding.UTF8.GetBytes(canonical));
        headers[WopHeaders.Sign] = SignHeader.Build(client.Suite.SecurityReq, 1800, signedNames, sig);

        var result = client.VerifyResponse("POST", "/p", headers, body);
        Assert.False(result.Ok);
        Assert.Equal(WopErrorCode.Protocol, result.ErrorCode);
        Assert.Contains("I1", result.Reason);
    }

    // I2：先验签后解密 —— 验签失败的 L2 报文绝不触达解密路径
    [Fact]
    public void I2_验签失败时报DecryptFailed绝不可能()
    {
        var client = Sm2Client();
        var (headers, body) = new WopClientTests().BuildEncryptedResponsePublic(client,
            Encoding.UTF8.GetBytes("{\"v\":1}"), "/p");
        headers[WopHeaders.Sign] = "WOP-SM2-SM3 v1/1800/" +
            headers[WopHeaders.Sign].Split(' ')[1].Split('/')[2] + "/" +
            new string('A', 86);   // 破坏签名，其余不动
        var result = client.VerifyResponse("POST", "/p", headers, body);
        Assert.Equal(WopErrorCode.VerifyFailed, result.ErrorCode);
    }

    // I3：alg 族比对在 bulk 解密前 —— 跨族 DEK 拒绝错误码是一致性类而非解密类
    [Fact]
    public void I3_跨族DEK_拒绝码为AlgMismatch非DecryptFailed()
    {
        var client = RsaClient();
        var dek = DekPayload.Encode("SM4-GCM", new byte[16], new byte[12]);
        var (headers, body) = new WopClientTests().BuildEncryptedDekPublic(client, dek, new byte[64], "/p");
        var result = client.VerifyResponse("POST", "/p", headers, body);
        Assert.Equal(WopErrorCode.AlgMismatch, result.ErrorCode);
        Assert.DoesNotContain("tag", result.Reason!, StringComparison.OrdinalIgnoreCase);
    }

    // I4：出站 IV 生成点唯一 —— 同一 client 两次 L2 出站 IV 必不相同（CSPRNG 结构断言）
    [Fact]
    public void I4_两次出站IV必不相同()
    {
        var client = RsaClient();
        var body = Encoding.UTF8.GetBytes("{\"x\":1}");
        var d1 = client.BuildRequest("POST", "/p", body, SecurityLevel.L2);
        var d2 = client.BuildRequest("POST", "/p", body, SecurityLevel.L2);
        Assert.NotEqual(d1.Headers[WopHeaders.Encrypt], d2.Headers[WopHeaders.Encrypt]);
    }

    // I5：算法族互斥贯穿三处 —— securityReq / digest 标签 / dek alg（前两处已在套件与 digest 测试，
    // 此处补 dek alg 与 digest 标签的联动负向量）
    [Fact]
    public void I5_跨族digest标签_值正确也拒绝()
    {
        var client = RsaClient();
        var body = Encoding.UTF8.GetBytes("{}");
        // SM3 摘要（值真实正确）但标签 sm3 配 RSA 套件 → 跨族拒绝（I5）
        var sm2Suite = AlgorithmSuite.Parse("WOP-SM2-SM3");
        var sm3Value = "sm3 " + Codec.LowerHex(ContentDigest.Compute(sm2Suite, body));
        var headers = new Dictionary<string, string>
        {
            [WopHeaders.AppKey] = "platform",
            [WopHeaders.Timestamp] = "1",
            [WopHeaders.Nonce] = "n",
            [WopHeaders.ContentDigest] = sm3Value,
        };
        var signedNames = headers.Keys.OrderBy(k => k, StringComparer.Ordinal).ToList();
        var canonical = CanonicalRequest.Build("v1/1800", "POST", "/p", "",
            CanonicalRequest.CanonicalHeaders(signedNames.ToDictionary(n => n, n => headers[n])));
        var sig = WopCrypto.Sign(client.Suite, WopClientTests.RespKeyMaterial(client.Suite), Encoding.UTF8.GetBytes(canonical));
        headers[WopHeaders.Sign] = SignHeader.Build(client.Suite.SecurityReq, 1800, signedNames, sig);
        var result = client.VerifyResponse("POST", "/p", headers, body);
        Assert.Equal(WopErrorCode.Protocol, result.ErrorCode);
        Assert.Contains("族不符", result.Reason);
    }

    // I7：对外语义模糊化 —— 验签/解密失败仅两种固定文案
    [Theory]
    [InlineData(WopErrorCode.VerifyFailed, "签名验证失败")]
    [InlineData(WopErrorCode.DecryptFailed, "解密失败")]
    public void I7_模糊文案唯一(WopErrorCode code, string message)
    {
        var e = WopException.Fuzzy(code);
        Assert.Equal(message, e.Message);
        Assert.DoesNotContain("tag", e.Message, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("padding", e.Message, StringComparison.OrdinalIgnoreCase);
    }
}

// 供不变式测试构造响应的门面（测试闭环辅助）
public static class WopClientTestExtensions
{
    public static (Dictionary<string, string>, byte[]) BuildEncryptedResponsePublic(
        this WopClientTests tests, WopClient client, byte[] body, string path)
    {
        var suite = client.Suite;
        var cek = new byte[suite.CekLength];
        var iv = new byte[12];
        var dek = DekPayload.Encode(suite.MessageAlgorithm, cek, iv);
        return BuildEncryptedDekPublic(tests, client, dek,
            WopCrypto.SealMessage(suite, body, cek, iv), path);
    }

    public static (Dictionary<string, string>, byte[]) BuildEncryptedDekPublic(
        this WopClientTests tests, WopClient client, string dekPlain, byte[] cipher, string path)
    {
        var wire = EncryptedEnvelope.Wrap(Codec.EncodeB64Url(cipher));
        var wrapped = WopCrypto.WrapDek(client.Suite, WopClientTests.RespPubMaterial(client.Suite),
            Encoding.UTF8.GetBytes(dekPlain));
        var headers = new Dictionary<string, string>
        {
            [WopHeaders.AppKey] = "platform",
            [WopHeaders.Timestamp] = "1724900000001",
            [WopHeaders.Nonce] = "resp-nonce",
            [WopHeaders.Encrypt] = EncryptHeader.BuildL2(wrapped),
            [WopHeaders.ContentDigest] = ContentDigest.BuildHeaderValue(client.Suite, wire),
        };
        var signedNames = headers.Keys.OrderBy(k => k, StringComparer.Ordinal).ToList();
        var canonical = CanonicalRequest.Build("v1/1800", "POST", path, "",
            CanonicalRequest.CanonicalHeaders(signedNames.ToDictionary(n => n, n => headers[n])));
        var sig = WopCrypto.Sign(client.Suite, WopClientTests.RespKeyMaterial(client.Suite), Encoding.UTF8.GetBytes(canonical));
        headers[WopHeaders.Sign] = SignHeader.Build(client.Suite.SecurityReq, 1800, signedNames, sig);
        return (headers, wire);
    }
}
