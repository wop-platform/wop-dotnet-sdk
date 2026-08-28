using System;
using System.Collections.Generic;
using Wop.Sdk;
using Xunit;

public class ContentDigestTests
{
    static readonly AlgorithmSuite Rsa = AlgorithmSuite.Parse("WOP-RSA3072-SHA256");
    static readonly AlgorithmSuite Sm2 = AlgorithmSuite.Parse("WOP-SM2-SM3");

    [Fact]
    public void Compute_按套件族选算法()
    {
        var data = new byte[] { 1, 2, 3 };
        Assert.Equal(32, ContentDigest.Compute(Rsa, data).Length);
        Assert.Equal(32, ContentDigest.Compute(Sm2, data).Length);
        Assert.NotEqual(ContentDigest.Compute(Rsa, data), ContentDigest.Compute(Sm2, data));
    }

    [Fact]
    public void BuildHeaderValue_标签恰一空格小写hex_与向量摘要一致()
    {
        var body = System.Text.Encoding.UTF8.GetBytes("WOP 跨语言测试向量 2026-08-28 — The quick brown fox jumps over the lazy dog.");
        Assert.Equal("sha-256 4cf7ab3bcefc20c8d6116d4ce9a3fdfb0d60ba5391472d7bffcf159da9e033ca",
            ContentDigest.BuildHeaderValue(Rsa, body));
        Assert.Equal("sm3 23592263765cf506d07cc8614c09067e6de38e64c53e5b672c022532d01737cf",
            ContentDigest.BuildHeaderValue(Sm2, body));
    }

    [Theory]
    [InlineData("sha-256 23592263765cf506d07cc8614c09067e6de38e64c53e5b672c022532d01737cf", "sha-256", "23592263765cf506d07cc8614c09067e6de38e64c53e5b672c022532d01737cf")]
    [InlineData("sm3 23592263765cf506d07cc8614c09067e6de38e64c53e5b672c022532d01737cf", "sm3", "23592263765cf506d07cc8614c09067e6de38e64c53e5b672c022532d01737cf")]
    public void Parse_合法值(string value, string tag, string hex)
    {
        var (t, h) = ContentDigest.Parse(value);
        Assert.Equal(tag, t);
        Assert.Equal(hex, h);
    }

    [Theory]  // D2 钉死：恰一空格、小写、64 hex；I5：跨族标签拒绝
    [InlineData("sha-256  23592263765cf506d07cc8614c09067e6de38e64c53e5b672c022532d01737cf")]  // 双空格
    [InlineData("sha-256 23592263765CF506D07CC8614C09067E6DE38E64C53E5B672C022532D01737CF")]     // 大写
    [InlineData("sha-256 3592263765cf506d07cc8614c09067e6de38e64c53e5b672c022532d01737cf")]     // 63 位
    [InlineData("sha-256 23592263765cf506d07cc8614c09067e6de38e64c53e5b672c022532d01737cf1")]   // 65 位
    [InlineData("md5 23592263765cf506d07cc8614c09067e6de38e64c53e5b672c022532d01737cf")]        // 未支持 tag
    [InlineData("sha-256 23592263765cf506d07cc8614c09067e6de38e64c53e5b672c022532d01737cg")]   // 非 hex 字符
    [InlineData("sha-25623592263765cf506d07cc8614c09067e6de38e64c53e5b672c022532d01737cf")]    // 无空格
    [InlineData("")]
    public void Parse_结构非法_协议类拒绝(string value)
    {
        var ex = Assert.Throws<WopException>(() => ContentDigest.Parse(value));
        Assert.Equal(WopErrorCode.Protocol, ex.ErrorCode);
    }

    [Theory]
    [InlineData("WOP-RSA3072-SHA256", "sm3 23592263765cf506d07cc8614c09067e6de38e64c53e5b672c022532d01737cf", "跨族")]   // I5
    [InlineData("WOP-SM2-SM3", "sha-256 23592263765cf506d07cc8614c09067e6de38e64c53e5b672c022532d01737cf", "跨族")]
    public void ValidateHeader_跨族标签拒绝(string suiteReq, string header, string part)
    {
        var ex = Assert.Throws<WopException>(() =>
            ContentDigest.ValidateHeader(AlgorithmSuite.Parse(suiteReq), header));
        Assert.Equal(WopErrorCode.Protocol, ex.ErrorCode);
        Assert.Contains(part, ex.Message);
    }

    [Fact]
    public void ValidateHeader_同族合法()
    {
        var v = "sha-256 " + new string('a', 64);
        ContentDigest.ValidateHeader(Rsa, v);
    }

    [Fact]
    public void Validate_值不匹配_完整性类明确拒绝()
    {
        var body = new byte[] { 1, 2, 3 };
        var wrong = "sha-256 " + new string('0', 64);
        var ex = Assert.Throws<WopException>(() => ContentDigest.Validate(Rsa, wrong, body));
        Assert.Equal(WopErrorCode.DigestMismatch, ex.ErrorCode);
    }

    [Fact]
    public void Validate_匹配通过()
    {
        var body = new byte[] { 1, 2, 3 };
        ContentDigest.Validate(Rsa, ContentDigest.BuildHeaderValue(Rsa, body), body);
        ContentDigest.Validate(Sm2, ContentDigest.BuildHeaderValue(Sm2, body), body);
    }
}

public class EncryptedEnvelopeTests
{
    [Fact]
    public void Wrap_拼装JSON信封()
    {
        Assert.Equal("{\"encrypted\":\"AAEC\"}", System.Text.Encoding.UTF8.GetString(
            EncryptedEnvelope.Wrap(Codec.EncodeB64Url(new byte[] { 0, 1, 2 }))));
    }

    [Fact]
    public void Extract_提取密文字段_容忍未知字段()
    {
        var cipher = Codec.EncodeB64Url(new byte[] { 9, 9 });
        var body = System.Text.Encoding.UTF8.GetBytes("{\"encrypted\":\"" + cipher + "\",\"extra\":{\"k\":1}}");
        Assert.Equal(cipher, EncryptedEnvelope.Extract(body));
    }

    [Theory]
    [InlineData("not json")]
    [InlineData("[]")]
    [InlineData("{}")]                                   // 缺 encrypted
    [InlineData("{\"encrypted\":123}")]                  // 非字符串
    [InlineData("{\"other\":\"x\"}")]
    [InlineData("{\"encrypted\":\"ab+c\"}")]             // 非法 b64url 字符
    [InlineData("{\"encrypted\":\"\"}")]                 // 空
    public void Extract_非法信封_协议类拒绝(string body)
    {
        var ex = Assert.Throws<WopException>(() =>
            EncryptedEnvelope.Extract(System.Text.Encoding.UTF8.GetBytes(body)));
        Assert.Equal(WopErrorCode.Protocol, ex.ErrorCode);
    }
}

public class EncryptHeaderTests
{
    [Fact]
    public void BuildL2()
    {
        Assert.Equal("L2;dek=AAEC", EncryptHeader.BuildL2(Codec.EncodeB64Url(new byte[] { 0, 1, 2 })));
    }

    [Fact]
    public void Parse_合法()
    {
        var (level, dek) = EncryptHeader.Parse("  L2;dek=AAEC ");
        Assert.Equal("L2", level);
        Assert.Equal("AAEC", dek);
    }

    [Theory]
    [InlineData("")]
    [InlineData("L1;dek=AAEC")]
    [InlineData("L2")]
    [InlineData("L2;dek=")]
    [InlineData("L2;dek=AA=C")]
    [InlineData("L2;dek=AA+C")]
    [InlineData("L2dek=AAEC")]
    public void Parse_非法_协议类拒绝(string value)
    {
        var ex = Assert.Throws<WopException>(() => EncryptHeader.Parse(value));
        Assert.Equal(WopErrorCode.Protocol, ex.ErrorCode);
    }
}

public class DekPayloadTests
{
    [Fact]
    public void Encode_三段()
    {
        Assert.Equal("AES-256-GCM$AAEC$AwQ",
            DekPayload.Encode("AES-256-GCM", new byte[] { 0, 1, 2 }, new byte[] { 3, 4 }));
    }

    [Fact]
    public void Parse_合法_解析key与iv()
    {
        var key16 = Codec.EncodeB64Url(new byte[16]);
        var iv12 = Codec.EncodeB64Url(new byte[12]);
        var p = DekPayload.Parse("SM4-GCM$" + key16 + "$" + iv12);
        Assert.Equal("SM4-GCM", p.Alg);
        Assert.Equal(new byte[16], p.Key);
        Assert.Equal(new byte[12], p.Iv);
        Assert.True(p.MatchesSuite(AlgorithmSuite.Parse("WOP-SM2-SM3")));
        Assert.False(p.MatchesSuite(AlgorithmSuite.Parse("WOP-RSA3072-SHA256")));
    }

    [Theory]
    [InlineData("AES-256-GCM$AAEC")]                          // 两段
    [InlineData("AES-256-GCM$AAEC$AwQ$BAU")]                  // 四段
    [InlineData("AES-128-GCM$AAEC$AwQ")]                      // 未支持 alg
    [InlineData("AES-256-GCM$$AwQ")]                          // key 空
    [InlineData("AES-256-GCM$AA=C$AwQ")]                      // b64url 非法
    [InlineData("AES-256-GCM$AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8$AwQ")]  // key 长度 32 但 alg 要 32 —— 修正见下
    [InlineData("SM4-GCM$AAEC$AwQFBgcICQ")]                   // iv 非 12B
    [InlineData("")]
    public void Parse_非法载荷_协议类拒绝(string payload)
    {
        Assert.Throws<WopException>(() => DekPayload.Parse(payload));
    }

    [Fact]
    public void Parse_key长度与alg不符_拒绝()
    {
        // AES-256-GCM key 须 32B，给 16B
        var key16 = Codec.EncodeB64Url(new byte[16]);
        var iv12 = Codec.EncodeB64Url(new byte[12]);
        Assert.Throws<WopException>(() => DekPayload.Parse("AES-256-GCM$" + key16 + "$" + iv12));
    }
}
