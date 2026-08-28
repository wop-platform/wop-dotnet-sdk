using System;
using System.Linq;
using System.IO;
using System.Text.Json;
using Wop.Sdk;
using Xunit;

public class KeyCodecTests
{
    static readonly JsonDocument V = JsonDocument.Parse(
        File.OpenRead(Path.Combine(AppContext.BaseDirectory, "fixtures", "crypto-vectors.json")));

    static string Key(string path)
    {
        JsonElement e = V.RootElement;
        foreach (var p in path.Split('.'))
            e = int.TryParse(p, out var i) ? e[i] : e.GetProperty(p);
        return e.GetString()!;
    }

    [Theory]
    [InlineData("keys.rsa3072.publicSpkiB64")]
    [InlineData("keys.rsa4096.publicSpkiB64")]
    public void ParseRsaPublicKey_SPKI合法(string path)
    {
        var suite = AlgorithmSuite.Parse(path.Contains("4096") ? "WOP-RSA4096-SHA256" : "WOP-RSA3072-SHA256");
        var key = KeyCodec.ParseRsaPublicKey(Key(path), suite);
        Assert.Equal(suite.KeyBits, key.Modulus.BitLength);
    }

    [Fact]
    public void ParseRsaPublicKey_位数与套件不符_配置类拒绝()
    {
        var suite3072 = AlgorithmSuite.Parse("WOP-RSA3072-SHA256");
        var ex = Assert.Throws<WopException>(() =>
            KeyCodec.ParseRsaPublicKey(Key("keys.rsa4096.publicSpkiB64"), suite3072));
        Assert.Equal(WopErrorCode.Config, ex.ErrorCode);
        Assert.Contains("位数", ex.Message);
    }

    [Theory]
    [InlineData("keys.rsa3072.privatePkcs8B64", "WOP-RSA3072-SHA256")]
    [InlineData("keys.rsa4096.privatePkcs8B64", "WOP-RSA4096-SHA256")]
    public void ParseRsaPrivateKey_PKCS8合法(string path, string suiteReq)
    {
        var key = KeyCodec.ParseRsaPrivateKey(Key(path), AlgorithmSuite.Parse(suiteReq));
        Assert.True(key.Modulus.BitLength > 0);
    }

    [Fact]
    public void ParseRsaPrivateKey_位数不符_拒绝()
    {
        var suite3072 = AlgorithmSuite.Parse("WOP-RSA3072-SHA256");
        Assert.Throws<WopException>(() =>
            KeyCodec.ParseRsaPrivateKey(Key("keys.rsa4096.privatePkcs8B64"), suite3072));
    }

    [Fact]
    public void ParseRsaKey_PEM包装合法()
    {
        var b64 = Key("keys.rsa3072.publicSpkiB64");
        var pem = "-----BEGIN PUBLIC KEY-----\n" + InsertLineBreaks(b64) + "\n-----END PUBLIC KEY-----\n";
        var suite = AlgorithmSuite.Parse("WOP-RSA3072-SHA256");
        Assert.Equal(3072, KeyCodec.ParseRsaPublicKey(pem, suite).Modulus.BitLength);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("!!!not-base64!!!")]
    public void 密钥材料非法_配置类拒绝(string material)
    {
        var suite = AlgorithmSuite.Parse("WOP-RSA3072-SHA256");
        var ex = Assert.Throws<WopException>(() => KeyCodec.ParseRsaPublicKey(material, suite));
        Assert.Equal(WopErrorCode.Config, ex.ErrorCode);
    }

    [Fact]
    public void ParseSm2PublicKey_未压缩点合法()
    {
        var key = KeyCodec.ParseSm2PublicKey(Key("keys.sm2.publicPointB64"));
        Assert.Equal(65, key.Q.GetEncoded(false).Length);
    }

    [Fact]
    public void ParseSm2PublicKey_PEM包装_容忍()
    {
        var b64 = Key("keys.sm2.publicPointB64");
        var pem = "-----BEGIN PUBLIC KEY-----\n" + InsertLineBreaks(b64) + "\n-----END PUBLIC KEY-----";
        Assert.NotNull(KeyCodec.ParseSm2PublicKey(pem));
    }

    [Fact]
    public void ParseSm2PrivateKey_标量合法且派生公钥等于向量公钥()
    {
        var priv = KeyCodec.ParseSm2PrivateKey(Key("keys.sm2.privateDB64"));
        var pub = KeyCodec.ParseSm2PublicKey(Key("keys.sm2.publicPointB64"));
        var dom = Org.BouncyCastle.Asn1.GM.GMNamedCurves.GetByName("sm2p256v1");
        var dg = dom.G.Multiply(priv.D).Normalize();
        Assert.Equal(pub.Q.Normalize(), dg);
    }

    [Theory]  // I5 曲线守卫：格式、长度、前缀、坐标域、on-curve 全部前置拒绝
    [InlineData("63B")]           // 长度错（63 字节）
    [InlineData("66B")]           // 长度错（66 字节）
    [InlineData("badPrefix")]     // 前缀非 04
    [InlineData("offCurve")]      // on-curve 校验
    [InlineData("coordOverflow")] // 坐标 ≥ p
    public void ParseSm2PublicKey_非法点_配置类拒绝(string kind)
    {
        var raw = Convert.FromBase64String(Key("keys.sm2.publicPointB64"));
        byte[] bad = kind switch
        {
            "63B" => raw[..63],
            "66B" => [.. raw, 0x00],
            "badPrefix" => [0x03, .. raw[1..]],
            "offCurve" => raw[..33].Concat(new byte[] { raw[33] }).ToArray()[..34]
                .Concat(((new Org.BouncyCastle.Math.BigInteger(1, raw, 33, 32)).Add(Org.BouncyCastle.Math.BigInteger.One))
                    .ToByteArrayUnsigned()).ToArray(),
            "coordOverflow" => raw[..1]
                .Concat(new byte[] { 0xFF, 0xFF, 0xFF, 0xFF }).Concat(raw[5..33])
                .Concat(raw[33..]).ToArray(),
            _ => raw,
        };
        if (kind == "offCurve")
        {
            // y+1（保持 32 字节定长）
            var y = new Org.BouncyCastle.Math.BigInteger(1, raw, 33, 32)
                .Add(Org.BouncyCastle.Math.BigInteger.One);
            var yb = y.ToByteArrayUnsigned();
            var padded = new byte[32];
            Array.Copy(yb, 0, padded, 32 - yb.Length, yb.Length);
            bad = [.. raw[..33], .. padded];
        }
        var ex = Assert.Throws<WopException>(() =>
            KeyCodec.ParseSm2PublicKey(Convert.ToBase64String(bad)));
        Assert.Equal(WopErrorCode.Config, ex.ErrorCode);
    }

    [Theory]
    [InlineData(31)]
    [InlineData(33)]
    public void ParseSm2PrivateKey_长度错_拒绝(int len)
    {
        var raw = new byte[len];
        Assert.Throws<WopException>(() => KeyCodec.ParseSm2PrivateKey(Convert.ToBase64String(raw)));
    }

    [Fact]
    public void ParseSm2PrivateKey_零标量_越界拒绝()
    {
        Assert.Throws<WopException>(() => KeyCodec.ParseSm2PrivateKey(Convert.ToBase64String(new byte[32])));
    }

    static string InsertLineBreaks(string s)
    {
        var sb = new System.Text.StringBuilder();
        for (var i = 0; i < s.Length; i += 64)
        {
            if (i > 0)
            {
                sb.Append('\n');
            }
            sb.Append(s, i, Math.Min(64, s.Length - i));
        }
        return sb.ToString();
    }
}
