using System;
using System.IO;
using System.Text;
using System.Text.Json;
using Org.BouncyCastle.Security;
using Wop.Sdk;
using Xunit;

/// <summary>边界杀变异测试：针对 Stryker 首轮存活的真实边界缺口
/// （解码索引边界、SkipValue 深度边界、hex 转义边界、CSPRNG 注入流合同、
/// expiredSeconds 上界、\u 转义恰满截断），每个用例锚定具体变异点。</summary>
public class MutationKillBoundaryTests
{
    static readonly JsonElement Keys = JsonDocument.Parse(File.OpenRead(
        Path.Combine(AppContext.BaseDirectory, "fixtures", "crypto-vectors.json"))).RootElement.GetProperty("keys");

    static string K(string name, string field) => Keys.GetProperty(name).GetProperty(field).GetString()!;

    static readonly byte[] Body = Encoding.UTF8.GetBytes("{\"k\":1}");

    // Codec.cs:63 '0'=52 低 2 位为零 → rem3 规范尾（杀 c > '0'→c >= '0'：变异后 '0' 掉入 62 → 62&3≠0 拒收）
// spec:D1
    [Fact]
    public void 边界_数字零尾字符_规范接受()
    {
        // A=0, B=1, '0'=52 → 000000 000001 110100 → 0x00 0x1D
        Assert.Equal(new byte[] { 0x00, 0x1D }, Codec.DecodeB64Url("AB0"));
    }

    // Codec.cs:63 'Q'=16 低 4 位为零 → rem2 规范尾（杀 &&→||：变异后 Q→68 → 68&0xF≠0 拒收）
// spec:D1
    [Fact]
    public void 边界_大写Q尾字符_规范接受()
    {
        // A=0, Q=16 → 000000 010000 → 0x01
        Assert.Equal(new byte[] { 0x01 }, Codec.DecodeB64Url("AQ"));
    }

    // Codec.cs:63 'w'=48 低 4 位为零 → rem2 规范尾（同上 &&→||，小写侧）
// spec:D1
    [Fact]
    public void 边界_小写w尾字符_规范接受()
    {
        // A=0, w=48 → 000000 110000 → 0x03
        Assert.Equal(new byte[] { 0x03 }, Codec.DecodeB64Url("Aw"));
    }

    // EncryptedEnvelope.cs:157 SkipValue 循环内字符串感知块：串内不平衡结构字符
// spec:D3
    // （3 个 '}' 使裸扫描 depth 错位；原实现 ReadString 整串跳过不受影响）
    [Fact]
    public void 边界_串内多个闭合括号_不误判()
    {
        var body = "{\"a\":{\"b\":\"}}}rz\"},\"encrypted\":\"AA\"}";
        Assert.Equal("AA", EncryptedEnvelope.Extract(Encoding.UTF8.GetBytes(body)));
    }
    // EncryptedEnvelope SkipValue 循环内字符串感知：串内转义引号与逗号（裸扫描必错位）
    [Fact]
    public void 边界_串内转义引号与逗号_不误判()
    {
        var body = "{\"a\":\"x\\\"y,z\",\"encrypted\":\"AA\"}";
        Assert.Equal("AA", EncryptedEnvelope.Extract(Encoding.UTF8.GetBytes(body)));
    }


    // 串内转义引号+闭合括号：裸扫描把 \" 后内容当结构字符，必错位到"缺少 encrypted"
    [Fact]
    public void 边界_串内转义引号后闭合括号_不误判()
    {
        var body = "{\"a\":\"a\\\"}\",\"encrypted\":\"AA\"}";
        Assert.Equal("AA", EncryptedEnvelope.Extract(Encoding.UTF8.GetBytes(body)));
    }

    // EncryptedEnvelope.cs:87 i+4 == s.Length 恰满截断（杀 >= → >：变异后 Substring 越界抛非 Wop 异常）
// spec:D3
    [Fact]
    public void 边界_u转义恰满截断_拒绝()
    {
        Assert.Throws<WopException>(() =>
            EncryptedEnvelope.Extract(Encoding.UTF8.GetBytes("{\"a\":\"\\u123")));
    }

    // EncryptedEnvelope.cs:95 hex 字符集全部边界（'9','F','f','a','A' 各自恰合法）
// spec:D3
    [Fact]
    public void 边界_u转义hex边界字符_接受()
    {
        var body = "{\"a\":\"\\uA9fa\\uF0aF\",\"encrypted\":\"AA\"}";
        Assert.Equal("AA", EncryptedEnvelope.Extract(Encoding.UTF8.GetBytes(body)));
    }

    // EncryptedEnvelope.cs:118 0x20 空格是字符串内合法字符（杀 < → <=：变异后空格被当控制字符拒绝）
// spec:D3
    [Fact]
    public void 边界_字符串内空格_合法()
    {
        var body = "{\"a\":\"x y\",\"encrypted\":\"AA\"}";
        Assert.Equal("AA", EncryptedEnvelope.Extract(Encoding.UTF8.GetBytes(body)));
    }

    // WopClient.cs:378 expiredSeconds == 86400 上界恰好合法（杀 > → >=）
// spec:F9
    [Fact]
    public void 边界_expiredSeconds上界_合法()
    {
        var client = WopClient.Builder()
            .AppKey("a").Suite("WOP-RSA3072-SHA256")
            .MerchantPrivateKey(K("rsa3072", "privatePkcs8B64"))
            .PlatformPublicKey(K("rsa3072", "publicSpkiB64"))
            .ExpiredSeconds(86400)
            .Build();
        Assert.NotNull(client);
    }

    // WopCrypto.cs:297 注入随机流合同：SM2 L2 出向同序列流 → 字节级相同
// spec:F5 I4
    // （杀 random ?? new → 恒 new：变异后每次真随机，两次 wire 必不同）
    [Fact]
    public void 边界_SM2注入随机流_出向确定性()
    {
        WopClient BuildWith(SequencedRandom random) => WopClient.Builder()
            .AppKey("a").Suite("WOP-SM2-SM3")
            .MerchantPrivateKey(K("sm2", "privateDB64"))
            .PlatformPublicKey(K("sm2", "publicPointB64"))
            .WithClock(() => 1724900000000)
            .WithNonce(() => "nonce-001")
            .WithRandom(random)
            .Build();

        var d1 = BuildWith(new SequencedRandom()).BuildRequest("POST", "/e", Body, SecurityLevel.L2);
        var d2 = BuildWith(new SequencedRandom()).BuildRequest("POST", "/e", Body, SecurityLevel.L2);
        Assert.Equal(d1.WireBody, d2.WireBody);
        Assert.Equal(d1.Headers[WopHeaders.Encrypt], d2.Headers[WopHeaders.Encrypt]);
    }

    /// <summary>确定性顺序流：第 n 字节 = (n*7+1) & 0xFF，字节可重复。</summary>
    sealed class SequencedRandom : SecureRandom
    {
        private byte _n;

        private void Fill(byte[] buffer)
        {
            for (var i = 0; i < buffer.Length; i++)
            {
                buffer[i] = (byte)(_n++ * 7 + 1);
            }
        }

        public override void NextBytes(byte[] bytes) => Fill(bytes);

#if NET8_0
        public override void NextBytes(Span<byte> buffer)
        {
            var tmp = new byte[buffer.Length];
            Fill(tmp);
            tmp.CopyTo(buffer);
        }
#endif
    }
}
