using System;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Linq;
using Org.BouncyCastle.Math;
using Wop.Sdk;
using Xunit;

/// <summary>覆盖率闭合：击穿负分支与边角路径（对应 Go 仓 CoverageCloseTest 惯例）。</summary>
public class CoverageCloseTests
{
    static readonly JsonElement Keys = JsonDocument.Parse(File.OpenRead(
        Path.Combine(AppContext.BaseDirectory, "fixtures", "crypto-vectors.json"))).RootElement.GetProperty("keys");

    static string K(string name, string field) => Keys.GetProperty(name).GetProperty(field).GetString()!;

    static AlgorithmSuite RsaSuite() => AlgorithmSuite.Parse("WOP-RSA3072-SHA256");
    static AlgorithmSuite Sm2Suite() => AlgorithmSuite.Parse("WOP-SM2-SM3");

    // ==================== EncryptedEnvelope 手写 JSON 解析器全分支 ====================

    [Theory]
    [InlineData("{\"a\":\"x\",\"encrypted\":\"AA\"}")]                      // encrypted 非首位
    [InlineData("{\"a\":{\"n\":[1,2]},\"encrypted\":\"AA\"}")]             // 嵌套对象/数组 skip
    [InlineData("{\"a\":[{\"b\":\"c\"}],\"encrypted\":\"AA\"}")]           // 数组内嵌套对象
    [InlineData("{\"a\":true,\"encrypted\":\"AA\"}")]
    [InlineData("{\"a\":null,\"encrypted\":\"AA\"}")]
    [InlineData("{\"a\":123,\"encrypted\":\"AA\"}")]
    [InlineData("{ \"encrypted\" : \"AA\" }")]                             // 空白容忍
    [InlineData("{\"encrypted\":\"AA\",\"z\":{}}")]                        // encrypted 后还有字段
    public void Envelope_提取合法(string body)
    {
        Assert.Equal("AA", EncryptedEnvelope.Extract(Encoding.UTF8.GetBytes(body)));
    }

    [Theory]
    [InlineData("[1]")]                                  // 非对象
    [InlineData(" x")]                                   // 非空白后非 {
    [InlineData("{,}")]
    [InlineData("{\"a\" \"x\"}")]                        // 缺冒号
    [InlineData("{\"a\"")]                               // 键后截断
    [InlineData("{\"a\"}")]
    [InlineData("{\"a\":")]
    [InlineData("{\"a\": \"unterminated}")]              // 字符串未闭合
    [InlineData("{\"a\":\"x\" \"encrypted\":\"AA\"}")]   // 缺逗号 → 下一键读取失败
    [InlineData("{\"encrypted\":\"a\\x\"}")]             // 非法转义
    [InlineData("{\"encrypted\":\"a\\\"}")]              // 转义后截断
    [InlineData("{\"encrypted\":\"a\u0001b\"}")]         // 未转义控制字符（U+0001）
    [InlineData("{ }")]                                  // 无字段
    public void Envelope_非法结构_拒绝(string body)
    {
        Assert.Throws<WopException>(() => EncryptedEnvelope.Extract(Encoding.UTF8.GetBytes(body)));
    }

    [Fact]
    public void Envelope_键内合法转义可解析_转义键名语义等价()
    {
        // RFC 8259：键名 "encrypte\u0064" 解码后即 "encrypted" → 提取成功（非缺字段）
        Assert.Equal("AA",
            EncryptedEnvelope.Extract(Encoding.UTF8.GetBytes("{\"zz\":\"x\",\"encrypte\\u0064\":\"AA\"}")));
        // 真正不同的键（含转义字符但整体 ≠ encrypted）→ 缺字段拒绝
        Assert.Throws<WopException>(() =>
            EncryptedEnvelope.Extract(Encoding.UTF8.GetBytes("{\"a\\u0041b\":\"x\"}")));
    }

    // ==================== WopCrypto 配置类缺钥分支 ====================

    [Fact]
    public void Crypto_缺钥_配置类明确拒绝()
    {
        var msg = Encoding.UTF8.GetBytes("m");
        var rsaEmpty = new AsymmetricKeyMaterial();
        Assert.Throws<WopException>(() => WopCrypto.Sign(RsaSuite(), rsaEmpty, msg));
        Assert.Throws<WopException>(() => WopCrypto.Verify(RsaSuite(), rsaEmpty, msg, "AA"));
        Assert.Throws<WopException>(() => WopCrypto.WrapDek(RsaSuite(), rsaEmpty, msg));
        Assert.Throws<WopException>(() => WopCrypto.UnwrapDek(RsaSuite(), rsaEmpty, "AA"));

        var sm2Empty = new AsymmetricKeyMaterial();
        Assert.Throws<WopException>(() => WopCrypto.Sign(Sm2Suite(), sm2Empty, msg));
        Assert.Throws<WopException>(() => WopCrypto.Verify(Sm2Suite(), sm2Empty, msg, new string('A', 86)));
        Assert.Throws<WopException>(() => WopCrypto.WrapDek(Sm2Suite(), sm2Empty, msg));
        Assert.Throws<WopException>(() => WopCrypto.UnwrapDek(Sm2Suite(), sm2Empty, new string('A', 20)));
    }

    [Fact]
    public void Crypto_跨族钥_配置类拒绝()
    {
        var msg = Encoding.UTF8.GetBytes("m");
        var rsaKey = AsymmetricKeyMaterial.ParsePrivate(K("rsa3072", "privatePkcs8B64"), RsaSuite());
        var rsaPub = AsymmetricKeyMaterial.ParsePublic(K("rsa3072", "publicSpkiB64"), RsaSuite());
        var sm2Key = AsymmetricKeyMaterial.ParsePrivate(K("sm2", "privateDB64"), Sm2Suite());
        var sm2Pub = AsymmetricKeyMaterial.ParsePublic(K("sm2", "publicPointB64"), Sm2Suite());
        // SM2 套件 + RSA 材料（类型不符）
        Assert.Throws<WopException>(() => WopCrypto.Sign(Sm2Suite(), rsaKey, msg));
        Assert.Throws<WopException>(() => WopCrypto.Verify(Sm2Suite(), rsaPub, msg, new string('A', 86)));
        Assert.Throws<WopException>(() => WopCrypto.WrapDek(Sm2Suite(), rsaPub, msg));
        Assert.Throws<WopException>(() => WopCrypto.UnwrapDek(Sm2Suite(), rsaKey, new string('A', 20)));
        // RSA 套件 + SM2 材料
        Assert.Throws<WopException>(() => WopCrypto.Sign(RsaSuite(), sm2Key, msg));
        Assert.Throws<WopException>(() => WopCrypto.Verify(RsaSuite(), sm2Pub, msg, "AA"));
        Assert.Throws<WopException>(() => WopCrypto.WrapDek(RsaSuite(), sm2Pub, msg));
        Assert.Throws<WopException>(() => WopCrypto.UnwrapDek(RsaSuite(), sm2Key, "AA"));
    }

    [Fact]
    public void Crypto_fixedK非法范围_配置类拒绝()
    {
        var sm2Key = AsymmetricKeyMaterial.ParsePrivate(K("sm2", "privateDB64"), Sm2Suite());
        var msg = Encoding.UTF8.GetBytes("m");
        Assert.Throws<WopException>(() => WopCrypto.Sign(Sm2Suite(), sm2Key, msg, BigInteger.Zero));
        Assert.Throws<WopException>(() => WopCrypto.Sign(Sm2Suite(), sm2Key, msg,
            new BigInteger("fffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d54124", 16)));
        Assert.Throws<WopException>(() => WopCrypto.WrapDek(Sm2Suite(),
            AsymmetricKeyMaterial.ParsePublic(K("sm2", "publicPointB64"), Sm2Suite()), msg, BigInteger.One.Negate()));
    }

    [Fact]
    public void Crypto_报文key与iv长度_配置类明确()
    {
        Assert.Throws<WopException>(() => WopCrypto.SealMessage(RsaSuite(), new byte[1], new byte[16], new byte[12]));
        Assert.Throws<WopException>(() => WopCrypto.SealMessage(RsaSuite(), new byte[1], new byte[32], new byte[11]));
        Assert.Throws<WopException>(() => WopCrypto.SealMessage(Sm2Suite(), new byte[1], new byte[16], new byte[13]));
        // OpenMessage 长度不符 → 模糊（I7）
        var ex = Assert.Throws<WopException>(() =>
            WopCrypto.OpenMessage(RsaSuite(), new byte[40], new byte[16], new byte[12]));
        Assert.Equal(WopErrorCode.DecryptFailed, ex.ErrorCode);
    }

    [Fact]
    public void Crypto_UnwrapDek_非法b64url_协议类()
    {
        var rsaKey = AsymmetricKeyMaterial.ParsePrivate(K("rsa3072", "privatePkcs8B64"), RsaSuite());
        var ex = Assert.Throws<WopException>(() => WopCrypto.UnwrapDek(RsaSuite(), rsaKey, "ab=c"));
        Assert.Equal(WopErrorCode.Protocol, ex.ErrorCode);
    }

    // ==================== FixedScalarRandom 填充语义 ====================

    [Fact]
    public void FixedScalarRandom_数组路径与I2OSP左补零()
    {
        var r = new FixedScalarRandom(BigInteger.ValueOf(0x0102));
        var buf = new byte[4];
        r.NextBytes(buf);   // byte[] 路径（netstandard2.0 分支）
        Assert.Equal(new byte[] { 0, 0, 1, 2 }, buf);
        var shortBuf = new byte[1];
        r.NextBytes(shortBuf);   // buffer 短于标量 → 取低位
        Assert.Equal(new byte[] { 2 }, shortBuf);
    }

    // ==================== WopClientBuilder 边角 ====================

    [Fact]
    public void Builder_未配置套件_解析类拒绝()
    {
        var ex = Assert.Throws<WopException>(() => WopClient.Builder()
            .AppKey("a").MerchantPrivateKey("x").PlatformPublicKey("y").Build());
        Assert.Equal(WopErrorCode.SuiteParse, ex.ErrorCode);
    }

    [Fact]
    public void Builder_未配置密钥_配置类拒绝()
    {
        var b = WopClient.Builder().AppKey("a").Suite("WOP-SM2-SM3");
        Assert.Equal(WopErrorCode.Config, Assert.Throws<WopException>(() => b.Build()).ErrorCode);
        b.MerchantPrivateKey(K("sm2", "privateDB64"));
        Assert.Equal(WopErrorCode.Config, Assert.Throws<WopException>(() => b.Build()).ErrorCode);
    }

    [Fact]
    public void Builder_expiredSeconds非正_拒绝()
    {
        Assert.Throws<WopException>(() => WopClientTests.RsaBuilder().ExpiredSeconds(0).Build());
        Assert.Throws<WopException>(() => WopClientTests.RsaBuilder().ExpiredSeconds(-5).Build());
    }

    [Fact]
    public void Builder_GatewayBaseUrl与默认nonce链路()
    {
        var client = WopClient.Builder()
            .AppKey("a").Suite("WOP-RSA3072-SHA256")
            .MerchantPrivateKey(K("rsa3072", "privatePkcs8B64"))
            .PlatformPublicKey(K("rsa3072", "publicSpkiB64"))
            .GatewayBaseUrl("https://gw.example.com")
            .Build();
        var d = client.BuildRequest("GET", "/q", null, SecurityLevel.L0);
        Assert.Equal(32, d.Headers[WopHeaders.Nonce].Length);   // 默认 CSPRNG nonce（32 hex = 16B）
    }

    // ==================== WopClient verify 边角 ====================

    [Fact]
    public void VerifyCallback_相对URL_拒绝()
    {
        var client = WopClientTests.RsaBuilder().Build();
        var result = client.VerifyCallback("/only/path", new Dictionary<string, string>(), null);
        Assert.False(result.Ok);
        Assert.Equal(WopErrorCode.Protocol, result.ErrorCode);
    }

    [Fact]
    public void VerifyCallback_仅域名无path_拒绝()
    {
        var client = WopClientTests.RsaBuilder().Build();
        var result = client.VerifyCallback("https://example.com", new Dictionary<string, string>(), null);
        Assert.False(result.Ok);
    }

    [Fact]
    public void Verify_缺少签名头_协议类拒绝()
    {
        var client = WopClientTests.RsaBuilder().Build();
        var result = client.VerifyResponse("GET", "/q", new Dictionary<string, string>(), null);
        Assert.False(result.Ok);
        Assert.Equal(WopErrorCode.Protocol, result.ErrorCode);
    }

    // ==================== Transport 边角 ====================

    [Fact]
    public void Transport_HttpClient为空_拒绝()
    {
        Assert.Throws<WopException>(() => new HttpClientTransport((System.Net.Http.HttpClient)null!, "https://x"));
    }

    [Fact]
    public void Transport_读取体失败_配置类()
    {
        var throwingContent = new FailingContent();
        var response = new System.Net.Http.HttpResponseMessage(System.Net.HttpStatusCode.OK)
        {
            Content = throwingContent,
        };
        var handler = new ThrowingHandler(response);
        var transport = new HttpClientTransport(handler, "https://gw.example.com");
        var draft = WopClientTests.RsaBuilder().Build().BuildRequest("GET", "/q", null, SecurityLevel.L0);
        var ex = Assert.Throws<WopException>(() => transport.Send(draft));
        Assert.Equal(WopErrorCode.Config, ex.ErrorCode);
    }

    sealed class ThrowingHandler : System.Net.Http.HttpMessageHandler
    {
        private readonly System.Net.Http.HttpResponseMessage _response;
        internal ThrowingHandler(System.Net.Http.HttpResponseMessage response) => _response = response;
        protected override Task<System.Net.Http.HttpResponseMessage> SendAsync(
            System.Net.Http.HttpRequestMessage request, System.Threading.CancellationToken ct)
            => Task.FromResult(_response);
    }

    sealed class FailingContent : System.Net.Http.HttpContent
    {
        protected override Task<Stream> CreateContentReadStreamAsync()
            => Task.FromResult<Stream>(new ThrowingStream());

        protected override Task SerializeToStreamAsync(Stream stream, System.Net.TransportContext? context)
            => throw new InvalidOperationException();

        protected override bool TryComputeLength(out long length)
        {
            length = 0;
            return false;
        }
    }

    sealed class ThrowingStream : Stream
    {
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override int Read(byte[] buffer, int offset, int count) => throw new IOException("read fail");
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) { }
        public override void Write(byte[] buffer, int offset, int count) { }
    }
}

public class CoverageClose2Tests
{
    // ==================== null 入参分支（对外宽容 → 明确拒绝） ====================

    [Fact]
    public void Null入参_全部明确拒绝或归一()
    {
        var rsa = AlgorithmSuite.Parse("WOP-RSA3072-SHA256");
        Assert.Throws<WopException>(() => AlgorithmSuite.Parse(null!));
        Assert.Throws<WopException>(() => SignHeader.Parse(null!));
        Assert.Throws<WopException>(() => EncryptHeader.Parse(null!));
        Assert.Throws<WopException>(() => KeyCodec.DecodeKeyMaterial(null!));
        Assert.Throws<WopException>(() => KeyCodec.ParseRsaPublicKey(null!, rsa));
        Assert.Throws<WopException>(() => KeyCodec.ParseRsaPrivateKey(null!, rsa));
        Assert.Throws<WopException>(() => KeyCodec.ParseSm2PublicKey(null!));
        Assert.Throws<WopException>(() => KeyCodec.ParseSm2PrivateKey(null!));

        // CanonicalRequest：method/uri null 按空串归一
        Assert.Equal("\nGET\n\n\n", CanonicalRequest.Build(null!, "get", null!, null!, null!));
    }

    [Fact]
    public void BuildRequest_method为null_拒绝()
    {
        var client = WopClientTests.RsaBuilder().Build();
        Assert.Throws<WopException>(() => client.BuildRequest(null!, "/p", null, SecurityLevel.L0));
        Assert.Throws<WopException>(() => client.BuildRequest("  ", "/p", null, SecurityLevel.L0));
    }

    // ==================== KeyCodec DER 解析失败 catch ====================

    [Fact]
    public void RSA密钥_合法base64但非SPKI_PKCS8_拒绝()
    {
        var rsa = AlgorithmSuite.Parse("WOP-RSA3072-SHA256");
        var notSpki = Convert.ToBase64String(new byte[] { 0x30, 0x03, 0x02, 0x01, 0x01 }); // 合法 DER 非 SPKI
        Assert.Throws<WopException>(() => KeyCodec.ParseRsaPublicKey(notSpki, rsa));
        Assert.Throws<WopException>(() => KeyCodec.ParseRsaPrivateKey(notSpki, rsa));
        // 非 DER 垃圾
        Assert.Throws<WopException>(() => KeyCodec.ParseRsaPublicKey(Convert.ToBase64String(new byte[20]), rsa));
        Assert.Throws<WopException>(() => KeyCodec.ParseRsaPrivateKey(Convert.ToBase64String(new byte[20]), rsa));
    }

    [Fact]
    public void PEM体含空行_容忍()
    {
        var b64 = Convert.ToBase64String(new byte[10]);
        var pem = "-----BEGIN PUBLIC KEY-----\n\n" + b64 + "\n\n-----END PUBLIC KEY-----";
        var rsa = AlgorithmSuite.Parse("WOP-RSA3072-SHA256");
        Assert.Throws<WopException>(() => KeyCodec.ParseRsaPublicKey(pem, rsa)); // 10B 非 SPKI → 拒绝，但 PEM 提取路径已走
    }

    // ==================== Envelope 转义全分支 ====================

    [Fact]
    public void Envelope_全转义集_合法跳过()
    {
        var body = "{\"a\":\"\\\"\\\\\\/\\b\\f\\n\\r\\t\",\"encrypted\":\"AA\"}";
        Assert.Equal("AA", EncryptedEnvelope.Extract(Encoding.UTF8.GetBytes(body)));
    }

    [Theory]
    [InlineData("  ")]        // 全空白
    [InlineData("{\"a")]      // 键截断
    public void Envelope_空与截断_拒绝(string body)
    {
        Assert.Throws<WopException>(() => EncryptedEnvelope.Extract(Encoding.UTF8.GetBytes(body)));
    }

    // ==================== Verify：无 body 响应全合法通过（wireBody null 归一） ====================

    [Fact]
    public void VerifyResponse_无body无digest_合法通过()
    {
        var client = WopClientTests.RsaBuilder().Build();
        var headers = new Dictionary<string, string>
        {
            [WopHeaders.AppKey] = "platform",
            [WopHeaders.Timestamp] = "1724900000001",
            [WopHeaders.Nonce] = "resp-nonce",
        };
        var signedNames = headers.Keys.OrderBy(k => k, StringComparer.Ordinal).ToList();
        var canonical = CanonicalRequest.Build("v1/1800", "GET", "/q", "",
            CanonicalRequest.CanonicalHeaders(signedNames.ToDictionary(n => n, n => headers[n])));
        var sig = WopCrypto.Sign(client.Suite, WopClientTests.RespKeyMaterial(client.Suite), Encoding.UTF8.GetBytes(canonical));
        headers[WopHeaders.Sign] = SignHeader.Build(client.Suite.SecurityReq, 1800, signedNames, sig);
        var result = client.VerifyResponse("GET", "/q", headers, null);
        Assert.True(result.Ok);
        Assert.Empty(result.Plaintext!);
    }

    [Fact]
    public void VerifyResponse_RSA公钥缺失分支_需定长签名先过()
    {
        // 构造 384B 签名（长度合法）但材料为 SM2 公钥 → RSA 验签公钥缺失 → Config
        var client = WopClientTests.RsaBuilder().Build();
        Assert.Throws<WopException>(() => WopCrypto.Verify(
            AlgorithmSuite.Parse("WOP-RSA3072-SHA256"),
            WopClientTests.RespPubMaterial(AlgorithmSuite.Parse("WOP-SM2-SM3")),
            Encoding.UTF8.GetBytes("m"), new string('A', 512)));
    }

    // ==================== Transport 单参构造 ====================

    [Fact]
    public void Transport_单参构造()
    {
        var t = new HttpClientTransport("https://gw.example.com");
        Assert.NotNull(t);
    }

    [Fact]
    public void VerifyCallback_path仅斜杠_拒绝()
    {
        var client = WopClientTests.RsaBuilder().Build();
        var result = client.VerifyCallback("https://example.com/", new Dictionary<string, string>(), null);
        Assert.False(result.Ok);
        Assert.Equal(WopErrorCode.Protocol, result.ErrorCode);
    }
}
