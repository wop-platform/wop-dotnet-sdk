using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.Json;
using Wop.Sdk;
using Xunit;

/// <summary>错误契约测试（变异测试杀 message 类变异）：
/// WopException.Message 是商户可编程排查的对外语义（spec §10.2），
/// 每条错误路径断言 ErrorCode + Message 关键词非空——message 置空/漂移即测试失败。
/// 覆盖明确类错误的全部构造点（I7 模糊类文案已由 InvariantsTests 钉死）。</summary>
public class ErrorContractTests
{
    static readonly JsonElement Keys = JsonDocument.Parse(File.OpenRead(
        Path.Combine(AppContext.BaseDirectory, "fixtures", "crypto-vectors.json"))).RootElement.GetProperty("keys");

    static string K(string name, string field) => Keys.GetProperty(name).GetProperty(field).GetString()!;

    static readonly byte[] Body = Encoding.UTF8.GetBytes("{\"k\":1}");

    static WopException Rex(Action a) => Assert.Throws<WopException>(a);

    static void Rex(Action a, WopErrorCode code, string keyword)
    {
        var ex = Rex(a);
        Assert.Equal(code, ex.ErrorCode);
        Assert.Contains(keyword, ex.Message);
    }

    // ==================== AlgorithmSuite（F1） ====================
// spec:F1

    [Fact]
    public void 契约_suite空值() => Rex(() => AlgorithmSuite.Parse(null!), WopErrorCode.SuiteParse, "为空");

    [Fact]
    public void 契约_suite格式非法() => Rex(() => AlgorithmSuite.Parse("bad"), WopErrorCode.SuiteParse, "格式非法");

    [Fact]
    public void 契约_suite组合不支持() =>
        Rex(() => AlgorithmSuite.Parse("WOP-RSA3072-SM3"), WopErrorCode.SuiteUnsupported, "不支持的算法组合");

    // ==================== Codec（F7/D1） ====================
// spec:F7 D1

    [Fact]
    public void 契约_b64url非法字符() => Rex(() => Codec.DecodeB64Url("AB+"), WopErrorCode.Protocol, "非法字符");

    [Fact]
    public void 契约_b64url长度非法() => Rex(() => Codec.DecodeB64Url("A"), WopErrorCode.Protocol, "长度非法");

    [Fact]
    public void 契约_b64url尾随位() => Rex(() => Codec.DecodeB64Url("abd"), WopErrorCode.Protocol, "尾随位");

    // ==================== ContentDigest（F4/D2） ====================
// spec:F4 D2 I5

    [Fact]
    public void 契约_digest格式非法() =>
        Rex(() => ContentDigest.Parse("no-space"), WopErrorCode.Protocol, "格式非法");

    [Fact]
    public void 契约_digest跨族标签()
    {
        var sm2 = AlgorithmSuite.Parse("WOP-SM2-SM3");
        var hex = Codec.LowerHex(ContentDigest.Compute(sm2, Body));
        var ex = Rex(() => ContentDigest.ValidateHeader(
            AlgorithmSuite.Parse("WOP-RSA3072-SHA256"), "sm3 " + hex));
        Assert.Equal(WopErrorCode.Protocol, ex.ErrorCode);
        Assert.Contains("族不符", ex.Message);
        Assert.Contains("标签", ex.Message);
        Assert.Contains("与套件", ex.Message);
    }

    [Fact]
    public void 契约_digest值不匹配()
    {
        var rsa = AlgorithmSuite.Parse("WOP-RSA3072-SHA256");
        var wrong = Codec.LowerHex(ContentDigest.Compute(rsa, Encoding.UTF8.GetBytes("other")));
        Rex(() => ContentDigest.Validate(rsa, "sha-256 " + wrong, Body),
            WopErrorCode.DigestMismatch, "不匹配");
    }

    // ==================== DekPayload（F5） ====================
// spec:F5 I3

    [Fact]
    public void 契约_dek段数() => Rex(() => DekPayload.Parse("AES-256-GCM$k"), WopErrorCode.Protocol, "三段");

    [Fact]
    public void 契约_dek算法未支持() =>
        Rex(() => DekPayload.Parse("FOO$" + Codec.EncodeB64Url(new byte[32]) + "$" + Codec.EncodeB64Url(new byte[12])),
            WopErrorCode.Protocol, "未支持");

    [Fact]
    public void 契约_dekKey长度()
    {
        var ex = Rex(() => DekPayload.Parse("AES-256-GCM$" + Codec.EncodeB64Url(new byte[16])
            + "$" + Codec.EncodeB64Url(new byte[12])));
        Assert.Equal(WopErrorCode.Protocol, ex.ErrorCode);
        Assert.Contains("key 长度", ex.Message);
        Assert.Contains("与算法", ex.Message);
        Assert.Contains("要求", ex.Message);
        Assert.Contains("不符", ex.Message);
    }

    [Fact]
    public void 契约_dekIv长度()
    {
        var ex = Rex(() => DekPayload.Parse("AES-256-GCM$" + Codec.EncodeB64Url(new byte[32])
            + "$" + Codec.EncodeB64Url(new byte[8])));
        Assert.Equal(WopErrorCode.Protocol, ex.ErrorCode);
        Assert.Contains("iv 长度", ex.Message);
        Assert.Contains("GCM 要求的 12 不符", ex.Message);
    }

    // ==================== EncryptedEnvelope（F5/D3） ====================
// spec:F5 D3

    static void EnvelopeRex(string body, string keyword) =>
        Rex(() => EncryptedEnvelope.Extract(Encoding.UTF8.GetBytes(body)), WopErrorCode.Protocol, keyword);

    [Theory]
    [InlineData("[]", "JSON 对象")]
    [InlineData("{\"a\" 1}", "结构非法")]            // 缺冒号
    [InlineData("x1", "JSON 对象")]                  // 非 JSON 对象开头
    [InlineData("{\"encrypted\":\"\"}", "encrypted 为空")]
    [InlineData("{\"a\":1}", "缺少 encrypted")]
    [InlineData("{\"a\":\"AA\",x", "JSON 字符串结构非法")]
    [InlineData("{\"a\":\"x\\", "转义非法")]          // 转义后截断
    [InlineData("{\"a\":\"\\u12", "转义非法")]        // \u 后不足 4 字符
    [InlineData("{\"a\":\"\\uZZZZ\"}", "转义非法")]   // 非 hex
    [InlineData("{\"a\":\"\\q\"}", "转义非法")]       // 未知转义
    [InlineData("{\"a\":\"x", "未闭合")]
    [InlineData("{\"encrypted\":\"!!\"}", "base64url")]
    public void 契约_信封错误(string body, string keyword) => EnvelopeRex(body, keyword);

    [Fact]
    public void 契约_信封未转义控制字符()
    {
        Rex(() => EncryptedEnvelope.Extract(Encoding.UTF8.GetBytes("{\"a\":\"a\u0001b\",\"encrypted\":\"AA\"}")),
            WopErrorCode.Protocol, "控制字符");
    }

    // ==================== KeyCodec（D12） ====================
// spec:D12

    [Theory]
    [InlineData("  ")]
    [InlineData(null)]
    public void 契约_密钥材料为空(string? material) =>
        Rex(() => KeyCodec.DecodeKeyMaterial(material!), WopErrorCode.Config, "为空");

    [Fact]
    public void 契约_密钥Base64解码失败() =>
        Rex(() => KeyCodec.DecodeKeyMaterial("!!!not-base64!!!"), WopErrorCode.Config, "Base64 解码失败");

    [Fact]
    public void 契约_rsa公钥解析失败()
    {
        Rex(() => KeyCodec.ParseRsaPublicKey(Convert.ToBase64String(new byte[8]),
                AlgorithmSuite.Parse("WOP-RSA3072-SHA256")),
            WopErrorCode.Config, "RSA 公钥解析失败");
    }

    [Fact]
    public void 契约_rsa私钥解析失败()
    {
        Rex(() => KeyCodec.ParseRsaPrivateKey(Convert.ToBase64String(new byte[8]),
                AlgorithmSuite.Parse("WOP-RSA3072-SHA256")),
            WopErrorCode.Config, "RSA 私钥解析失败");
    }

    [Fact]
    public void 契约_rsa位数不符()
    {
        var ex = Assert.Throws<WopException>(() => WopClient.Builder()
            .AppKey("a").Suite("WOP-RSA3072-SHA256")
            .MerchantPrivateKey(K("rsa4096", "privatePkcs8B64"))
            .PlatformPublicKey(K("rsa3072", "publicSpkiB64"))
            .Build());
        Assert.Equal(WopErrorCode.Config, ex.ErrorCode);
        Assert.Contains("位数", ex.Message);
        Assert.Contains("与套件", ex.Message);
        Assert.Contains("要求", ex.Message);
        Assert.Contains("位不符", ex.Message);
    }

    [Fact]
    public void 契约_sm2公钥未压缩点()
    {
        var wrong = new byte[65];
        wrong[0] = 0x03;   // 非法前缀（65B 但非 04：杀 ||→&& 变异）
        var ex = Rex(() => KeyCodec.ParseSm2PublicKey(Convert.ToBase64String(wrong)));
        Assert.Equal(WopErrorCode.Config, ex.ErrorCode);
        Assert.Contains("未压缩点", ex.Message);
        Assert.Contains("共 65 字节", ex.Message);
        Assert.Contains("实际", ex.Message);
        Assert.EndsWith(" 字节", ex.Message);
    }

    [Fact]
    public void 契约_sm2公钥点非法()
    {
        var offCurve = new byte[65];
        offCurve[0] = 0x04;
        for (var i = 1; i < 65; i++) offCurve[i] = (byte)(i * 7 + 3);
        Rex(() => KeyCodec.ParseSm2PublicKey(Convert.ToBase64String(offCurve)),
            WopErrorCode.Config, "点非法");
    }

    [Fact]
    public void 契约_sm2私钥长度()
    {
        var ex = Rex(() => KeyCodec.ParseSm2PrivateKey(Convert.ToBase64String(new byte[31])));
        Assert.Equal(WopErrorCode.Config, ex.ErrorCode);
        Assert.Contains("32 字节", ex.Message);
        Assert.Contains("实际", ex.Message);
        Assert.EndsWith(" 字节", ex.Message);
    }

    [Fact]
    public void 契约_sm2私钥d零() =>
        Rex(() => KeyCodec.ParseSm2PrivateKey(Convert.ToBase64String(new byte[32])),
            WopErrorCode.Config, "[1, n-1]");

    [Fact]
    public void 契约_sm2私钥d等于N()
    {
        var n = Sm2Params.Domain.N.ToByteArrayUnsigned();
        Rex(() => KeyCodec.ParseSm2PrivateKey(Convert.ToBase64String(n)),
            WopErrorCode.Config, "[1, n-1]");
    }

    // ==================== SignHeader（F3） ====================
// spec:F3

    [Theory]
    [InlineData("", "缺少 x-wop-sign")]
    [InlineData("noversion", "空格分隔")]
    [InlineData("X v9/1800/a/b", "签名协议版本")]
    [InlineData("X v1/abc/a/b", "expiredSeconds 非法")]
    [InlineData("X v1/1800//sig", "signedHeaders 为空")]
    [InlineData("X v1/1800/a/", "signature 为空")]
    public void 契约_签名头错误(string header, string keyword) =>
        Rex(() => SignHeader.Parse(header), WopErrorCode.Protocol, keyword);

    [Fact]
    public void 契约_签名头null_缺少头()
    {
        Rex(() => SignHeader.Parse(null!), WopErrorCode.Protocol, "缺少 x-wop-sign");
    }

    [Fact]
    public void 契约_expiredSeconds范围全段文案()
    {
        var ex = Assert.Throws<WopException>(() => SignHeader.Parse("X v1/0/a/b"));
        Assert.Equal(WopErrorCode.Protocol, ex.ErrorCode);
        Assert.Contains("超出允许范围", ex.Message);
        Assert.Contains("(0,", ex.Message);
        Assert.Contains("]", ex.Message);
    }

    // ==================== EncryptHeader（F5） ====================
// spec:F5

    [Fact]
    public void 契约_加密头格式() =>
        Rex(() => EncryptHeader.Parse("garbage"), WopErrorCode.Protocol, "须为 L2");

    [Fact]
    public void 契约_加密头dek段() =>
        Rex(() => EncryptHeader.Parse("L2;dek=A*B"), WopErrorCode.Protocol, "dek 段");


    // ==================== Transport（Q1/D4） ====================
    // spec:Q1 D4

    [Fact]
    public void 契约_transport_HttpClient为空() =>
        Rex(() => new HttpClientTransport((System.Net.Http.HttpClient)null!, "https://x"),
            WopErrorCode.Config, "HttpClient 为空");

    [Fact]
    public void 契约_响应体恰超上限_明确文案()
    {
        // 恰 MaxResponseBytes+1 字节：读满 limit 不触发流中断，由长度检查给出"上限"文案
        var payload = new byte[HttpClientTransport.MaxResponseBytes + 1];
        var response = new System.Net.Http.HttpResponseMessage(System.Net.HttpStatusCode.OK)
        {
            Content = new System.Net.Http.ByteArrayContent(payload),
        };
        var transport = new HttpClientTransport(
            new RelayHandler(response), "https://gw.example.com");
        var draft = WopClientTests.RsaBuilder().Build().BuildRequest("GET", "/q", null, SecurityLevel.L0);
        Rex(() => transport.Send(draft), WopErrorCode.Protocol, "上限");
    }

    [Fact]
    public void 契约_响应体读取中断_超限文案()
    {
        var response = new System.Net.Http.HttpResponseMessage(System.Net.HttpStatusCode.OK)
        {
            Content = new EndlessContent(),
        };
        var transport = new HttpClientTransport(
            new RelayHandler(response), "https://gw.example.com");
        var draft = WopClientTests.RsaBuilder().Build().BuildRequest("GET", "/q", null, SecurityLevel.L0);
        Rex(() => transport.Send(draft), WopErrorCode.Protocol, "超限");
    }

    /// <summary>读不完的流（D5：限额生效于读取过程中）。</summary>
    sealed class EndlessContent : System.Net.Http.HttpContent
    {
        protected override System.Threading.Tasks.Task<Stream> CreateContentReadStreamAsync()
            => System.Threading.Tasks.Task.FromResult<Stream>(new EndlessStream());

        protected override System.Threading.Tasks.Task SerializeToStreamAsync(Stream stream, System.Net.TransportContext? context)
            => throw new InvalidOperationException();

        protected override bool TryComputeLength(out long length)
        {
            length = 0;
            return false;
        }
    }

    sealed class EndlessStream : Stream
    {
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override int Read(byte[] buffer, int offset, int count)
        {
            Array.Clear(buffer, offset, count);
            return count;
        }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) { }
        public override void Write(byte[] buffer, int offset, int count) { }
    }

    sealed class RelayHandler : System.Net.Http.HttpMessageHandler
    {
        private readonly System.Net.Http.HttpResponseMessage _response;
        internal RelayHandler(System.Net.Http.HttpResponseMessage response) => _response = response;
        protected override System.Threading.Tasks.Task<System.Net.Http.HttpResponseMessage> SendAsync(
            System.Net.Http.HttpRequestMessage request, System.Threading.CancellationToken ct)
            => System.Threading.Tasks.Task.FromResult(_response);
    }

    // ==================== WopClient / Builder（I6） ====================
// spec:I6 F9 F6

    [Fact]
    public void 契约_未配置任何项_appKey为空() =>
        Rex(() => WopClient.Builder().Build(), WopErrorCode.Config, "appKey 为空");

    [Fact]
    public void 契约_缺套件() =>
        Rex(() => WopClient.Builder().AppKey("a").Build(), WopErrorCode.SuiteParse, "suite 未配置");

    [Fact]
    public void 契约_缺商户私钥() =>
        Rex(() => WopClient.Builder().AppKey("a").Suite("WOP-RSA3072-SHA256").Build(),
            WopErrorCode.Config, "商户私钥未配置");

    [Fact]
    public void 契约_缺平台公钥() =>
        Rex(() => WopClient.Builder().AppKey("a").Suite("WOP-RSA3072-SHA256")
                .MerchantPrivateKey(K("rsa3072", "privatePkcs8B64")).Build(),
            WopErrorCode.Config, "平台公钥未配置");

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void 契约_expiredSeconds越下界(long v)
    {
        var ex = Assert.Throws<WopException>(() =>
            WopClientTests.RsaBuilder().ExpiredSeconds(v).Build());
        Assert.Equal(WopErrorCode.Protocol, ex.ErrorCode);
        Assert.Contains("超出允许范围", ex.Message);
        Assert.Contains("(0,", ex.Message);
        Assert.Contains("]", ex.Message);
    }

    [Fact]
    public void 契约_method为空() =>
        Rex(() => WopClientTests.RsaBuilder().Build().BuildRequest(" ", "/p", Body, SecurityLevel.L0),
            WopErrorCode.Config, "method 为空");

    [Fact]
    public void 契约_path为空() =>
        Rex(() => WopClientTests.RsaBuilder().Build().BuildRequest("POST", "  ", Body, SecurityLevel.L0),
            WopErrorCode.Config, "path 为空");

    [Fact]
    public void 契约_L2需要非空body() =>
        Rex(() => WopClientTests.RsaBuilder().Build().BuildRequest("POST", "/p", null, SecurityLevel.L2),
            WopErrorCode.Config, "非空 body");

    [Fact]
    public void 契约_execute_transport为空() =>
        Rex(() => WopClientTests.RsaBuilder().Build().Execute(null!, "POST", "/p", Body, SecurityLevel.L0),
            WopErrorCode.Config, "transport 为空");

    [Theory]
    [InlineData("::::bad")]     // Uri 解析失败（143 行）
    [InlineData("https://gw.example.com/")]   // 根路径（145 行）
    public void 契约_回调URL非法文案(string url)
    {
        var r = WopClientTests.RsaBuilder().Build()
            .VerifyCallback(url, new Dictionary<string, string>(), null);
        Assert.False(r.Ok);
        Assert.Equal(WopErrorCode.Protocol, r.ErrorCode);
        Assert.Contains("回调 URL 非法", r.Reason);
    }

    // ==================== WopCrypto（internal，F3/F5） ====================
// spec:F3 F5

    static AsymmetricKeyMaterial RsaPrivMat() =>
        AsymmetricKeyMaterial.ParsePrivate(K("rsa3072", "privatePkcs8B64"), AlgorithmSuite.Parse("WOP-RSA3072-SHA256"));

    static AsymmetricKeyMaterial Sm2PrivMat() =>
        AsymmetricKeyMaterial.ParsePrivate(K("sm2", "privateDB64"), AlgorithmSuite.Parse("WOP-SM2-SM3"));

    [Fact]
    public void 契约_SM2套件缺少私钥()
    {
        Rex(() => WopCrypto.Sign(AlgorithmSuite.Parse("WOP-SM2-SM3"), RsaPrivMat(), Body),
            WopErrorCode.Config, "SM2 套件缺少私钥");
    }

    [Fact]
    public void 契约_RSA套件缺少私钥()
    {
        Rex(() => WopCrypto.Sign(AlgorithmSuite.Parse("WOP-RSA3072-SHA256"), Sm2PrivMat(), Body),
            WopErrorCode.Config, "RSA 套件缺少私钥");
    }

    [Fact]
    public void 契约_SM2套件缺少验签公钥()
    {
        Rex(() => WopCrypto.Verify(AlgorithmSuite.Parse("WOP-SM2-SM3"), RsaPrivMat(), Body,
            Codec.EncodeB64Url(new byte[64])), WopErrorCode.Config, "SM2 套件缺少验签公钥");
    }

    [Fact]
    public void 契约_RSA套件缺少验签公钥()
    {
        Rex(() => WopCrypto.Verify(AlgorithmSuite.Parse("WOP-RSA3072-SHA256"), Sm2PrivMat(), Body,
            Codec.EncodeB64Url(new byte[384])), WopErrorCode.Config, "RSA 套件缺少验签公钥");
    }

    [Fact]
    public void 契约_签名定长文案()
    {
        var ex = Assert.Throws<WopException>(() => WopCrypto.Verify(
            AlgorithmSuite.Parse("WOP-RSA3072-SHA256"),
            AsymmetricKeyMaterial.ParsePublic(K("rsa3072", "publicSpkiB64"),
                AlgorithmSuite.Parse("WOP-RSA3072-SHA256")),
            Body, Codec.EncodeB64Url(new byte[63])));
        Assert.Equal(WopErrorCode.Protocol, ex.ErrorCode);
        Assert.Contains("签名长度", ex.Message);
        Assert.Contains("字节与套件", ex.Message);
        Assert.Contains("定长", ex.Message);
        Assert.Contains("字节不符", ex.Message);
    }

    [Fact]
    public void 契约_对称密钥长度()
    {
        var ex = Assert.Throws<WopException>(() => WopCrypto.SealMessage(
            AlgorithmSuite.Parse("WOP-RSA3072-SHA256"), Body, new byte[16], new byte[12]));
        Assert.Equal(WopErrorCode.Config, ex.ErrorCode);
        Assert.Contains("对称密钥长度", ex.Message);
        Assert.Contains("与套件要求的", ex.Message);
        Assert.Contains("不符", ex.Message);
    }

    [Fact]
    public void 契约_IV长度()
    {
        var ex = Assert.Throws<WopException>(() => WopCrypto.SealMessage(
            AlgorithmSuite.Parse("WOP-RSA3072-SHA256"), Body, new byte[32], new byte[8]));
        Assert.Equal(WopErrorCode.Config, ex.ErrorCode);
        Assert.Contains("IV 长度", ex.Message);
        Assert.Contains("12 字节", ex.Message);
    }

    [Fact]
    public void 契约_SM2套件缺少DEK包装公钥()
    {
        Rex(() => WopCrypto.WrapDek(AlgorithmSuite.Parse("WOP-SM2-SM3"), RsaPrivMat(), Body),
            WopErrorCode.Config, "SM2 套件缺少 DEK 包装公钥");
    }

    [Fact]
    public void 契约_RSA套件缺少DEK包装公钥()
    {
        Rex(() => WopCrypto.WrapDek(AlgorithmSuite.Parse("WOP-RSA3072-SHA256"), Sm2PrivMat(), Body),
            WopErrorCode.Config, "RSA 套件缺少 DEK 包装公钥");
    }

    [Fact]
    public void 契约_固定k范围()
    {
        Rex(() => WopCrypto.Sign(AlgorithmSuite.Parse("WOP-SM2-SM3"), Sm2PrivMat(), Body,
            fixedK: Org.BouncyCastle.Math.BigInteger.Zero), WopErrorCode.Config, "固定 k");
    }

    [Fact]
    public void 契约_固定k等于N_拒绝()
    {
        // k = n 落在 [1, n-1] 之外：必须明确拒绝（杀 >= → > 边界变异）
        Rex(() => WopCrypto.Sign(AlgorithmSuite.Parse("WOP-SM2-SM3"), Sm2PrivMat(), Body,
            fixedK: Sm2Params.Domain.N), WopErrorCode.Config, "固定 k");
    }

    // ==================== WopException ToString ====================
// spec:I7

    [Fact]
    public void 契约_ToString格式()
    {
        var ex = new WopException(WopErrorCode.Config, "x");
        Assert.Equal("wop: [CONFIG] x", ex.ToString());
    }
}
