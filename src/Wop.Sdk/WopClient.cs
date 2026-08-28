using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Org.BouncyCastle.Security;

namespace Wop.Sdk;

/// <summary>WOP 商户客户端（协议核心门面）：出向 BuildRequest（L0/L2 信封）与
/// 入向 VerifyResponse/VerifyCallback（F6 固定顺序校验）。
/// 请求方向：商户私钥加签、平台公钥包 DEK；响应/回调方向：平台公钥验签、商户私钥解包。
/// 线程安全（不可变）。</summary>
public sealed class WopClient
{
    private readonly string _appKey;
    private readonly AlgorithmSuite _suite;
    private readonly AsymmetricKeyMaterial _merchantPrivate;
    private readonly AsymmetricKeyMaterial _platformPublic;
    private readonly long _expiredSeconds;
    private readonly Func<long> _clock;
    private readonly Func<string> _nonceGen;
    private readonly SecureRandom _random;

    internal WopClient(WopClientBuilder b)
    {
        _appKey = b.AppKeyValue;
        _suite = b.SuiteValue ?? throw new WopException(WopErrorCode.SuiteParse, "suite 未配置");
        _merchantPrivate = AsymmetricKeyMaterial.ParsePrivate(b.MerchantPrivateKeyValue ?? "", _suite);
        _platformPublic = AsymmetricKeyMaterial.ParsePublic(b.PlatformPublicKeyValue ?? "", _suite);
        _expiredSeconds = b.ExpiredSecondsValue;
        _clock = b.ClockValue;
        _nonceGen = b.NonceGenValue;
        _random = b.RandomValue;
    }

    /// <summary>已装配的算法套件（只读）。</summary>
    public AlgorithmSuite Suite => _suite;

    /// <summary>创建构建器。</summary>
    public static WopClientBuilder Builder() => new();

    // ==================== 出向 ====================

    /// <summary>构造请求草稿（headers + wireBody，零网络 IO；F9：CSPRNG nonce、毫秒时间戳、
    /// expiredSeconds 组装）。除 CSPRNG 值外同输入同输出（幂等）。
    /// D2：无 body（GET/空体）→ digest 头缺席；有 body 必产且必入 signedHeaders（I1）。
    /// L2 需要非空 body。</summary>
    public RequestDraft BuildRequest(string method, string path, byte[]? body, SecurityLevel level)
    {
        var upperMethod = (method ?? "").Trim().ToUpperInvariant();
        if (upperMethod.Length == 0)
        {
            throw new WopException(WopErrorCode.Config, "HTTP method 为空");
        }
        if (string.IsNullOrWhiteSpace(path))
        {
            throw new WopException(WopErrorCode.Config, "请求 path 为空");
        }
        var hasBody = body is { Length: > 0 };
        if (level == SecurityLevel.L2 && !hasBody)
        {
            throw new WopException(WopErrorCode.Config, "L2 加密需要非空 body");
        }

        var headers = new SortedDictionary<string, string>(StringComparer.Ordinal)
        {
            [WopHeaders.AppKey] = _appKey,
            [WopHeaders.Timestamp] = _clock().ToString(System.Globalization.CultureInfo.InvariantCulture),
            [WopHeaders.Nonce] = _nonceGen(),
        };

        byte[]? wireBody = null;
        if (level == SecurityLevel.L2)
        {
            var (wire, encryptHeader) = SealEnvelope(body!);
            wireBody = wire;
            headers[WopHeaders.Encrypt] = encryptHeader;
        }
        else if (hasBody)
        {
            wireBody = body;
        }

        if (wireBody is { Length: > 0 })
        {
            headers[WopHeaders.ContentDigest] = ContentDigest.BuildHeaderValue(_suite, wireBody); // D2/D3/I1
        }

        var authString = WopSignProtocol.Version + "/" +
                         _expiredSeconds.ToString(System.Globalization.CultureInfo.InvariantCulture);
        var canonical = CanonicalRequest.Build(authString, upperMethod, path, "",
            CanonicalRequest.CanonicalHeaders(headers));
        var signature = WopCrypto.Sign(_suite, _merchantPrivate, Encoding.UTF8.GetBytes(canonical));
        var signedNames = headers.Keys.ToList();
        var signHeader = SignHeader.Build(_suite.SecurityReq, _expiredSeconds, signedNames, signature);

        var outHeaders = new Dictionary<string, string>(headers, StringComparer.Ordinal)
        {
            [WopHeaders.Sign] = signHeader,
        };
        return new RequestDraft(upperMethod, path, outHeaders, wireBody);
    }

    /// <summary>L2 数字信封：CSPRNG CEK + IV（I4：IV 生成点唯一）→
    /// 套件报文策略全文加密 → JSON 信封 → 平台公钥包装 DEK。</summary>
    private (byte[] wireBody, string encryptHeader) SealEnvelope(byte[] plaintext)
    {
        var cek = new byte[_suite.CekLength];
        _random.NextBytes(cek);
        var iv = new byte[12];                       // GCM IV 12B（spec §3.3②）
        _random.NextBytes(iv);

        var sealedBytes = WopCrypto.SealMessage(_suite, plaintext, cek, iv);
        var wireBody = EncryptedEnvelope.Wrap(Codec.EncodeB64Url(sealedBytes));
        var dekPlain = Encoding.UTF8.GetBytes(DekPayload.Encode(_suite.MessageAlgorithm, cek, iv));
        var wrapped = WopCrypto.WrapDek(_suite, _platformPublic, dekPlain);
        return (wireBody, EncryptHeader.BuildL2(wrapped));
    }

    // ==================== 入向（F6：验签 → digest 复核 → DEK 解包 → alg 族比对 → bulk 解密） ====================

    /// <summary>校验网关响应。method/path 为商户原始请求的方法与路径
    /// （平台响应 canonical 复用请求 URI）。</summary>
    public VerifyResult VerifyResponse(string method, string path,
        IEnumerable<KeyValuePair<string, string>> headers, byte[]? body)
    {
        return Verify(method, path, headers, body);
    }

    /// <summary>校验平台回调：canonical URI 取回调 URL 的 path（不含 query），方法恒为 POST。</summary>
    public VerifyResult VerifyCallback(string callbackUrl,
        IEnumerable<KeyValuePair<string, string>> headers, byte[]? body)
    {
        string path;
        try
        {
            path = new Uri(callbackUrl, UriKind.Absolute).AbsolutePath;
        }
        catch (Exception)
        {
            return VerifyResult.Fail(new WopException(WopErrorCode.Protocol, "回调 URL 非法：" + callbackUrl));
        }
        if (string.IsNullOrEmpty(path) || path == "/")
        {
            return VerifyResult.Fail(new WopException(WopErrorCode.Protocol, "回调 URL 非法：" + callbackUrl));
        }
        return Verify("POST", path, headers, body);
    }

    /// <summary>一站式调用：BuildRequest → transport 发送 → VerifyResponse（F6）。</summary>
    public (VerifyResult Result, TransportResponse Response) Execute(IWopTransport transport,
        string method, string path, byte[]? body, SecurityLevel level)
    {
        if (transport == null)
        {
            throw new WopException(WopErrorCode.Config, "transport 为空");
        }
        var draft = BuildRequest(method, path, body, level);
        var response = transport.Send(draft);
        return (Verify(draft.Method, draft.Path, response.Headers, response.Body), response);
    }

    private VerifyResult Verify(string method, string path,
        IEnumerable<KeyValuePair<string, string>> headerPairs, byte[]? wireBody)
    {
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var (name, value) in headerPairs)
        {
            headers[name.ToLowerInvariant()] = value;
        }
        try
        {
            return VerifyInbound(method, path, headers, wireBody);
        }
        catch (WopException e)
        {
            return VerifyResult.Fail(e);
        }
    }

    private VerifyResult VerifyInbound(string method, string path,
        Dictionary<string, string> headers, byte[]? wireBody)
    {
        // 0. 结构化签名头解析 + 套件一致性
        var parsed = SignHeader.Parse(GetHeader(headers, WopHeaders.Sign));
        if (parsed.SecurityReq != _suite.SecurityReq)
        {
            throw new WopException(WopErrorCode.Protocol,
                "响应套件 " + parsed.SecurityReq + " 与客户端配置 " + _suite.SecurityReq + " 不符");
        }

        // 1. 结构前置校验（公开协议知识，明确拒绝；先于验签）：
        //    D2 有 body 必传 digest、I1 digest 必入 signedHeaders
        var hasBody = wireBody is { Length: > 0 };
        if (hasBody)
        {
            if (string.IsNullOrEmpty(GetHeader(headers, WopHeaders.ContentDigest)))
            {
                throw new WopException(WopErrorCode.DigestMismatch, "有响应体但缺少 x-wop-content-digest");
            }
            if (!parsed.SignedHeaders.Contains(WopHeaders.ContentDigest))
            {
                throw new WopException(WopErrorCode.Protocol,
                    "x-wop-content-digest 未列入 signedHeaders（I1）");
            }
        }
        else if (!string.IsNullOrEmpty(GetHeader(headers, WopHeaders.ContentDigest)))
        {
            throw new WopException(WopErrorCode.Protocol, "无响应体不应携带 x-wop-content-digest");
        }

        // 2. 验签（I2：先验签后解密）：按 signedHeaders 从真实响应头重建 canonical
        var signedMap = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var name in parsed.SignedHeaders)
        {
            var value = GetHeader(headers, name);
            if (string.IsNullOrEmpty(value))
            {
                throw new WopException(WopErrorCode.Protocol, "已签名头 " + name + " 在响应中缺失");
            }
            signedMap[name] = value;
        }
        var canonical = CanonicalRequest.Build(parsed.AuthString, method, path, "",
            CanonicalRequest.CanonicalHeaders(signedMap));
        WopCrypto.Verify(_suite, _platformPublic, Encoding.UTF8.GetBytes(canonical), parsed.Signature);

        // 3. digest 复核（D2/I5：格式 + 族耦合 + 值比对）
        if (hasBody)
        {
            ContentDigest.Validate(_suite, GetHeader(headers, WopHeaders.ContentDigest), wireBody!);
        }

        // 4-6. L2：DEK 解包 → alg 族比对（解包后、bulk 解密前，D8/I3）→ bulk 解密
        var encryptHeader = GetHeader(headers, WopHeaders.Encrypt);
        if (string.IsNullOrEmpty(encryptHeader))
        {
            return VerifyResult.Success(wireBody ?? Array.Empty<byte>());
        }
        var (_, dekB64Url) = EncryptHeader.Parse(encryptHeader);
        var payloadPlain = WopCrypto.UnwrapDek(_suite, _merchantPrivate, dekB64Url);   // I7：模糊
        var payload = DekPayload.Parse(Encoding.UTF8.GetString(payloadPlain));
        if (!payload.MatchesSuite(_suite))
        {
            throw new WopException(WopErrorCode.AlgMismatch,
                "dek alg " + payload.Alg + " 与套件 " + _suite.SecurityReq + " 族不符（期望 " +
                _suite.MessageAlgorithm + "）");
        }
        var cipherB64Url = EncryptedEnvelope.Extract(wireBody!);
        var ciphertext = Codec.DecodeB64Url(cipherB64Url);
        var plaintext = WopCrypto.OpenMessage(_suite, ciphertext, payload.Key, payload.Iv); // I7：模糊
        return VerifyResult.Success(plaintext);
    }

    private static string GetHeader(Dictionary<string, string> headers, string name)
    {
        return headers.TryGetValue(name, out var v) ? v : "";
    }
}

/// <summary>WopClient 构建器（spec §2 概念 API 的 .NET 惯用映射）。
/// 密钥入参为字符串（PEM 或 Base64 单行，D12）；Build 时原子装配（I6）。</summary>
public sealed class WopClientBuilder
{
    internal string AppKeyValue { get; private set; } = "";
    internal AlgorithmSuite? SuiteValue { get; private set; }
    internal string? MerchantPrivateKeyValue { get; private set; }
    internal string? PlatformPublicKeyValue { get; private set; }
    internal long ExpiredSecondsValue { get; private set; } = WopSignProtocol.ExpiredSecondsDefault;
    internal Func<long> ClockValue { get; private set; } = DefaultClock;
    internal Func<string> NonceGenValue { get; private set; } = DefaultNonce;
    internal SecureRandom RandomValue { get; private set; } = new();
    internal string? GatewayBaseUrlValue { get; private set; }

    private static long DefaultClock() => DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

    private static string DefaultNonce()
    {
        var bytes = new byte[16];
        new SecureRandom().NextBytes(bytes);
        return Codec.LowerHex(bytes);
    }

    /// <summary>商户 appKey。</summary>
    public WopClientBuilder AppKey(string appKey)
    {
        AppKeyValue = appKey;
        return this;
    }

    /// <summary>算法套件（securityReq，如 WOP-RSA3072-SHA256 / WOP-SM2-SM3）。</summary>
    public WopClientBuilder Suite(string securityReq)
    {
        SuiteValue = AlgorithmSuite.Parse(securityReq);
        return this;
    }

    /// <summary>商户私钥（PEM 或 Base64 单行）：请求加签 / 响应 DEK 解包。
    /// 解析延迟到 Build（I6：套件 + 双钥原子装配）。</summary>
    public WopClientBuilder MerchantPrivateKey(string material)
    {
        MerchantPrivateKeyValue = material;
        return this;
    }

    /// <summary>平台公钥（PEM 或 Base64 单行）：响应/回调验签 / DEK 包装。</summary>
    public WopClientBuilder PlatformPublicKey(string material)
    {
        PlatformPublicKeyValue = material;
        return this;
    }

    /// <summary>网关基地址（可选；仅 Execute 路径消费）。</summary>
    public WopClientBuilder GatewayBaseUrl(string baseUrl)
    {
        GatewayBaseUrlValue = baseUrl;
        return this;
    }

    /// <summary>签名有效时长（秒，默认 1800，上限 86400）。</summary>
    public WopClientBuilder ExpiredSeconds(long seconds)
    {
        ExpiredSecondsValue = seconds;
        return this;
    }

    /// <summary>固定时钟（联调/测试确定性钩子）。</summary>
    internal WopClientBuilder WithClock(Func<long> clock)
    {
        ClockValue = clock;
        return this;
    }

    /// <summary>固定 nonce 生成器（联调/测试确定性钩子）。</summary>
    internal WopClientBuilder WithNonce(Func<string> nonceGen)
    {
        NonceGenValue = nonceGen;
        return this;
    }

    /// <summary>构建客户端：套件原子装配 + 密钥格式/位数校验（错误均明确）。</summary>
    public WopClient Build()
    {
        if (string.IsNullOrWhiteSpace(AppKeyValue))
        {
            throw new WopException(WopErrorCode.Config, "appKey 为空");
        }
        if (SuiteValue == null)
        {
            throw new WopException(WopErrorCode.SuiteParse, "suite 未配置");
        }
        if (string.IsNullOrEmpty(MerchantPrivateKeyValue))
        {
            throw new WopException(WopErrorCode.Config, "商户私钥未配置");
        }
        if (string.IsNullOrEmpty(PlatformPublicKeyValue))
        {
            throw new WopException(WopErrorCode.Config, "平台公钥未配置");
        }
        if (ExpiredSecondsValue <= 0 || ExpiredSecondsValue > WopSignProtocol.ExpiredSecondsMax)
        {
            throw new WopException(WopErrorCode.Protocol,
                "expiredSeconds 超出允许范围 (0, " + WopSignProtocol.ExpiredSecondsMax + "]");
        }
        return new WopClient(this);
    }
}
