using System;
using System.Collections.Generic;

namespace Wop.Sdk;

/// <summary>DEK 载荷（spec §6.1）：alg$base64url(key)$base64url(iv)。
/// '$' 不在 Base64URL 字母表中，分隔符无碰撞。</summary>
public sealed class DekPayload
{
    private static readonly IReadOnlyDictionary<string, int> AlgKeyLengths =
        new Dictionary<string, int>
        {
            ["AES-256-GCM"] = 32,
            ["SM4-GCM"] = 16,
        };

    /// <summary>报文对称算法标识（AES-256-GCM / SM4-GCM）。</summary>
    public string Alg { get; }

    /// <summary>对称密钥。</summary>
    public byte[] Key { get; }

    /// <summary>GCM IV。</summary>
    public byte[] Iv { get; }

    private DekPayload(string alg, byte[] key, byte[] iv)
    {
        Alg = alg;
        Key = key;
        Iv = iv;
    }

    /// <summary>校验载荷 alg 与套件族一致（I3/I5：AES-256-GCM↔RSA、SM4-GCM↔SM2）。</summary>
    public bool MatchesSuite(AlgorithmSuite suite) => Alg == suite.MessageAlgorithm;

    /// <summary>组装线上载荷串。</summary>
    public static string Encode(string alg, byte[] key, byte[] iv)
    {
        return alg + "$" + Codec.EncodeB64Url(key) + "$" + Codec.EncodeB64Url(iv);
    }

    /// <summary>严格解析载荷：恰三段、算法已知、key/iv 长度匹配、b64url 严格。
    /// 结构非法为协议类明确错误（解析时序：解包之后、bulk 解密之前，D8）。</summary>
    public static DekPayload Parse(string payload)
    {
        var parts = payload.Split('$');
        if (parts.Length != 3)
        {
            throw new WopException(WopErrorCode.Protocol, "DEK 载荷须为 alg$key$iv 三段");
        }
        var alg = parts[0];
        if (!AlgKeyLengths.TryGetValue(alg, out var keyLen))
        {
            throw new WopException(WopErrorCode.Protocol, "DEK 载荷 alg 未支持：" + alg);
        }
        var key = Codec.DecodeB64Url(parts[1]);
        var iv = Codec.DecodeB64Url(parts[2]);
        if (key.Length != keyLen)
        {
            throw new WopException(WopErrorCode.Protocol,
                "DEK 载荷 key 长度 " + key.Length + " 与算法 " + alg + " 要求的 " + keyLen + " 不符");
        }
        if (iv.Length != 12)
        {
            throw new WopException(WopErrorCode.Protocol,
                "DEK 载荷 iv 长度 " + iv.Length + " 与 GCM 要求的 12 不符");
        }
        return new DekPayload(alg, key, iv);
    }
}
