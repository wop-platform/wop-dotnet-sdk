using System;
using Org.BouncyCastle.Crypto.Digests;

namespace Wop.Sdk;

/// <summary>x-wop-content-digest（F4 / D2 / D3 / I1 / I5）：
/// 值结构 = 算法标记 + 恰一空格 + 小写 hex（32 字节摘要恒 64 位 hex）。
/// 标签与套件族强耦合：sha-256 仅 RSA 族、sm3 仅 SM2 族，跨族拒绝；
/// 摘要对象 = 线上原始报文字节（L2 时即密文载体）。</summary>
public static class ContentDigest
{
    /// <summary>按套件族计算摘要（④）：RSA 族 → SHA-256，SM2 族 → SM3。</summary>
    public static byte[] Compute(AlgorithmSuite suite, byte[] data)
    {
        var digest = suite.IsSm2 ? (object)new SM3Digest() : new Sha256Digest();
        byte[] hash;
        if (digest is SM3Digest sm3)
        {
            hash = new byte[sm3.GetDigestSize()];
            sm3.BlockUpdate(data, 0, data.Length);
            sm3.DoFinal(hash, 0);
        }
        else
        {
            var sha = (Sha256Digest)digest;
            hash = new byte[sha.GetDigestSize()];
            sha.BlockUpdate(data, 0, data.Length);
            sha.DoFinal(hash, 0);
        }
        return hash;
    }

    /// <summary>组装线上值：算法标记 + 恰一空格 + 小写 hex。</summary>
    public static string BuildHeaderValue(AlgorithmSuite suite, byte[] data)
    {
        return suite.DigestTag + " " + Codec.LowerHex(Compute(suite, data));
    }

    /// <summary>严格解析 digest 头值，返回 (tag, hex)。结构非法
    /// （双空格、大写、长度不符、未支持 tag 等）→ 协议类明确错误。</summary>
    public static (string Tag, string Hex) Parse(string value)
    {
        var sp = value.IndexOf(' ');
        if (sp < 0)
        {
            throw Invalid();
        }
        var tag = value.Substring(0, sp);
        if ((tag != "sha-256" && tag != "sm3") || value.Length != sp + 1 + 64)
        {
            throw Invalid();
        }
        var hex = value.Substring(sp + 1);
        foreach (var c in hex)
        {
            if (c < '0' || c > '9' && c < 'a' || c > 'f')
            {
                throw Invalid();
            }
        }
        return (tag, hex);
    }

    private static WopException Invalid() => new(WopErrorCode.Protocol,
        "x-wop-content-digest 格式非法：须为 <sha-256|sm3> + 恰一空格 + 64 位小写 hex");

    /// <summary>结构 + 套件族耦合校验（D2/I5，不含值比对）。</summary>
    public static void ValidateHeader(AlgorithmSuite suite, string headerValue)
    {
        var (tag, _) = Parse(headerValue);
        if (tag != suite.DigestTag)
        {
            throw new WopException(WopErrorCode.Protocol,
                "x-wop-content-digest 标签 " + tag + " 与套件 " + suite.SecurityReq + " 族不符（跨族拒绝）");
        }
    }

    /// <summary>复核线上报文摘要：结构（D2）→ 套件族耦合（I5）→ 常数时间值比对。
    /// 摘要不匹配返回完整性类明确错误。</summary>
    public static void Validate(AlgorithmSuite suite, string headerValue, byte[] wireBody)
    {
        ValidateHeader(suite, headerValue);
        var hex = headerValue.Substring(headerValue.IndexOf(' ') + 1);
        var computed = Codec.LowerHex(Compute(suite, wireBody));
        if (!ConstantTimeEquals(computed, hex))
        {
            throw new WopException(WopErrorCode.DigestMismatch, "x-wop-content-digest 与线上报文字节不匹配");
        }
    }

    private static bool ConstantTimeEquals(string a, string b)
    {
        if (a.Length != b.Length)
        {
            return false;
        }
        var diff = 0;
        for (var i = 0; i < a.Length; i++)
        {
            diff |= a[i] ^ b[i];
        }
        return diff == 0;
    }
}
