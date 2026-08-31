using System;
using System.Collections.Generic;
using System.Linq;

namespace Wop.Sdk;

/// <summary>结构化签名头 x-wop-sign（F3）：
/// &lt;securityReq&gt; &lt;protocolVersion&gt;/&lt;expiredSeconds&gt;/&lt;signedHeaders&gt;/&lt;signature&gt;
/// 示例：WOP-RSA3072-SHA256 v1/1800/x-wop-appkey;x-wop-nonce/pOVoj1mI...
/// 解析与网关 SignHeaderParser 严格语义对齐（trim 容忍、v1 钉死、段数与范围校验）。</summary>
public sealed class SignHeader
{
    /// <summary>原始套件标识。</summary>
    public string SecurityReq { get; }

    /// <summary>协议版本（恒 v1）。</summary>
    public string ProtocolVersion { get; }

    /// <summary>签名有效时长（秒）。</summary>
    public long ExpiredSeconds { get; }

    /// <summary>参与签名的头名称列表（已 lowercase、去空）。</summary>
    public IReadOnlyList<string> SignedHeaders { get; }

    /// <summary>签名（base64url 无填充原串）。</summary>
    public string Signature { get; }

    private SignHeader(string securityReq, string protocolVersion, long expiredSeconds,
        IReadOnlyList<string> signedHeaders, string signature)
    {
        SecurityReq = securityReq;
        ProtocolVersion = protocolVersion;
        ExpiredSeconds = expiredSeconds;
        SignedHeaders = signedHeaders;
        Signature = signature;
    }

    /// <summary>authString = protocolVersion/expiredSeconds。</summary>
    public string AuthString => ProtocolVersion + "/" + ExpiredSeconds.ToString(System.Globalization.CultureInfo.InvariantCulture);

    /// <summary>严格解析 x-wop-sign 值；结构非法为协议类明确错误。</summary>
    public static SignHeader Parse(string header)
    {
        var trimmed = (header ?? "").Trim();
        if (trimmed.Length == 0)
        {
            throw new WopException(WopErrorCode.Protocol, "缺少 x-wop-sign 头");
        }
        var sp = trimmed.IndexOf(' ');
        if (sp <= 0)
        {
            throw new WopException(WopErrorCode.Protocol,
                "x-wop-sign 格式错误：缺少 securityReq 与 authString 的空格分隔");
        }
        var securityReq = trimmed.Substring(0, sp);
        // 签名为 base64url（无 '/'），SplitN 4 段安全
        var seg = trimmed.Substring(sp + 1).Trim().Split(new[] { '/' }, 4);
        if (seg.Length != 4)
        {
            throw new WopException(WopErrorCode.Protocol,
                "x-wop-sign 格式错误：应为 <protocolVersion>/<expiredSeconds>/<signedHeaders>/<signature>");
        }
        if (seg[0] != WopSignProtocol.Version)
        {
            throw new WopException(WopErrorCode.Protocol, "不支持的签名协议版本 " + seg[0]);
        }
        if (!long.TryParse(seg[1], out var expiredSeconds))
        {
            throw new WopException(WopErrorCode.Protocol, "expiredSeconds 非法 " + seg[1]);
        }
        if (expiredSeconds <= 0 || expiredSeconds > WopSignProtocol.ExpiredSecondsMax)
        {
            throw new WopException(WopErrorCode.Protocol,
                "expiredSeconds 超出允许范围 (0, " + WopSignProtocol.ExpiredSecondsMax + "]");
        }
        var signedHeaders = ParseSignedHeaders(seg[2]);
        if (signedHeaders.Count == 0)
        {
            throw new WopException(WopErrorCode.Protocol, "signedHeaders 为空");
        }
        if (seg[3].Trim().Length == 0)
        {
            throw new WopException(WopErrorCode.Protocol, "signature 为空");
        }
        return new SignHeader(securityReq, seg[0], expiredSeconds, signedHeaders, seg[3]);
    }

    /// <summary>解析 signedHeaders 段：分号切分、trim、lowercase、剔空。</summary>
    private static IReadOnlyList<string> ParseSignedHeaders(string raw)
    {
        var parts = raw.Split(';');
        var list = new List<string>(parts.Length);
        foreach (var p in parts)
        {
            var name = p.Trim().ToLowerInvariant();
            if (name.Length > 0)
            {
                list.Add(name);
            }
        }
        return list;
    }

    /// <summary>组装 x-wop-sign 值（signedHeaders 须已排序去重）。</summary>
    public static string Build(string securityReq, long expiredSeconds,
        IReadOnlyList<string> signedHeaders, string signature)
    {
        return securityReq + " " + WopSignProtocol.Version + "/" +
               expiredSeconds.ToString(System.Globalization.CultureInfo.InvariantCulture) +
               "/" + string.Join(";", signedHeaders) + "/" + signature;
    }
}
