using System;

namespace Wop.Sdk;

/// <summary>加密指令头 x-wop-encrypt: L2;dek=&lt;base64url&gt;（F5）。</summary>
public static class EncryptHeader
{
    private const string Prefix = "L2;dek=";

    /// <summary>组装 L2 加密指令头。</summary>
    public static string BuildL2(string dekB64Url)
    {
        return Prefix + dekB64Url;
    }

    /// <summary>解析加密指令头：仅支持 L2 且必带 dek；
    /// dek 段字符集前置校验（b64url 无填充，快速失败）。</summary>
    public static (string Level, string DekB64Url) Parse(string value)
    {
        var v = (value ?? "").Trim();
        if (!v.StartsWith(Prefix, StringComparison.Ordinal) || v.Length == Prefix.Length)
        {
            throw new WopException(WopErrorCode.Protocol, "x-wop-encrypt 须为 L2;dek=<base64url>");
        }
        var dek = v.Substring(Prefix.Length);
        foreach (var c in dek)
        {
            var ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
                     || (c >= '0' && c <= '9') || c == '-' || c == '_';
            if (!ok)
            {
                throw new WopException(WopErrorCode.Protocol, "x-wop-encrypt dek 段须为 base64url 无填充");
            }
        }
        return ("L2", dek);
    }
}
