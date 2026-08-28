using System;
using System.Text;

namespace Wop.Sdk;

/// <summary>线上编码契约（spec §3.4 / D10）：二进制一律 base64url 无填充，
/// 严格模式拒收 '=' 与标准字母表字符；十六进制统一小写。</summary>
public static class Codec
{
    private static readonly char[] HexLower = "0123456789abcdef".ToCharArray();

    /// <summary>编码为 base64url 无填充。</summary>
    public static string EncodeB64Url(byte[] data)
    {
        return Convert.ToBase64String(data)
            .Replace('+', '-').Replace('/', '_')
            .TrimEnd('=');
    }

    /// <summary>严格解码 base64url 无填充：含 '='、'+'、'/'、空白或长度非法（%4==1）
    /// 一律拒绝（F6/F7 负向量锚点）。</summary>
    public static byte[] DecodeB64Url(string s)
    {
        foreach (var c in s)
        {
            var ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
                     || (c >= '0' && c <= '9') || c == '-' || c == '_';
            if (!ok)
            {
                throw new WopException(WopErrorCode.Protocol,
                    "base64url 串含非法字符（须无填充、URL 字母表）");
            }
        }
        if (s.Length % 4 == 1)
        {
            throw new WopException(WopErrorCode.Protocol, "base64url 串长度非法（%4==1）");
        }
        var std = new StringBuilder(s.Length + 3)
            .Append(s).Replace('-', '+').Replace('_', '/');
        var pad = (4 - std.Length % 4) % 4;
        std.Append('=', pad);
        // 预检（字符集 + 长度）后 FromBase64String 恒成功，无需防御 catch
        return Convert.FromBase64String(std.ToString());
    }

    /// <summary>小写十六进制（D10：统一小写；.NET BitConverter 默认大写带连字符是经典翻车点）。</summary>
    public static string LowerHex(byte[] data)
    {
        var chars = new char[data.Length * 2];
        for (int i = 0; i < data.Length; i++)
        {
            chars[i * 2] = HexLower[data[i] >> 4];
            chars[i * 2 + 1] = HexLower[data[i] & 0x0F];
        }
        return new string(chars);
    }

    /// <summary>去首尾空白并将连续空白折叠为单个空格（canonicalRequest 用）。
    /// 空白类对齐 Java Character.isWhitespace 常见子集：空格、\t、\n、\x0B、\f、\r。</summary>
    public static string TrimAll(string s)
    {
        if (string.IsNullOrEmpty(s))
        {
            return "";
        }
        var sb = new StringBuilder(s.Length);
        var pendingSpace = false;
        var started = false;
        foreach (var c in s)
        {
            if (IsWhitespace(c))
            {
                if (started)
                {
                    pendingSpace = true;
                }
            }
            else
            {
                if (pendingSpace)
                {
                    sb.Append(' ');
                    pendingSpace = false;
                }
                sb.Append(c);
                started = true;
            }
        }
        return sb.ToString();
    }

    private static bool IsWhitespace(char c) =>
        c == ' ' || c == '\t' || c == '\n' || c == '\x0B' || c == '\f' || c == '\r';

    /// <summary>按 java.net.URLEncoder(UTF-8) 语义编码，'+' 替换回 %20
    /// （canonicalRequest 的 RFC 3986 风格钉子，F2）：保留 [A-Za-z0-9.-*_]，
    /// 其余字符按 UTF-8 字节 %XX（大写十六进制），空格 → %20。</summary>
    public static string UrlEncodeJava(string s)
    {
        if (string.IsNullOrEmpty(s))
        {
            return "";
        }
        var bytes = Encoding.UTF8.GetBytes(s);
        var sb = new StringBuilder(bytes.Length);
        foreach (var b in bytes)
        {
            var keep = (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z')
                       || (b >= '0' && b <= '9') || b == '.' || b == '-' || b == '*' || b == '_';
            if (keep)
            {
                sb.Append((char)b);
            }
            else
            {
                sb.Append('%').Append(HexUpper(b >> 4)).Append(HexUpper(b & 0x0F));
            }
        }
        return sb.ToString();
    }

    private static char HexUpper(int v) => (char)(v < 10 ? '0' + v : 'A' + v - 10);
}
