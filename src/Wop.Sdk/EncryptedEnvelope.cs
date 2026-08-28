using System;
using System.Text;

namespace Wop.Sdk;

/// <summary>L2 线上信封 JSON：{"encrypted":"&lt;base64url&gt;"}。
/// b64url 字母表无需 JSON 转义；提取容忍未知字段。</summary>
public static class EncryptedEnvelope
{
    /// <summary>将密文（base64url 无填充）包裹为线上体。</summary>
    public static byte[] Wrap(string cipherB64Url)
    {
        // b64url 字母表（A-Za-z0-9-_）与 JSON 字符串安全集直接兼容
        return Encoding.UTF8.GetBytes("{\"encrypted\":\"" + cipherB64Url + "\"}");
    }

    /// <summary>从线上体提取 encrypted 密文字段（容忍未知字段）。
    /// 非法 JSON / 缺字段 / 非字符串值 / 非法字符 → 协议类明确错误。</summary>
    public static string Extract(byte[] wireBody)
    {
        var s = Encoding.UTF8.GetString(wireBody);
        var i = SkipWs(s, 0);
        if (i >= s.Length || s[i] != '{')
        {
            throw Bad("信封须为 JSON 对象");
        }
        i = SkipWs(s, i + 1);
        while (i < s.Length && s[i] != '}')
        {
            if (s[i] == ',')
            {
                i = SkipWs(s, i + 1);
                continue;
            }
            var (key, afterKey) = ReadString(s, i);
            i = SkipWs(s, afterKey);
            if (i >= s.Length || s[i] != ':')
            {
                throw Bad("信封 JSON 结构非法");
            }
            i = SkipWs(s, i + 1);
            if (key == "encrypted")
            {
                var (value, afterValue) = ReadString(s, i);
                if (value.Length == 0)
                {
                    throw Bad("encrypted 为空");
                }
                ValidateB64Url(value);
                return value;
            }
            i = SkipValue(s, i);
        }
        throw Bad("信封缺少 encrypted 字段");
    }

    private static int SkipWs(string s, int i)
    {
        while (i < s.Length && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r'))
        {
            i++;
        }
        return i;
    }

    private static (string, int) ReadString(string s, int i)
    {
        if (i >= s.Length || s[i] != '"')
        {
            throw Bad("信封 JSON 字符串结构非法");
        }
        i++;
        var sb = new StringBuilder();
        while (i < s.Length && s[i] != '"')
        {
            var c = s[i];
            if (c == '\\')
            {
                i++;
                if (i >= s.Length)
                {
                    throw Bad("信封 JSON 转义非法");
                }
                c = s[i] switch
                {
                    '"' => '"',
                    '\\' => '\\',
                    '/' => '/',
                    'b' => '\b',
                    'f' => '\f',
                    'n' => '\n',
                    'r' => '\r',
                    't' => '\t',
                    _ => throw Bad("信封 JSON 转义非法"),
                };
            }
            else if (c < 0x20)
            {
                throw Bad("信封 JSON 含未转义控制字符");
            }
            sb.Append(c);
            i++;
        }
        if (i >= s.Length)
        {
            throw Bad("信封 JSON 字符串未闭合");
        }
        return (sb.ToString(), i + 1);
    }

    private static int SkipValue(string s, int i)
    {
        if (i < s.Length && s[i] == '"')
        {
            var (_, after) = ReadString(s, i);
            return after;
        }
        var depth = 0;
        while (i < s.Length && s[i] != ',')
        {
            if (s[i] == '{' || s[i] == '[')
            {
                depth++;
            }
            else if (s[i] == '}' || s[i] == ']')
            {
                if (depth == 0)
                {
                    return i;
                }
                depth--;
            }
            i++;
        }
        return i;
    }

    private static void ValidateB64Url(string v)
    {
        foreach (var c in v)
        {
            var ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
                     || (c >= '0' && c <= '9') || c == '-' || c == '_';
            if (!ok)
            {
                throw new WopException(WopErrorCode.Protocol, "encrypted 字段须为 base64url 无填充");
            }
        }
    }

    private static WopException Bad(string message) => new(WopErrorCode.Protocol, message);
}
