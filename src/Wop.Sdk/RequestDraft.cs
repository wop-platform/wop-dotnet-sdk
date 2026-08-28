using System.Collections.Generic;

namespace Wop.Sdk;

/// <summary>报文加密级别：L0 明文、L2 全文数字信封。</summary>
public enum SecurityLevel
{
    /// <summary>明文（依赖签名 + digest 完整性防线）。</summary>
    L0,

    /// <summary>全文数字信封（非对称包 DEK + 对称 bulk 加密）。</summary>
    L2,
}

/// <summary>协议核心产出的待发送请求：商户可直接消费自带 HTTP 栈，
/// 或交给本 SDK 的 IWopTransport 发送。纯计算、零网络 IO。</summary>
public sealed class RequestDraft
{
    /// <summary>HTTP 方法（已统一大写）。</summary>
    public string Method { get; }

    /// <summary>请求路径。</summary>
    public string Path { get; }

    /// <summary>协议头（含 x-wop-sign；L2 含 x-wop-encrypt 与 digest）。</summary>
    public IReadOnlyDictionary<string, string> Headers { get; }

    /// <summary>线上报文字节（L2 = JSON 信封密文；无 body 为 null）。</summary>
    public byte[]? WireBody { get; }

    internal RequestDraft(string method, string path, IReadOnlyDictionary<string, string> headers, byte[]? wireBody)
    {
        Method = method;
        Path = path;
        Headers = headers;
        WireBody = wireBody;
    }
}

/// <summary>F6 校验管线结果：Ok 为真时 Plaintext 携带 L2 解密后明文（L0 即 wire body）；
/// 失败时 ErrorCode/Reason 按错误分类总表对外（验签/解密类模糊，其余明确，I7）。</summary>
public sealed class VerifyResult
{
    /// <summary>是否通过全部校验。</summary>
    public bool Ok { get; }

    /// <summary>失败错误码（成功为 null）。</summary>
    public WopErrorCode? ErrorCode { get; }

    /// <summary>失败对外语义（I7：验签/解密类恒为固定模糊文案）。</summary>
    public string? Reason { get; }

    /// <summary>通过时的报文明文（无 body 为空数组）。</summary>
    public byte[]? Plaintext { get; }

    private VerifyResult(bool ok, WopErrorCode? code, string? reason, byte[]? plaintext)
    {
        Ok = ok;
        ErrorCode = code;
        Reason = reason;
        Plaintext = plaintext;
    }

    internal static VerifyResult Success(byte[]? plaintext) => new(true, null, null, plaintext);

    internal static VerifyResult Fail(WopException e) => new(false, e.ErrorCode, e.Message, null);
}
