using System;

namespace Wop.Sdk;

/// <summary>稳定公共错误码契约（商户可编程处理）。
/// 分类依据 crypto-strategy-spec §10.2：鉴权前可判定的公开协议知识 → 明确；
/// 依赖密钥参与的判定 → 模糊（防 padding-oracle 式信息泄露）。</summary>
public enum WopErrorCode
{
    /// <summary>配置类（明确）：密钥缺失、解析失败、密钥与套件不符。</summary>
    Config,

    /// <summary>解析类（明确）：securityReq 空值/格式/前缀错误。</summary>
    SuiteParse,

    /// <summary>支持类（明确）：算法不在支持列表、跨族组合、长度非法。</summary>
    SuiteUnsupported,

    /// <summary>协议格式类（明确）：x-wop-sign / digest 头 / L2 信封结构非法。</summary>
    Protocol,

    /// <summary>完整性类（明确）：摘要与线上报文字节不符（D2）。</summary>
    DigestMismatch,

    /// <summary>验签类（模糊）：签名验证失败，对外不区分原因（I7）。</summary>
    VerifyFailed,

    /// <summary>解密类（模糊）：DEK 解包或 GCM 解密失败，对外不区分原因（I7）。</summary>
    DecryptFailed,

    /// <summary>一致性类（明确）：dek alg 与套件族不符（公开映射知识，I3 允许提前拒）。</summary>
    AlgMismatch,
}

/// <summary>SDK 统一错误模型：ErrorCode 可编程处理，Message 为对外语义。
/// 验签/解密类错误的 Message 恒为固定模糊文案（I7 纪律）。</summary>
public sealed class WopException : Exception
{
    /// <summary>错误码（稳定公共契约）。</summary>
    public WopErrorCode ErrorCode { get; }

    public WopException(WopErrorCode errorCode, string message)
        : base(message)
    {
        ErrorCode = errorCode;
    }

    /// <summary>构造模糊类错误（I7：文案钉死，细节不外泄）。</summary>
    public static WopException Fuzzy(WopErrorCode code) => new(
        code,
        code == WopErrorCode.DecryptFailed ? "解密失败" : "签名验证失败");

    /// <summary>统一诊断串 "wop: [CODE] message"（错误码大写，便于日志检索）。</summary>
    public override string ToString() => "wop: [" + ErrorCode.ToString().ToUpperInvariant() + "] " + Message;
}
