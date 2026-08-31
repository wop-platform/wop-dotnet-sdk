using System;
using System.Text;
using Org.BouncyCastle.Asn1.GM;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;

namespace Wop.Sdk;

/// <summary>密钥解析（D12 分发契约）：密钥入参为字符串（PEM 或 Base64 单行），
/// SDK 内部解析。RSA 公钥 = X.509 SPKI DER、私钥 = PKCS#8；
/// SM2 公钥 = 未压缩点 04‖X‖Y（65B，on-curve 前置守卫）、私钥 = d 32B 大端标量。
/// 解析失败 → 配置类明确错误（帮助商户自查）。</summary>
internal static class KeyCodec
{
    internal static X9ECParameters Sm2Curve => Sm2Params.Curve;
    internal static ECDomainParameters Sm2Domain => Sm2Params.Domain;

    /// <summary>归一密钥材料：PEM 块取其 DER 体；否则按标准 Base64 解码（容忍换行折行）。</summary>
    internal static byte[] DecodeKeyMaterial(string material)
    {
        var trimmed = (material ?? "").Trim();
        if (trimmed.Length == 0)
        {
            throw new WopException(WopErrorCode.Config, "密钥材料为空");
        }
        if (trimmed.StartsWith("-----BEGIN", StringComparison.Ordinal))
        {
            var body = ExtractPemBody(trimmed);
            return Convert.FromBase64String(body);
        }
        var clean = new StringBuilder(trimmed.Length);
        foreach (var c in trimmed)
        {
            if (!char.IsWhiteSpace(c))
            {
                clean.Append(c);
            }
        }
        try
        {
            return Convert.FromBase64String(clean.ToString());
        }
        catch (FormatException)
        {
            throw new WopException(WopErrorCode.Config, "密钥 Base64 解码失败");
        }
    }

    /// <summary>提取 PEM 块 Base64 体（剥离 BEGIN/END 行与空白行）。</summary>
    private static string ExtractPemBody(string pem)
    {
        var lines = pem.Split('\n');
        var sb = new StringBuilder();
        foreach (var line in lines)
        {
            var t = line.Trim();
            if (t.Length == 0 || t.StartsWith("-----", StringComparison.Ordinal))
            {
                continue;
            }
            sb.Append(t);
        }
        return sb.ToString();
    }

    /// <summary>解析 RSA 公钥（SPKI DER，Base64/PEM 皆可），并校验模长匹配套件。</summary>
    internal static RsaKeyParameters ParseRsaPublicKey(string material, AlgorithmSuite suite)
    {
        var der = DecodeKeyMaterial(material);
        try
        {
            var key = (RsaKeyParameters)PublicKeyFactory.CreateKey(der);
            ValidateRsaSize(suite, key.Modulus.BitLength);
            return key;
        }
        catch (WopException)
        {
            throw;
        }
        catch (Exception)
        {
            throw new WopException(WopErrorCode.Config, "RSA 公钥解析失败（期望 SPKI DER Base64/PEM）");
        }
    }

    /// <summary>解析 RSA 私钥（PKCS#8 DER，Base64/PEM 皆可），并校验模长匹配套件。</summary>
    internal static RsaPrivateCrtKeyParameters ParseRsaPrivateKey(string material, AlgorithmSuite suite)
    {
        var der = DecodeKeyMaterial(material);
        try
        {
            var key = (RsaPrivateCrtKeyParameters)PrivateKeyFactory.CreateKey(der);
            ValidateRsaSize(suite, key.Modulus.BitLength);
            return key;
        }
        catch (WopException)
        {
            throw;
        }
        catch (Exception)
        {
            throw new WopException(WopErrorCode.Config, "RSA 私钥解析失败（期望 PKCS#8 DER Base64/PEM）");
        }
    }

    /// <summary>校验 RSA 模长与套件要求一致（不符 → 配置类明确错误）。</summary>
    private static void ValidateRsaSize(AlgorithmSuite suite, int bits)
    {
        if (bits != suite.KeyBits)
        {
            throw new WopException(WopErrorCode.Config,
                "RSA 密钥位数 " + bits + " 与套件 " + suite.SecurityReq + " 要求的 " + suite.KeyBits + " 位不符");
        }
    }

    /// <summary>解析 SM2 公钥：65B 未压缩点（04‖X‖Y）。
    /// on-curve 校验由 BC DecodePoint 提供（I5 曲线守卫）。</summary>
    internal static ECPublicKeyParameters ParseSm2PublicKey(string material)
    {
        var der = DecodeKeyMaterial(material);
        if (der.Length != 65 || der[0] != 0x04)
        {
            throw new WopException(WopErrorCode.Config,
                "SM2 公钥须为未压缩点 04‖X‖Y 共 65 字节（Base64），实际 " + der.Length + " 字节");
        }
        try
        {
            var q = Sm2Curve.Curve.DecodePoint(der);
            return new ECPublicKeyParameters(q, Sm2Domain);
        }
        catch (Exception)
        {
            throw new WopException(WopErrorCode.Config, "SM2 公钥点非法（不在 sm2p256v1 曲线上）");
        }
    }

    /// <summary>解析 SM2 私钥：32B 大端标量 d，范围 [1, n-1]。</summary>
    internal static ECPrivateKeyParameters ParseSm2PrivateKey(string material)
    {
        var der = DecodeKeyMaterial(material);
        if (der.Length != 32)
        {
            throw new WopException(WopErrorCode.Config,
                "SM2 私钥须为 32 字节大端标量 d（Base64），实际 " + der.Length + " 字节");
        }
        var d = new BigInteger(1, der);
        if (d.SignValue == 0 || d.CompareTo(Sm2Domain.N) >= 0)
        {
            throw new WopException(WopErrorCode.Config, "SM2 私钥标量 d 超出 [1, n-1] 范围");
        }
        return new ECPrivateKeyParameters(d, Sm2Domain);
    }
}
