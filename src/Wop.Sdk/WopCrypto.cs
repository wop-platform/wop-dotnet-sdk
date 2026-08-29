using System;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;

namespace Wop.Sdk;

/// <summary>SM2 签名默认用户标识（协议向量钉死）。</summary>
internal static class Sm2Defaults
{
    public static readonly byte[] UserId = System.Text.Encoding.UTF8.GetBytes("1234567812345678");
}

/// <summary>定标量 SecureRandom：向量 conformance 的 fixed-k 唯一入口（测试专用）。
/// 以 I2OSP 语义左补零填充任意读取宽度，使 BC 采样得到的标量恰为给定值。</summary>
internal sealed class FixedScalarRandom : SecureRandom
{
    private readonly byte[] _scalar;

    internal FixedScalarRandom(BigInteger k)
    {
        _scalar = k.ToByteArrayUnsigned();
    }

    private void Fill(byte[] buffer)
    {
        for (var i = 0; i < buffer.Length; i++)
        {
            var off = i - (buffer.Length - _scalar.Length);
            buffer[i] = off >= 0 && off < _scalar.Length ? _scalar[off] : (byte)0;
        }
    }

    public override void NextBytes(byte[] bytes) => Fill(bytes);

#if NET8_0
    public override void NextBytes(Span<byte> buffer)
    {
        for (var i = 0; i < buffer.Length; i++)
        {
            var off = i - (buffer.Length - _scalar.Length);
            buffer[i] = off >= 0 && off < _scalar.Length ? _scalar[off] : (byte)0;
        }
    }
#endif
}

/// <summary>非对称密钥材料（internal）：按套件族二选一填充。</summary>
internal sealed class AsymmetricKeyMaterial
{
    internal RsaPrivateCrtKeyParameters? RsaPrivate { get; init; }
    internal RsaKeyParameters? RsaPublic { get; init; }
    internal ECPrivateKeyParameters? Sm2Private { get; init; }
    internal ECPublicKeyParameters? Sm2Public { get; init; }

    internal static AsymmetricKeyMaterial ParsePrivate(string material, AlgorithmSuite suite) =>
        suite.IsSm2
            ? new AsymmetricKeyMaterial { Sm2Private = KeyCodec.ParseSm2PrivateKey(material) }
            : new AsymmetricKeyMaterial { RsaPrivate = KeyCodec.ParseRsaPrivateKey(material, suite) };

    internal static AsymmetricKeyMaterial ParsePublic(string material, AlgorithmSuite suite) =>
        suite.IsSm2
            ? new AsymmetricKeyMaterial { Sm2Public = KeyCodec.ParseSm2PublicKey(material) }
            : new AsymmetricKeyMaterial { RsaPublic = KeyCodec.ParseRsaPublicKey(material, suite) };
}

/// <summary>密码层（internal）：签名/验签（F3/F7）、报文对称加解密（F5②）、
/// DEK 非对称包装/解包（F5③）。算法按套件族路由，线上编码全部 base64url 无填充。
/// 验签/解密失败对外一律模糊（I7），格式/长度/配置类错误明确。</summary>
internal static class WopCrypto
{
    private const int GcmIvLength = 12;
    private const int GcmTagBits = 128;

    // ==================== ① 签名 / 验签 ====================

    /// <summary>对 canonicalRequest 字节加签，返回 base64url 无填充签名。
    /// RSA = SHA256withRSA（PKCS#1 v1.5）；SM2 = SM3withSM2 裸 r‖s 64B（D9）。
    /// fixedK 仅测试向量消费（须落在 [1, n-1]）；random 为确定性随机源钩子
    /// （SM2 k 从注入流消费，interop 随机流合同），null → 真 CSPRNG。</summary>
    internal static string Sign(AlgorithmSuite suite, AsymmetricKeyMaterial priv, byte[] message, BigInteger? fixedK = null, SecureRandom? random = null)
    {
        byte[] signature;
        if (suite.IsSm2)
        {
            if (priv.Sm2Private == null)
            {
                throw new WopException(WopErrorCode.Config, "SM2 套件缺少私钥");
            }
            var signer = new SM2Signer(PlainDsaEncoding.Instance, new SM3Digest());
            var signRandom = SecureRandomFor(fixedK, random);
            signer.Init(true, new ParametersWithID(
                new ParametersWithRandom(priv.Sm2Private, signRandom), Sm2Defaults.UserId));
            signer.BlockUpdate(message, 0, message.Length);
            // SM2Signer 对合法密钥恒产出（无效 r/s 内部重试），无失败路径
            signature = signer.GenerateSignature();
        }
        else
        {
            if (priv.RsaPrivate == null)
            {
                throw new WopException(WopErrorCode.Config, "RSA 套件缺少私钥");
            }
            var signer = new RsaDigestSigner(new Sha256Digest());
            signer.Init(true, priv.RsaPrivate);
            signer.BlockUpdate(message, 0, message.Length);
            signature = signer.GenerateSignature();
        }
        return Codec.EncodeB64Url(signature);
    }

    /// <summary>验签：b64url 严格解码 → 定长前置校验（F7）→ 族路由验签。
    /// 失败一律模糊（I7）；格式/长度类为协议明确错误。</summary>
    internal static void Verify(AlgorithmSuite suite, AsymmetricKeyMaterial pub, byte[] message, string sigB64Url)
    {
        var signature = Codec.DecodeB64Url(sigB64Url);
        if (signature.Length != suite.SignatureLength)
        {
            throw new WopException(WopErrorCode.Protocol,
                "签名长度 " + signature.Length + " 字节与套件 " + suite.SecurityReq +
                " 定长 " + suite.SignatureLength + " 字节不符");
        }
        bool ok;
        if (suite.IsSm2)
        {
            if (pub.Sm2Public == null)
            {
                throw new WopException(WopErrorCode.Config, "SM2 套件缺少验签公钥");
            }
            var signer = new SM2Signer(PlainDsaEncoding.Instance, new SM3Digest());
            signer.Init(false, new ParametersWithID(pub.Sm2Public, Sm2Defaults.UserId));
            signer.BlockUpdate(message, 0, message.Length);
            ok = signer.VerifySignature(signature);
        }
        else
        {
            if (pub.RsaPublic == null)
            {
                throw new WopException(WopErrorCode.Config, "RSA 套件缺少验签公钥");
            }
            var signer = new RsaDigestSigner(new Sha256Digest());
            signer.Init(false, pub.RsaPublic);
            signer.BlockUpdate(message, 0, message.Length);
            ok = signer.VerifySignature(signature);
        }
        if (!ok)
        {
            throw WopException.Fuzzy(WopErrorCode.VerifyFailed);
        }
    }

    // ==================== ② 报文对称加密 ====================

    /// <summary>加密明文，输出 ciphertext‖tag 尾拼（D10/F4）。key/iv 长度与套件不符为配置类明确错误。</summary>
    internal static byte[] SealMessage(AlgorithmSuite suite, byte[] plaintext, byte[] key, byte[] iv)
    {
        var expectedKey = suite.CekLength;
        if (key.Length != expectedKey)
        {
            throw new WopException(WopErrorCode.Config,
                "对称密钥长度 " + key.Length + " 与套件要求的 " + expectedKey + " 不符");
        }
        if (iv.Length != GcmIvLength)
        {
            throw new WopException(WopErrorCode.Config, "IV 长度须为 " + GcmIvLength + " 字节");
        }
        return ProcessAead(suite, true, plaintext, key, iv);
    }

    /// <summary>解密 ciphertext‖tag；任何失败（tag 不符、密钥不符）对外模糊（I7）。</summary>
    internal static byte[] OpenMessage(AlgorithmSuite suite, byte[] ciphertextWithTag, byte[] key, byte[] iv)
    {
        if (key.Length != suite.CekLength || iv.Length != GcmIvLength)
        {
            throw WopException.Fuzzy(WopErrorCode.DecryptFailed);
        }
        try
        {
            return ProcessAead(suite, false, ciphertextWithTag, key, iv);
        }
        catch (Exception)
        {
            throw WopException.Fuzzy(WopErrorCode.DecryptFailed);
        }
    }

    private static byte[] ProcessAead(AlgorithmSuite suite, bool forEncryption, byte[] input, byte[] key, byte[] iv)
    {
        var cipher = suite.IsSm2
            ? new GcmBlockCipher(new SM4Engine())
            : new GcmBlockCipher(new AesEngine());
        cipher.Init(forEncryption, new AeadParameters(new KeyParameter(key), GcmTagBits, iv));
        var output = new byte[cipher.GetOutputSize(input.Length)];
        var len = cipher.ProcessBytes(input, 0, input.Length, output, 0);
        len += cipher.DoFinal(output, len);
        var result = new byte[len];
        Array.Copy(output, result, len);
        return result;
    }

    // ==================== ③ DEK 非对称包装 ====================

    /// <summary>用公钥包装 DEK 载荷明文，返回 base64url 无填充密文。
    /// RSA = OAEP 显式双 SHA-256 + 空 label（D10/F2 头号跨语言漂移源，显式构造）；
    /// SM2 = C1C3C2 裸拼接（D9）。fixedK 仅测试向量消费。</summary>
    internal static string WrapDek(AlgorithmSuite suite, AsymmetricKeyMaterial pub, byte[] payload, BigInteger? fixedK = null, SecureRandom? random = null)
    {
        byte[] wrapped;
        if (suite.IsSm2)
        {
            if (pub.Sm2Public == null)
            {
                throw new WopException(WopErrorCode.Config, "SM2 套件缺少 DEK 包装公钥");
            }
            var engine = new SM2Engine(SM2Engine.Mode.C1C3C2);
            engine.Init(true, new ParametersWithRandom(pub.Sm2Public, SecureRandomFor(fixedK, random)));
            wrapped = engine.ProcessBlock(payload, 0, payload.Length);
        }
        else
        {
            if (pub.RsaPublic == null)
            {
                throw new WopException(WopErrorCode.Config, "RSA 套件缺少 DEK 包装公钥");
            }
            // OAEP seed 从注入流消费（OAEP-from-stream 确定性，interop 随机流合同：
            // CEK、IV 之后依次取 seed），null → 真 CSPRNG
            var engine = new OaepEncoding(new RsaEngine(),
                new Sha256Digest(), new Sha256Digest(), Array.Empty<byte>());
            engine.Init(true, new ParametersWithRandom(pub.RsaPublic, random ?? new SecureRandom()));
            wrapped = engine.ProcessBlock(payload, 0, payload.Length);
        }
        return Codec.EncodeB64Url(wrapped);
    }

    /// <summary>用私钥解包 DEK 密文（base64url）。
    /// b64url 非法为协议类明确错误；解包失败为解密类模糊错误（I7）。</summary>
    internal static byte[] UnwrapDek(AlgorithmSuite suite, AsymmetricKeyMaterial priv, string dekB64Url)
    {
        var cipher = Codec.DecodeB64Url(dekB64Url.Trim());
        byte[] plain;
        if (suite.IsSm2)
        {
            if (priv.Sm2Private == null)
            {
                throw new WopException(WopErrorCode.Config, "SM2 套件缺少 DEK 解包私钥");
            }
            var engine = new SM2Engine(SM2Engine.Mode.C1C3C2);
            engine.Init(false, priv.Sm2Private);
            try
            {
                plain = engine.ProcessBlock(cipher, 0, cipher.Length);
            }
            catch (Exception)
            {
                throw WopException.Fuzzy(WopErrorCode.DecryptFailed);
            }
        }
        else
        {
            if (priv.RsaPrivate == null)
            {
                throw new WopException(WopErrorCode.Config, "RSA 套件缺少 DEK 解包私钥");
            }
            var engine = new OaepEncoding(new RsaEngine(),
                new Sha256Digest(), new Sha256Digest(), Array.Empty<byte>());
            engine.Init(false, priv.RsaPrivate);
            try
            {
                plain = engine.ProcessBlock(cipher, 0, cipher.Length);
            }
            catch (Exception)
            {
                throw WopException.Fuzzy(WopErrorCode.DecryptFailed);
            }
        }
        return plain;
    }

    /// <summary>随机源选择：fixedK 提供时构造定标量随机（向量专用）；
    /// 否则注入流优先（确定性钩子），最后真 CSPRNG。
    /// I4 纪律：出站 IV/CEK/nonce 的 CSPRNG 生成点唯一（本层），每次调用独立。</summary>
    private static SecureRandom SecureRandomFor(BigInteger? fixedK, SecureRandom? random)
    {
        if (fixedK is { } k)
        {
            if (k.SignValue <= 0 || k.CompareTo(Sm2Params.Domain.N) >= 0)
            {
                throw new WopException(WopErrorCode.Config, "固定 k 须落在 [1, n-1]");
            }
            return new FixedScalarRandom(k);
        }
        return random ?? new SecureRandom();
    }
}
