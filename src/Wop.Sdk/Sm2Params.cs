using Org.BouncyCastle.Asn1.GM;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Parameters;

namespace Wop.Sdk;

/// <summary>SM2 推荐曲线 sm2p256v1 域参数（进程级单例，BC 提供）。</summary>
internal static class Sm2Params
{
    internal static readonly X9ECParameters Curve = GMNamedCurves.GetByName("sm2p256v1");
    internal static readonly ECDomainParameters Domain = new(Curve);
}
