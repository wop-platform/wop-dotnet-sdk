using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Text;
using Wop.Sdk;
using Xunit;

/// <summary>覆盖率终局闭合（99.21% → 100% 行）：每条测试对应 coverlet 报告中的
/// 具体未覆盖行/分支，全部为既有语义的显式验证，不引入新行为。</summary>
public class CoverageClose4Tests
{
    // Codec.cs:64 DecodeIndex 的 '_' 分支（c == '-' ? 62 : 63 的 63 侧）
    // spec:D1（base64url 尾随位严格性：末字符下划线 63，%4==3 时低 2 位非零 → 拒）
    [Fact]
    public void DecodeB64Url_尾字符下划线_非规范尾随位拒绝()
    {
        var ex = Assert.Throws<WopException>(() => Codec.DecodeB64Url("AB_"));
        Assert.Equal(WopErrorCode.Protocol, ex.ErrorCode);
    }

    // EncryptedEnvelope.cs:68 ReadString 入口分支（i==len / 非引号开头）
    // spec:D3（value 位置必须是 JSON 字符串）
    [Theory]
    [InlineData("{\"encrypted\":")]    // 冒号后直接结束：SkipWs 后 i==len 进 ReadString
    [InlineData("{\"encrypted\":1")]   // 非引号开头的 value
    public void Envelope_value位置非字符串_拒绝(string body)
    {
        Assert.Throws<WopException>(() => EncryptedEnvelope.Extract(Encoding.UTF8.GetBytes(body)));
    }

    // EncryptedEnvelope.cs:87-89 \u 转义后不足 4 字符且字符串未闭合
    // spec:D3（RFC 8259 完整转义集，非法转义明确拒绝）
    [Fact]
    public void Envelope_u转义截断未闭合_拒绝()
    {
        Assert.Throws<WopException>(() =>
            EncryptedEnvelope.Extract(Encoding.UTF8.GetBytes("{\"a\":\"\\u12")));
    }

    // CanonicalRequest.cs:44 nz(method) ?? "" 的 null 侧
    // spec:F2（canonicalRequest 对 null method 按空串处理）
    [Fact]
    public void Build_method为null_按空串处理()
    {
        Assert.Equal("auth\n\n/p\n\n",
            CanonicalRequest.Build("auth", null!, "/p", "", ""));
    }

    // CanonicalRequest.cs:44 Build 内全部 nz() 的 null 侧（authString/uri/query/headers）
    // spec:F2（null 段按空串拼接，5 段分隔符不可省略）
    [Fact]
    public void Build_全null入参_按空段拼接()
    {
        Assert.Equal("\n\n\n\n", CanonicalRequest.Build(null!, null!, null!, null!, null!));
    }

    // WopClient.cs:144 string.IsNullOrEmpty(path) 的 true 侧
    // （mailto 类 scheme 无 path 组件 → AbsolutePath 为空串）
    // spec:F6（回调 URL 须含非根 path）
    [Fact]
    public void VerifyCallback_回调URL无路径组件_拒绝()
    {
        var client = WopClientTests.RsaBuilder().Build();
        var result = client.VerifyCallback("mailto:notify@example.com",
            new Dictionary<string, string>(), null);
        Assert.False(result.Ok);
        Assert.Equal(WopErrorCode.Protocol, result.ErrorCode);
    }

    // Transport.cs:52 baseUrl ?? "" 的 null 侧
    // spec:Q1（HTTP 适配层：基地址可空，拼接时按空串）
    [Fact]
    public void Transport_baseUrl为null_按空串处理()
    {
        using var hc = new System.Net.Http.HttpClient();
        var t = new HttpClientTransport(hc, null!);
        Assert.NotNull(t);
    }

    // Transport.cs:153-155,168-171 LimitStream 不支持成员显式抛 NotSupportedException
    // spec:D4（限额流只读语义：不支持成员显式失败，而非静默错误行为）
    [Fact]
    public void LimitStream_不支持成员_NotSupportedException()
    {
        var limitType = typeof(HttpClientTransport).GetNestedType("LimitStream",
            BindingFlags.NonPublic | BindingFlags.Instance)!;
        var ctor = limitType.GetConstructors(BindingFlags.NonPublic | BindingFlags.Instance)[0];
        var stream = (Stream)ctor.Invoke(new object[] { new MemoryStream(), 8L });
        using var s = stream;

        Assert.False(s.CanWrite);                                     // 行 153
        Assert.Throws<NotSupportedException>(() => s.Length);        // 行 154
        Assert.Throws<NotSupportedException>(() => s.Position);      // 行 155
        Assert.Throws<NotSupportedException>(() => s.Flush());       // 行 168
        Assert.Throws<NotSupportedException>(() => s.Seek(0, SeekOrigin.Begin));   // 行 169
        Assert.Throws<NotSupportedException>(() => s.SetLength(0));  // 行 170
        Assert.Throws<NotSupportedException>(() => s.Write(new byte[1], 0, 1));    // 行 171
    }

    // WopClient.cs:144 path == "/" 的 true 侧
    // spec:F6（回调 URI 取 path，根路径为非法回调地址）
    [Fact]
    public void VerifyCallback_回调URL仅根路径_拒绝()
    {
        var client = WopClientTests.RsaBuilder().Build();
        var result = client.VerifyCallback("https://gw.example.com/",
            Array.Empty<KeyValuePair<string, string>>(), null);
        Assert.False(result.Ok);
        Assert.Equal(WopErrorCode.Protocol, result.ErrorCode);
    }
}
