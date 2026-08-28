using System.Collections.Generic;
using Wop.Sdk;
using Xunit;

public class CanonicalRequestTests
{
    [Fact]
    public void CanonicalHeaders_名称小写排序_值折叠urlencode()
    {
        var headers = new Dictionary<string, string>
        {
            ["X-Wop-Appkey"] = "  demo-app ",
            ["x-wop-nonce"] = "ab c",
            ["X-Wop-Timestamp"] = "1724900000000",
        };
        // 名称/值均 TrimAll + urlencode，按名称 ASCII 升序，行间 \n，尾行不加
        Assert.Equal(
            "x-wop-appkey:demo-app\nx-wop-nonce:ab%20c\nx-wop-timestamp:1724900000000",
            CanonicalRequest.CanonicalHeaders(headers));
    }

    [Fact]
    public void CanonicalHeaders_空集合_空串()
    {
        Assert.Equal("", CanonicalRequest.CanonicalHeaders(new Dictionary<string, string>()));
    }

    [Fact]
    public void CanonicalHeaders_大小写同名_后者覆盖()
    {
        var headers = new Dictionary<string, string>
        {
            ["X-A"] = "1",
            ["x-a"] = "2",   // 同名（lowercase 后冲突）→ 字典语义后者覆盖
        };
        var headers2 = new Dictionary<string, string> { ["x-a"] = "2" };
        Assert.Equal(CanonicalRequest.CanonicalHeaders(headers2), CanonicalRequest.CanonicalHeaders(headers));
    }

    [Fact]
    public void CanonicalRequest_五段拼接_method大写()
    {
        Assert.Equal(
            "v1/1800\nPOST\n/api/v1/pay\n\nx-wop-appkey:demo",
            CanonicalRequest.Build("v1/1800", "post", "/api/v1/pay", "", "x-wop-appkey:demo"));
    }

    [Theory]
    [InlineData("", "v1/1800", "POST", "/p", "x:a")]
    [InlineData(null, "v1/1800", "POST", "/p", "x:a")]
    public void CanonicalRequest_空入参按空串处理(string? qs, string auth, string m, string uri, string ch)
    {
        var c = CanonicalRequest.Build(auth, m, uri, qs ?? "", ch);
        Assert.Equal("v1/1800\nPOST\n/p\n\nx:a", c);
    }
}

public class SignHeaderTests
{
    [Fact]
    public void Build_四段斜线拼接()
    {
        Assert.Equal(
            "WOP-RSA3072-SHA256 v1/1800/x-wop-appkey;x-wop-nonce/pOVoj1mI",
            SignHeader.Build("WOP-RSA3072-SHA256", 1800,
                new[] { "x-wop-appkey", "x-wop-nonce" }, "pOVoj1mI"));
    }

    [Fact]
    public void Parse_合法头()
    {
        var p = SignHeader.Parse("  WOP-SM2-SM3 v1/60/x-wop-a;X-WOP-B/Sg  ");
        Assert.Equal("WOP-SM2-SM3", p.SecurityReq);
        Assert.Equal("v1", p.ProtocolVersion);
        Assert.Equal(60, p.ExpiredSeconds);
        Assert.Equal(new[] { "x-wop-a", "x-wop-b" }, p.SignedHeaders);
        Assert.Equal("Sg", p.Signature);
        Assert.Equal("v1/60", p.AuthString);
    }

    [Theory]
    [InlineData("", "缺少 x-wop-sign 头")]
    [InlineData("   ", "缺少 x-wop-sign 头")]
    [InlineData("WOP-RSA3072-SHA256", "格式错误")]               // 无空格分隔
    [InlineData("WOP-RSA3072-SHA256 v1/1800/abc", "格式错误")]   // 段数不足
    [InlineData("WOP-RSA3072-SHA256 v2/1800/a/b", "协议版本")]
    [InlineData("WOP-RSA3072-SHA256 v1/abc/a/b", "expiredSeconds")]
    [InlineData("WOP-RSA3072-SHA256 v1/0/a/b", "范围")]
    [InlineData("WOP-RSA3072-SHA256 v1/86401/a/b", "范围")]
    [InlineData("WOP-RSA3072-SHA256 v1/1800//b", "signedHeaders")]
    [InlineData("WOP-RSA3072-SHA256 v1/1800/a/  ", "signature")]
    public void Parse_非法头_协议类明确拒绝(string header, string reasonPart)
    {
        var ex = Assert.Throws<WopException>(() => SignHeader.Parse(header));
        Assert.Equal(WopErrorCode.Protocol, ex.ErrorCode);
        Assert.Contains(reasonPart, ex.Message);
    }

    [Fact]
    public void Parse_86400_上限合法()
    {
        var p = SignHeader.Parse("WOP-RSA3072-SHA256 v1/86400/a/b");
        Assert.Equal(86400, p.ExpiredSeconds);
    }
}
