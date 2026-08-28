using Wop.Sdk;
using Xunit;

public class WopExceptionTests
{
    [Fact]
    public void 模糊错误_文案固定不携带细节_I7()
    {
        var e1 = WopException.Fuzzy(WopErrorCode.VerifyFailed);
        var e2 = WopException.Fuzzy(WopErrorCode.DecryptFailed);
        Assert.Equal("签名验证失败", e1.Message);
        Assert.Equal("解密失败", e2.Message);
        Assert.Equal(WopErrorCode.VerifyFailed, e1.ErrorCode);
        Assert.Equal(WopErrorCode.DecryptFailed, e2.ErrorCode);
    }

    [Fact]
    public void 明确错误_携带细节()
    {
        var e = new WopException(WopErrorCode.Config, "密钥解析失败：长度 31");
        Assert.Equal(WopErrorCode.Config, e.ErrorCode);
        Assert.Contains("31", e.Message);
        Assert.Contains("CONFIG", e.ToString());
    }
}
