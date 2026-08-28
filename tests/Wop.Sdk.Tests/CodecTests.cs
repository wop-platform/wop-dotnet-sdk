using System;
using Wop.Sdk;
using Xunit;

public class CodecTests
{
    [Theory]
    [InlineData(new byte[] { 0, 1, 2, 3 }, "AAECAw")]
    [InlineData(new byte[] { 0xfb, 0xff, 0xfe }, "-__-")]
    [InlineData(new byte[] { 0x00 }, "AA")]
    [InlineData(new byte[] { }, "")]
    public void EncodeB64Url_无填充URL字母表(byte[] input, string expected)
    {
        Assert.Equal(expected, Codec.EncodeB64Url(input));
    }

    [Fact]
    public void EncodeB64Url_与向量签名长度一致()
    {
        // 384B → 512 字符；512B → 683 字符（spec §3.3①）
        Assert.Equal(512, Codec.EncodeB64Url(new byte[384]).Length);
        Assert.Equal(683, Codec.EncodeB64Url(new byte[512]).Length);
        Assert.Equal(86, Codec.EncodeB64Url(new byte[64]).Length);
    }

    [Theory]
    [InlineData("AAECAw", new byte[] { 0, 1, 2, 3 })]
    [InlineData("-___", new byte[] { 0xfb, 0xff, 0xff })]
    [InlineData("AA", new byte[] { 0x00 })]
    [InlineData("", new byte[] { })]
    public void DecodeB64Url_正常解码(string input, byte[] expected)
    {
        Assert.Equal(expected, Codec.DecodeB64Url(input));
    }

    [Theory]                       // F6 严格无填充：带 '=' 与标准字母表字符一律拒收
    [InlineData("abc=")]           // 填充字符
    [InlineData("ab+c")]           // 标准字母表 '+'
    [InlineData("ab/c")]           // 标准字母表 '/'
    [InlineData("ab c")]           // 空白
    [InlineData("ab\tc")]
    [InlineData("ab\nc")]
    [InlineData("ab\r c")]
    [InlineData("a")]              // len % 4 == 1
    [InlineData("abcde")]
    public void DecodeB64Url_负向量必须拒绝(string input)
    {
        var ex = Assert.Throws<WopException>(() => Codec.DecodeB64Url(input));
        Assert.Equal(WopErrorCode.Protocol, ex.ErrorCode);
    }

    [Fact]
    public void DecodeB64Url_Roundtrip()
    {
        var rnd = new Random(42);
        for (int n = 0; n < 70; n++)
        {
            var b = new byte[n];
            rnd.NextBytes(b);
            Assert.Equal(b, Codec.DecodeB64Url(Codec.EncodeB64Url(b)));
        }
    }

    [Fact]
    public void LowerHex_小写无连字符()
    {
        Assert.Equal("00ffa1", Codec.LowerHex(new byte[] { 0x00, 0xff, 0xa1 }));
        Assert.Equal("", Codec.LowerHex(Array.Empty<byte>()));
    }

    [Theory]
    [InlineData("  a  b\tc ", "a b c")]          // 折叠连续空白
    [InlineData("\n\r\t x\r\n", "x")]
    [InlineData("a\vb\fc", "a b c")]           // VT/FF 属空白类
    [InlineData("", "")]
    [InlineData("   ", "")]
    [InlineData("a b", "a b")]                    // NBSP（U+00A0）非空白类，不折叠
    public void TrimAll_空白折叠(string input, string expected)
    {
        Assert.Equal(expected, Codec.TrimAll(input));
    }

    [Theory]
    [InlineData("AbC-._*09", "AbC-._*09")]        // 保留集原样
    [InlineData("a b", "a%20b")]                   // 空格 → %20（非 '+'）
    [InlineData("a+b", "a%2Bb")]
    [InlineData("a/b", "a%2Fb")]
    [InlineData("a=b", "a%3Db")]
    [InlineData("a;b", "a%3Bb")]
    [InlineData("a~b", "a%7Eb")] // ~ 非保留集 → %7E
    [InlineData("中文", "%E4%B8%AD%E6%96%87")]      // UTF-8 字节 %XX
    [InlineData("", "")]
    public void UrlEncodeJava_JavaUrlEncoder语义(string input, string expected)
    {
        Assert.Equal(expected, Codec.UrlEncodeJava(input));
    }

    [Fact]
    public void UrlEncodeJava_大写百分号十六进制()
    {
        Assert.Equal("%2F", Codec.UrlEncodeJava("/"));
    }
}
