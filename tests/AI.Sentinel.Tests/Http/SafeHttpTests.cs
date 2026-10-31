using AI.Sentinel.Http;
using Xunit;

namespace AI.Sentinel.Tests.Http;

public class SafeHttpTests
{
    [Theory]
    [InlineData("https://hooks.example.com/services/T/B/s3cret", "https://hooks.example.com")]
    [InlineData("https://user:pw@hooks.example.com:8443/a/b?token=s3cret#frag", "https://hooks.example.com:8443")]
    [InlineData("http://127.0.0.1:5000/x", "http://127.0.0.1:5000")]
    [InlineData("https://hooks.example.com:443/x", "https://hooks.example.com")]
    public void DescribeOrigin_KeepsSchemeHostAndPortOnly(string url, string expected)
    {
        var origin = SafeHttp.DescribeOrigin(new Uri(url));

        Assert.Equal(expected, origin);
        Assert.DoesNotContain("s3cret", origin, StringComparison.Ordinal);
        Assert.DoesNotContain("pw", origin, StringComparison.Ordinal);
    }
}
