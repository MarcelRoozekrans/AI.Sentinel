using System.Text.Json;
using System.Text.Json.Nodes;
using AI.Sentinel.Redaction;
using Xunit;

namespace AI.Sentinel.Tests.Redaction;

public class JsonScanTextTests
{
    // The redaction renders one member exactly as the scan renders it inside a document.
    [Theory]
    [InlineData("password", "hunter2")]
    [InlineData("pass\"word", "a\"b\\c")]
    [InlineData("note", "line1\nline2 <é> & 'x'")]
    [InlineData("", "")]
    public void RenderMember_IsTheMemberOfTheScanText(string name, string value)
    {
        var json = new JsonObject { [name] = value }.ToJsonString();
        using var doc = JsonDocument.Parse(json);
        var scan = HostContent.FromJson(doc.RootElement).ScanText();

        Assert.Equal(scan[1..^1], JsonScanText.RenderMember(name, value).Text);
    }
}
