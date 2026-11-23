using AI.Sentinel.ClaudeCode.Policy.Rego;
using Xunit;

namespace AI.Sentinel.Tests.ClaudeCode.Policy;

/// <summary>The host runs <c>sprintf</c> as OPA does for the verbs a reason string needs, and no other builtin.</summary>
public class RegoHostBuiltinsTests
{
    [Theory]
    [InlineData("\"hello %s\"", "[\"world\"]", "hello world")]
    [InlineData("\"%s and %s\"", "[\"a\", \"b\"]", "a and b")]
    [InlineData("\"%d files\"", "[3]", "3 files")]
    [InlineData("\"%5d|%-5d|%05d\"", "[42, 42, 42]", "   42|42   |00042")]
    [InlineData("\"%+d %+d\"", "[5, -5]", "+5 -5")]
    [InlineData("\"%.2f|%8.3f|%f\"", "[3.14159, 2.5, 1]", "3.14|   2.500|1.000000")]
    [InlineData("\"%v %v %v\"", "[true, null, 1.5]", "true null 1.5")]
    [InlineData("\"%t\"", "[false]", "false")]
    [InlineData("\"%q\"", "[\"a\\\"b\"]", "\"a\\\"b\"")]
    [InlineData("\"%x %X %o %b\"", "[255, 255, 8, 5]", "ff FF 10 101")]
    [InlineData("\"%x\"", "[\"hi\"]", "6869")]
    [InlineData("\"100%%\"", "[]", "100%")]
    [InlineData("\"%v\"", "[[\"a\", 1, {\"k\": true}]]", "[\"a\", 1, {\"k\": true}]")]
    [InlineData("\"%.3s\"", "[\"abcdef\"]", "abc")]
    [InlineData("\"%s\"", "[\"naïve ü\"]", "naïve ü")]
    public void Sprintf_formats_like_opa(string format, string args, string expected)
    {
        var json = HostBuiltins.Sprintf(format, args);

        Assert.NotNull(json);
        Assert.Equal(expected, System.Text.Json.JsonDocument.Parse(json).RootElement.GetString());
    }

    [Theory]
    [InlineData("\"%d\"", "[]", "%!d(MISSING)")]
    [InlineData("\"x\"", "[1]", "x%!(EXTRA int=1)")]
    [InlineData("\"%d\"", "[\"s\"]", "%!d(string=s)")]
    [InlineData("\"%d\"", "[1.5]", "%!d(float64=1.5)")]
    [InlineData("\"%z\"", "[1]", "%!z(int=1)")]
    [InlineData("\"50%\"", "[]", "50%!(NOVERB)")]
    public void Sprintf_marks_a_mismatch_the_way_go_does(string format, string args, string expected)
    {
        var json = HostBuiltins.Sprintf(format, args);

        Assert.Equal(expected, System.Text.Json.JsonDocument.Parse(json!).RootElement.GetString());
    }

    [Theory]
    [InlineData("1", "[]")]
    [InlineData("\"%s\"", "\"not an array\"")]
    public void Sprintf_of_arguments_with_the_wrong_type_is_undefined(string format, string args) =>
        Assert.Null(HostBuiltins.Sprintf(format, args));

    [Fact]
    public void Only_sprintf_is_implemented()
    {
        Assert.True(HostBuiltins.IsImplemented("sprintf"));
        Assert.False(HostBuiltins.IsImplemented("uuid.rfc4122"));
        Assert.False(HostBuiltins.IsImplemented("http.send"));
    }
}
