using AI.Sentinel.ClaudeCode.Events;
using Xunit;

namespace AI.Sentinel.Tests.ClaudeCode.Events;

/// <summary>A reason leaves the machine only after paths, URLs, email addresses and quoted values are replaced, and not at all when it
/// looks like it holds a secret (ADR-247).</summary>
public sealed class ReasonRedactionTests
{
    [Theory]
    [InlineData("may not read /etc/passwd", "may not read <path>")]
    [InlineData("may not read ~/.ssh/config now", "may not read <path> now")]
    [InlineData("writes to ./build/out and ../x", "writes to <path> and <path>")]
    [InlineData(@"blocked C:\Users\someone\notes.txt here", "blocked <path> here")]
    [InlineData("fetches https://internal.example.com/a?b=c today", "fetches <url> today")]
    [InlineData("mail someone@example.com about it", "mail <email> about it")]
    [InlineData("rule 'no force push' applies to \"main\"", "rule <value> applies to <value>")]
    [InlineData("ran `rm -rf build`", "ran <value>")]
    [InlineData("blocked src/private/roadmap.txt", "blocked <path>")]
    [InlineData("blocked docs/notes.md here", "blocked <path> here")]
    [InlineData("blocked C:/Users/Alice/notes.txt", "blocked <path>")]
    [InlineData(@"Blocked access to src\private\settings.json", "Blocked access to <path>")]
    [InlineData(@"writes to .\build\out and ..\x", "writes to <path> and <path>")]
    public void Paths_urls_emails_and_quoted_values_are_replaced(string reason, string expected) =>
        Assert.Equal(expected, ReasonRedactor.Redact(reason));

    [Theory]
    [InlineData("no force push to main")]
    [InlineData("the organisation forbids deleting branches and/or tags")]
    [InlineData("don't run that: it isn't allowed")]
    [InlineData("deleting a and/or b needs approval")]
    public void A_reason_with_nothing_private_is_unchanged(string reason) =>
        Assert.Equal(reason, ReasonRedactor.Redact(reason));

    // The samples are joined at run time so no secret-shaped literal sits in the source for a secret scanner to report.
    public static TheoryData<string> SecretLookingReasons => new()
    {
        "uses " + "AKIA" + "IOSFODNN7EXAMPLE" + " to sign",
        "the token " + "gh" + "p_" + "abcdefghijklmnopqrstuvwxyz0123456789" + " was in the command",
        "header Authorization: " + "Bear" + "er " + "abcdefghijklmnop1234567890",
        "-----BEGIN RSA " + "PRIVATE KEY" + "----- MIIE",
        "pass" + "word=hunter2 in the file",
        "api_" + "key: 'abc'",
        "jwt " + "eyJ" + "hbGciOiJIUzI1NiJ9." + "eyJ" + "zdWIiOiIxMjM0NTY3ODkwIn0." + "dozjgNryP4J3jVmNHl0w5N",
        "value " + "Zx9Qw3Lk8Vb2" + "Nm7Pa4Sd1Fg6Hj5Kt0Re",
    };

    [Theory]
    [MemberData(nameof(SecretLookingReasons))]
    public void A_reason_that_looks_like_it_holds_a_secret_is_dropped(string reason) =>
        Assert.Null(ReasonRedactor.Redact(reason));

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void An_empty_reason_is_dropped(string? reason) => Assert.Null(ReasonRedactor.Redact(reason));

    [Fact]
    public void A_long_reason_is_cut_to_what_the_server_takes()
    {
        var reason = string.Join(' ', Enumerable.Repeat("rule", 1000));

        Assert.Equal(ReasonRedactor.MaxLength, ReasonRedactor.Redact(reason)!.Length);
    }

    [Fact]
    public void A_secret_in_quotes_is_dropped_whole_and_not_just_hidden()
    {
        Assert.Null(ReasonRedactor.Redact("sent '" + "sk" + "-abcdefghijklmnopqrstuv" + "' to the model"));
    }
}
