using System.Text.Json;
using AI.Sentinel.Approvals.Conditions;
using Xunit;

namespace AI.Sentinel.Tests.Approvals.Conditions;

public class ArgumentConditionTests
{
    [Fact]
    public void Evaluate_MatchingValue_Holds()
    {
        var c = new ArgumentCondition("$.method", "^(POST|DELETE)$");
        using var del = JsonDocument.Parse("{\"method\":\"DELETE\"}");
        using var get = JsonDocument.Parse("{\"method\":\"GET\"}");
        using var empty = JsonDocument.Parse("{}");
        Assert.Equal(ConditionResult.Holds, c.Evaluate(del.RootElement));
        Assert.Equal(ConditionResult.DoesNotHold, c.Evaluate(get.RootElement));
        Assert.Equal(ConditionResult.DoesNotHold, c.Evaluate(empty.RootElement));
    }

    [Fact]
    public void Evaluate_IsCaseSensitiveUnlessInline()
    {
        using var doc = JsonDocument.Parse("{\"m\":\"POST\"}");
        Assert.Equal(ConditionResult.DoesNotHold, new ArgumentCondition("$.m", "^post$").Evaluate(doc.RootElement));
        Assert.Equal(ConditionResult.Holds, new ArgumentCondition("$.m", "(?i)^post$").Evaluate(doc.RootElement));
    }

    [Fact]
    public void Ctor_InvalidRegex_Throws()
    {
        var ex = Assert.Throws<ArgumentException>(() => new ArgumentCondition("$.m", "("));
        Assert.Contains("(", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Ctor_InvalidPath_Throws()
    {
        var ex = Assert.Throws<ArgumentException>(() => new ArgumentCondition("m", "x"));
        Assert.Contains("m", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Evaluate_Timeout_ReturnsTimedOut()
    {
        // The backreference makes NonBacktracking reject the pattern, so the 100 ms timeout applies.
        var c = new ArgumentCondition("$.v", "^(a+)+\\1$");
        using var doc = JsonDocument.Parse("{\"v\":\"" + new string('a', 50_000) + "!\"}");
        Assert.Equal(ConditionResult.TimedOut, c.Evaluate(doc.RootElement));
    }
}
