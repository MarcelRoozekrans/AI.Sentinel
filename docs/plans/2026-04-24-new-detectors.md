# New Detectors Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Implement 9 new detectors (OPS-09/10/11, SEC-18/19/21/22/30, HAL-09) following the hybrid rule-based + LLM-escalation approach approved in the design doc.

**Architecture:** Each detector is a standalone class decorated with `[Singleton(As = typeof(IDetector), AllowMultiple = true)]` — ZeroAllocInject source-gen wires DI automatically. Behavioural detectors implement `ILlmEscalatingDetector` for second-pass LLM analysis; structural/threshold detectors are plain `IDetector`. One stub (`SEC-18`) extends `StubDetector` because it needs infrastructure not yet in `SentinelContext`.

**Tech Stack:** C# 13 / .NET 8+10, Microsoft.Extensions.AI (`ChatRole`, `ChatMessage`), `System.Text.RegularExpressions` source-gen (`[GeneratedRegex]`), xUnit, ZeroAllocInject `[Singleton]`.

---

### Task 1: OPS-09 `TruncatedOutputDetector`

**Files:**
- Create: `src/AI.Sentinel/Detectors/Operational/TruncatedOutputDetector.cs`
- Modify: `tests/AI.Sentinel.Tests/Detectors/Operational/OperationalDetectorTests.cs`

**Step 1: Write the failing tests**

Add to `OperationalDetectorTests.cs` (inside the existing class):

```csharp
[Fact] public async Task TruncatedOutput_MidSentence_Medium()
{
    var r = await new TruncatedOutputDetector().AnalyzeAsync(
        Ctx("The model was running fine then it suddenly"), default);
    Assert.True(r.Severity >= Severity.Medium);
}

[Fact] public async Task TruncatedOutput_OpenCodeFence_Low()
{
    var r = await new TruncatedOutputDetector().AnalyzeAsync(
        Ctx("Here is the code:\n```csharp\nvar x = 1;"), default);
    Assert.Equal(Severity.Low, r.Severity);
}

[Fact] public async Task TruncatedOutput_CompleteResponse_Clean()
{
    var r = await new TruncatedOutputDetector().AnalyzeAsync(
        Ctx("The answer is 42."), default);
    Assert.True(r.IsClean);
}
```

**Step 2: Run tests to verify they fail**

```
dotnet test tests/AI.Sentinel.Tests --filter "TruncatedOutput" -v minimal
```
Expected: compilation error — `TruncatedOutputDetector` does not exist yet.

**Step 3: Implement**

```csharp
using AI.Sentinel.Detection;
using ZeroAllocInject;

namespace AI.Sentinel.Detectors.Operational;

[Singleton(As = typeof(IDetector), AllowMultiple = true)]
public sealed class TruncatedOutputDetector : IDetector
{
    private static readonly DetectorId _id    = new("OPS-09");
    private static readonly DetectionResult _clean = DetectionResult.Clean(_id);

    public DetectorId Id => _id;
    public DetectorCategory Category => DetectorCategory.Operational;

    public ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, CancellationToken ct)
    {
        var text = ctx.TextContent.TrimEnd();
        if (text.Length == 0) return ValueTask.FromResult(_clean);

        var fenceCount = CountOccurrences(text, "```");
        if (fenceCount % 2 != 0)
            return ValueTask.FromResult(DetectionResult.WithSeverity(_id, Severity.Low,
                "Unclosed code fence — response may be truncated"));

        if (text.EndsWith("...", StringComparison.Ordinal))
            return ValueTask.FromResult(DetectionResult.WithSeverity(_id, Severity.Low,
                "Response ends with ellipsis — possible truncation"));

        var last = text[^1];
        if (char.IsLower(last) || last == ',')
            return ValueTask.FromResult(DetectionResult.WithSeverity(_id, Severity.Medium,
                "Response ends mid-sentence — likely truncated"));

        return ValueTask.FromResult(_clean);
    }

    private static int CountOccurrences(string text, string value)
    {
        int count = 0, index = 0;
        while ((index = text.IndexOf(value, index, StringComparison.Ordinal)) >= 0)
        {
            count++;
            index += value.Length;
        }
        return count;
    }
}
```

**Step 4: Run tests**

```
dotnet test tests/AI.Sentinel.Tests --filter "TruncatedOutput" -v minimal
```
Expected: 3 tests PASS.

**Step 5: Commit**

```
git add src/AI.Sentinel/Detectors/Operational/TruncatedOutputDetector.cs tests/AI.Sentinel.Tests/Detectors/Operational/OperationalDetectorTests.cs
git commit -m "feat(detectors): OPS-09 TruncatedOutputDetector"
```

---

### Task 2: OPS-10 `WaitingForContextDetector`

**Files:**
- Create: `src/AI.Sentinel/Detectors/Operational/WaitingForContextDetector.cs`
- Modify: `tests/AI.Sentinel.Tests/Detectors/Operational/OperationalDetectorTests.cs`

**Step 1: Write the failing tests**

```csharp
[Fact] public async Task WaitingForContext_ShortUserMsg_Clean()
{
    var messages = new List<ChatMessage>
    {
        new(ChatRole.User,      "Help"),
        new(ChatRole.Assistant, "Could you clarify what you need help with?"),
    };
    var r = await new WaitingForContextDetector().AnalyzeAsync(CtxMessages(messages), default);
    Assert.True(r.IsClean);
}

[Fact] public async Task WaitingForContext_LongUserSelfContained_Low()
{
    var messages = new List<ChatMessage>
    {
        new(ChatRole.User,      "Please write me a complete C# class that implements a binary search tree with insert, delete, and find methods including unit tests."),
        new(ChatRole.Assistant, "Could you please provide more details about what you need?"),
    };
    var r = await new WaitingForContextDetector().AnalyzeAsync(CtxMessages(messages), default);
    Assert.True(r.Severity >= Severity.Low);
}

[Fact] public async Task WaitingForContext_MultipleStalls_Medium()
{
    var messages = new List<ChatMessage>
    {
        new(ChatRole.User,      "Please write me a complete C# class that implements a binary search tree with insert, delete, and find methods including unit tests."),
        new(ChatRole.Assistant, "Could you clarify what you need? Please provide more information. Could you specify the requirements?"),
    };
    var r = await new WaitingForContextDetector().AnalyzeAsync(CtxMessages(messages), default);
    Assert.True(r.Severity >= Severity.Medium);
}
```

**Step 2: Run to verify failure**

```
dotnet test tests/AI.Sentinel.Tests --filter "WaitingForContext" -v minimal
```

**Step 3: Implement**

```csharp
using System.Text.RegularExpressions;
using Microsoft.Extensions.AI;
using AI.Sentinel.Detection;
using ZeroAllocInject;

namespace AI.Sentinel.Detectors.Operational;

[Singleton(As = typeof(IDetector), AllowMultiple = true)]
public sealed partial class WaitingForContextDetector : IDetector
{
    private static readonly DetectorId _id    = new("OPS-10");
    private static readonly DetectionResult _clean = DetectionResult.Clean(_id);
    private const int MinUserMessageLength = 50;

    public DetectorId Id => _id;
    public DetectorCategory Category => DetectorCategory.Operational;

    [GeneratedRegex(
        @"(please\s+provide|could\s+you\s+clarify|could\s+you\s+share|" +
        @"i\s+need\s+more\s+information|could\s+you\s+specify|" +
        @"can\s+you\s+tell\s+me\s+more)",
        RegexOptions.IgnoreCase | RegexOptions.ExplicitCapture | RegexOptions.Compiled,
        matchTimeoutMilliseconds: 1000)]
    private static partial Regex StallPattern();

    public ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, CancellationToken ct)
    {
        var userText = string.Join(" ", ctx.Messages
            .Where(m => m.Role == ChatRole.User)
            .Select(m => m.Text ?? ""));
        if (userText.Length < MinUserMessageLength)
            return ValueTask.FromResult(_clean);

        var assistantText = string.Join(" ", ctx.Messages
            .Where(m => m.Role == ChatRole.Assistant)
            .Select(m => m.Text ?? ""));

        var matches = StallPattern().Matches(assistantText);
        return matches.Count switch
        {
            0 => ValueTask.FromResult(_clean),
            1 => ValueTask.FromResult(DetectionResult.WithSeverity(_id, Severity.Low,
                $"Model stalling: '{matches[0].Value}'")),
            _ => ValueTask.FromResult(DetectionResult.WithSeverity(_id, Severity.Medium,
                $"Multiple stall phrases ({matches.Count}) — model waiting for context it should have")),
        };
    }
}
```

**Step 4: Run tests**

```
dotnet test tests/AI.Sentinel.Tests --filter "WaitingForContext" -v minimal
```
Expected: 3 tests PASS.

**Step 5: Commit**

```
git add src/AI.Sentinel/Detectors/Operational/WaitingForContextDetector.cs tests/AI.Sentinel.Tests/Detectors/Operational/OperationalDetectorTests.cs
git commit -m "feat(detectors): OPS-10 WaitingForContextDetector"
```

---

### Task 3: OPS-11 `UnboundedConsumptionDetector`

**Files:**
- Create: `src/AI.Sentinel/Detectors/Operational/UnboundedConsumptionDetector.cs`
- Modify: `tests/AI.Sentinel.Tests/Detectors/Operational/OperationalDetectorTests.cs`

**Step 1: Write the failing tests**

```csharp
[Fact] public async Task UnboundedConsumption_SmallResponse_Clean()
{
    var messages = new List<ChatMessage>
    {
        new(ChatRole.User,      "What is 2+2?"),
        new(ChatRole.Assistant, "The answer is 4."),
    };
    var r = await new UnboundedConsumptionDetector().AnalyzeAsync(CtxMessages(messages), default);
    Assert.True(r.IsClean);
}

[Fact] public async Task UnboundedConsumption_LargeAbsolute_Low()
{
    var messages = new List<ChatMessage>
    {
        new(ChatRole.User,      "Write me something."),
        new(ChatRole.Assistant, new string('a', 6_000)),
    };
    var r = await new UnboundedConsumptionDetector().AnalyzeAsync(CtxMessages(messages), default);
    Assert.True(r.Severity >= Severity.Low);
}

[Fact] public async Task UnboundedConsumption_HighRatio_Medium()
{
    var messages = new List<ChatMessage>
    {
        new(ChatRole.User,      "Hi"),
        new(ChatRole.Assistant, new string('a', 16_000)),
    };
    var r = await new UnboundedConsumptionDetector().AnalyzeAsync(CtxMessages(messages), default);
    Assert.True(r.Severity >= Severity.Medium);
}
```

**Step 2: Run to verify failure**

```
dotnet test tests/AI.Sentinel.Tests --filter "UnboundedConsumption" -v minimal
```

**Step 3: Implement**

```csharp
using Microsoft.Extensions.AI;
using AI.Sentinel.Detection;
using ZeroAllocInject;

namespace AI.Sentinel.Detectors.Operational;

[Singleton(As = typeof(IDetector), AllowMultiple = true)]
public sealed class UnboundedConsumptionDetector : IDetector
{
    private static readonly DetectorId _id    = new("OPS-11");
    private static readonly DetectionResult _clean = DetectionResult.Clean(_id);

    public DetectorId Id => _id;
    public DetectorCategory Category => DetectorCategory.Operational;

    public ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, CancellationToken ct)
    {
        var responseLen = ctx.Messages
            .Where(m => m.Role == ChatRole.Assistant)
            .Sum(m => (m.Text ?? "").Length);
        var promptLen = ctx.Messages
            .Where(m => m.Role == ChatRole.User)
            .Sum(m => (m.Text ?? "").Length);

        if (responseLen == 0) return ValueTask.FromResult(_clean);

        var ratio = promptLen > 0 ? (double)responseLen / promptLen : double.MaxValue;

        if (responseLen > 50_000 || ratio > 100)
            return ValueTask.FromResult(DetectionResult.WithSeverity(_id, Severity.High,
                $"Response {responseLen:N0} chars ({ratio:F0}× prompt) — possible resource exhaustion"));
        if (responseLen > 15_000 || ratio > 40)
            return ValueTask.FromResult(DetectionResult.WithSeverity(_id, Severity.Medium,
                $"Response {responseLen:N0} chars ({ratio:F0}× prompt) — abnormally large"));
        if (responseLen > 5_000 || ratio > 15)
            return ValueTask.FromResult(DetectionResult.WithSeverity(_id, Severity.Low,
                $"Response {responseLen:N0} chars ({ratio:F0}× prompt) — unusually large"));

        return ValueTask.FromResult(_clean);
    }
}
```

**Step 4: Run tests**

```
dotnet test tests/AI.Sentinel.Tests --filter "UnboundedConsumption" -v minimal
```
Expected: 3 tests PASS.

**Step 5: Commit**

```
git add src/AI.Sentinel/Detectors/Operational/UnboundedConsumptionDetector.cs tests/AI.Sentinel.Tests/Detectors/Operational/OperationalDetectorTests.cs
git commit -m "feat(detectors): OPS-11 UnboundedConsumptionDetector"
```

---

### Task 4: SEC-18 `ToolDescriptionDivergenceDetector` (stub)

**Files:**
- Create: `src/AI.Sentinel/Detectors/Security/ToolDescriptionDivergenceDetector.cs`
- Modify: `tests/AI.Sentinel.Tests/Detectors/Security/ExtendedSecurityDetectorTests.cs`

**Step 1: Write the failing test**

```csharp
[Fact] public async Task ToolDescriptionDivergence_ReturnsClean()
{
    var r = await new ToolDescriptionDivergenceDetector().AnalyzeAsync(
        SecurityCtx("Normal response with no tool description changes"), default);
    Assert.Equal(Severity.None, r.Severity);
}
```

Note: check `ExtendedSecurityDetectorTests.cs` for the local helper method name (likely `SecurityCtx` or `Ctx`) and use the matching pattern.

**Step 2: Run to verify failure**

```
dotnet test tests/AI.Sentinel.Tests --filter "ToolDescriptionDivergence" -v minimal
```

**Step 3: Implement**

```csharp
using AI.Sentinel.Detection;
using ZeroAllocInject;

namespace AI.Sentinel.Detectors.Security;

// Needs tool descriptor snapshot added to SentinelContext (v1.1 follow-up)
// before a rule-based first pass is possible. StubDetector wires
// ILlmEscalatingDetector for the rare case where a divergent description
// leaks into message text.
[Singleton(As = typeof(IDetector), AllowMultiple = true)]
public sealed class ToolDescriptionDivergenceDetector()
    : StubDetector("SEC-18", DetectorCategory.Security) { }
```

**Step 4: Run tests**

```
dotnet test tests/AI.Sentinel.Tests --filter "ToolDescriptionDivergence" -v minimal
```
Expected: 1 test PASS.

**Step 5: Commit**

```
git add src/AI.Sentinel/Detectors/Security/ToolDescriptionDivergenceDetector.cs tests/AI.Sentinel.Tests/Detectors/Security/ExtendedSecurityDetectorTests.cs
git commit -m "feat(detectors): SEC-18 ToolDescriptionDivergenceDetector (stub)"
```

---

### Task 5: SEC-19 `ToolCallFrequencyDetector`

**Files:**
- Create: `src/AI.Sentinel/Detectors/Security/ToolCallFrequencyDetector.cs`
- Modify: `tests/AI.Sentinel.Tests/Detectors/Security/ExtendedSecurityDetectorTests.cs`

**Step 1: Write the failing tests**

```csharp
[Fact] public async Task ToolCallFrequency_FewCalls_Clean()
{
    var messages = Enumerable.Range(0, 3)
        .Select(_ => new ChatMessage(ChatRole.Tool, "result"))
        .ToList();
    var r = await new ToolCallFrequencyDetector().AnalyzeAsync(
        CtxMessages(messages), default);
    Assert.True(r.IsClean);
}

[Fact] public async Task ToolCallFrequency_ExcessiveCalls_Medium()
{
    var messages = Enumerable.Range(0, 12)
        .Select(_ => new ChatMessage(ChatRole.Tool, "result"))
        .ToList();
    var r = await new ToolCallFrequencyDetector().AnalyzeAsync(
        CtxMessages(messages), default);
    Assert.True(r.Severity >= Severity.Medium);
}
```

Note: use the `CtxMessages` helper already present in the test class (check the file if it only has a `Ctx(string)` helper — if so, add `CtxMessages` following the same pattern as `OperationalDetectorTests`).

**Step 2: Run to verify failure**

```
dotnet test tests/AI.Sentinel.Tests --filter "ToolCallFrequency" -v minimal
```

**Step 3: Implement**

```csharp
using Microsoft.Extensions.AI;
using AI.Sentinel.Detection;
using ZeroAllocInject;

namespace AI.Sentinel.Detectors.Security;

[Singleton(As = typeof(IDetector), AllowMultiple = true)]
public sealed class ToolCallFrequencyDetector : ILlmEscalatingDetector
{
    private static readonly DetectorId _id    = new("SEC-19");
    private static readonly DetectionResult _clean = DetectionResult.Clean(_id);

    public DetectorId Id => _id;
    public DetectorCategory Category => DetectorCategory.Security;

    public ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, CancellationToken ct)
    {
        var count = ctx.Messages.Count(m => m.Role == ChatRole.Tool);
        return count switch
        {
            > 20 => ValueTask.FromResult(DetectionResult.WithSeverity(_id, Severity.High,
                $"{count} tool calls in one batch — possible automated exfiltration")),
            > 10 => ValueTask.FromResult(DetectionResult.WithSeverity(_id, Severity.Medium,
                $"{count} tool calls in one batch — anomalous spike")),
            > 5  => ValueTask.FromResult(DetectionResult.WithSeverity(_id, Severity.Low,
                $"{count} tool calls in one batch — elevated frequency")),
            _    => ValueTask.FromResult(_clean),
        };
    }
}
```

**Step 4: Run tests**

```
dotnet test tests/AI.Sentinel.Tests --filter "ToolCallFrequency" -v minimal
```
Expected: 2 tests PASS.

**Step 5: Commit**

```
git add src/AI.Sentinel/Detectors/Security/ToolCallFrequencyDetector.cs tests/AI.Sentinel.Tests/Detectors/Security/ExtendedSecurityDetectorTests.cs
git commit -m "feat(detectors): SEC-19 ToolCallFrequencyDetector"
```

---

### Task 6: SEC-21 `ExcessiveAgencyDetector`

**Files:**
- Create: `src/AI.Sentinel/Detectors/Security/ExcessiveAgencyDetector.cs`
- Modify: `tests/AI.Sentinel.Tests/Detectors/Security/ExtendedSecurityDetectorTests.cs`

**Step 1: Write the failing tests**

```csharp
[Fact] public async Task ExcessiveAgency_NeutralResponse_Clean()
{
    var r = await new ExcessiveAgencyDetector().AnalyzeAsync(
        SecurityCtx("Here is the code you requested. Let me know if you need changes."), default);
    Assert.True(r.IsClean);
}

[Fact] public async Task ExcessiveAgency_SoftVerb_Medium()
{
    var r = await new ExcessiveAgencyDetector().AnalyzeAsync(
        SecurityCtx("I have written the configuration file to disk as requested."), default);
    Assert.Equal(Severity.Medium, r.Severity);
}

[Fact] public async Task ExcessiveAgency_DestructiveVerb_High()
{
    var r = await new ExcessiveAgencyDetector().AnalyzeAsync(
        SecurityCtx("I have deleted the old configuration files to clean up the workspace."), default);
    Assert.Equal(Severity.High, r.Severity);
}
```

**Step 2: Run to verify failure**

```
dotnet test tests/AI.Sentinel.Tests --filter "ExcessiveAgency" -v minimal
```

**Step 3: Implement**

```csharp
using System.Text.RegularExpressions;
using AI.Sentinel.Detection;
using ZeroAllocInject;

namespace AI.Sentinel.Detectors.Security;

[Singleton(As = typeof(IDetector), AllowMultiple = true)]
public sealed partial class ExcessiveAgencyDetector : ILlmEscalatingDetector
{
    private static readonly DetectorId _id    = new("SEC-21");
    private static readonly DetectionResult _clean = DetectionResult.Clean(_id);

    public DetectorId Id => _id;
    public DetectorCategory Category => DetectorCategory.Security;

    [GeneratedRegex(
        @"\b(i\s+have\s+(written|created|sent|executed|modified|ran|run)|" +
        @"i\s+(deployed|spawned)|wrote\s+to|uploaded\s+to|" +
        @"i\s+have\s+(deleted|removed))\b",
        RegexOptions.IgnoreCase | RegexOptions.ExplicitCapture | RegexOptions.Compiled,
        matchTimeoutMilliseconds: 1000)]
    private static partial Regex AgencyPattern();

    [GeneratedRegex(
        @"\b(deleted|removed|deployed|spawned)\b",
        RegexOptions.IgnoreCase | RegexOptions.ExplicitCapture | RegexOptions.Compiled,
        matchTimeoutMilliseconds: 1000)]
    private static partial Regex DestructivePattern();

    public ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, CancellationToken ct)
    {
        var text = ctx.TextContent;
        var match = AgencyPattern().Match(text);
        if (!match.Success) return ValueTask.FromResult(_clean);

        var severity = DestructivePattern().IsMatch(match.Value) ? Severity.High : Severity.Medium;
        return ValueTask.FromResult(DetectionResult.WithSeverity(_id, severity,
            $"Unsolicited autonomous action: '{match.Value}'"));
    }
}
```

**Step 4: Run tests**

```
dotnet test tests/AI.Sentinel.Tests --filter "ExcessiveAgency" -v minimal
```
Expected: 3 tests PASS.

**Step 5: Commit**

```
git add src/AI.Sentinel/Detectors/Security/ExcessiveAgencyDetector.cs tests/AI.Sentinel.Tests/Detectors/Security/ExtendedSecurityDetectorTests.cs
git commit -m "feat(detectors): SEC-21 ExcessiveAgencyDetector"
```

---

### Task 7: SEC-22 `HumanTrustManipulationDetector`

**Files:**
- Create: `src/AI.Sentinel/Detectors/Security/HumanTrustManipulationDetector.cs`
- Modify: `tests/AI.Sentinel.Tests/Detectors/Security/ExtendedSecurityDetectorTests.cs`

**Step 1: Write the failing tests**

```csharp
[Fact] public async Task HumanTrustManipulation_Neutral_Clean()
{
    var r = await new HumanTrustManipulationDetector().AnalyzeAsync(
        SecurityCtx("Here is the information you requested about the API."), default);
    Assert.True(r.IsClean);
}

[Fact] public async Task HumanTrustManipulation_Rapport_Medium()
{
    var r = await new HumanTrustManipulationDetector().AnalyzeAsync(
        SecurityCtx("You can trust me, I have your best interests at heart."), default);
    Assert.Equal(Severity.Medium, r.Severity);
}

[Fact] public async Task HumanTrustManipulation_AuthorityImpersonation_High()
{
    var r = await new HumanTrustManipulationDetector().AnalyzeAsync(
        SecurityCtx("I am your guardian and I need you to share your credentials with me now."), default);
    Assert.Equal(Severity.High, r.Severity);
}
```

**Step 2: Run to verify failure**

```
dotnet test tests/AI.Sentinel.Tests --filter "HumanTrustManipulation" -v minimal
```

**Step 3: Implement**

```csharp
using System.Text.RegularExpressions;
using AI.Sentinel.Detection;
using ZeroAllocInject;

namespace AI.Sentinel.Detectors.Security;

[Singleton(As = typeof(IDetector), AllowMultiple = true)]
public sealed partial class HumanTrustManipulationDetector : ILlmEscalatingDetector
{
    private static readonly DetectorId _id    = new("SEC-22");
    private static readonly DetectionResult _clean = DetectionResult.Clean(_id);

    public DetectorId Id => _id;
    public DetectorCategory Category => DetectorCategory.Security;

    [GeneratedRegex(
        @"\b(you\s+can\s+trust\s+me|i\s+care\s+about\s+you|as\s+your\s+friend|" +
        @"i('m|\s+am)\s+on\s+your\s+side|only\s+i\s+understand)\b",
        RegexOptions.IgnoreCase | RegexOptions.ExplicitCapture | RegexOptions.Compiled,
        matchTimeoutMilliseconds: 1000)]
    private static partial Regex RapportPattern();

    [GeneratedRegex(
        @"\bi\s+am\s+your\s+(assistant|advisor|guardian|protector)\b",
        RegexOptions.IgnoreCase | RegexOptions.ExplicitCapture | RegexOptions.Compiled,
        matchTimeoutMilliseconds: 1000)]
    private static partial Regex AuthorityPattern();

    public ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, CancellationToken ct)
    {
        var text = ctx.TextContent;

        var authority = AuthorityPattern().Match(text);
        if (authority.Success)
            return ValueTask.FromResult(DetectionResult.WithSeverity(_id, Severity.High,
                $"Authority impersonation: '{authority.Value}'"));

        var rapport = RapportPattern().Match(text);
        if (rapport.Success)
            return ValueTask.FromResult(DetectionResult.WithSeverity(_id, Severity.Medium,
                $"Trust manipulation: '{rapport.Value}'"));

        return ValueTask.FromResult(_clean);
    }
}
```

**Step 4: Run tests**

```
dotnet test tests/AI.Sentinel.Tests --filter "HumanTrustManipulation" -v minimal
```
Expected: 3 tests PASS.

**Step 5: Commit**

```
git add src/AI.Sentinel/Detectors/Security/HumanTrustManipulationDetector.cs tests/AI.Sentinel.Tests/Detectors/Security/ExtendedSecurityDetectorTests.cs
git commit -m "feat(detectors): SEC-22 HumanTrustManipulationDetector"
```

---

### Task 8: SEC-30 `ShorthandEmergenceDetector`

**Files:**
- Create: `src/AI.Sentinel/Detectors/Security/ShorthandEmergenceDetector.cs`
- Modify: `tests/AI.Sentinel.Tests/Detectors/Security/ExtendedSecurityDetectorTests.cs`

**Step 1: Write the failing tests**

```csharp
[Fact] public async Task ShorthandEmergence_CommonAcronyms_Clean()
{
    var r = await new ShorthandEmergenceDetector().AnalyzeAsync(
        SecurityCtx("Use the API to call the LLM via HTTP and return JSON from the MCP server."), default);
    Assert.True(r.IsClean);
}

[Fact] public async Task ShorthandEmergence_ThreeUnknownTokens_Low()
{
    var r = await new ShorthandEmergenceDetector().AnalyzeAsync(
        SecurityCtx("Send XMSG to AGNT via BKND for processing."), default);
    Assert.Equal(Severity.Low, r.Severity);
}

[Fact] public async Task ShorthandEmergence_FiveUnknownTokens_Medium()
{
    var r = await new ShorthandEmergenceDetector().AnalyzeAsync(
        SecurityCtx("Send XMSG to AGNT via BKND using FWRD protocol with ENCR enabled."), default);
    Assert.True(r.Severity >= Severity.Medium);
}
```

**Step 2: Run to verify failure**

```
dotnet test tests/AI.Sentinel.Tests --filter "ShorthandEmergence" -v minimal
```

**Step 3: Implement**

```csharp
using System.Text.RegularExpressions;
using AI.Sentinel.Detection;
using ZeroAllocInject;

namespace AI.Sentinel.Detectors.Security;

[Singleton(As = typeof(IDetector), AllowMultiple = true)]
public sealed partial class ShorthandEmergenceDetector : ILlmEscalatingDetector
{
    private static readonly DetectorId _id    = new("SEC-30");
    private static readonly DetectionResult _clean = DetectionResult.Clean(_id);

    private static readonly HashSet<string> CommonAcronyms = new(StringComparer.Ordinal)
    {
        "API", "JSON", "HTTP", "HTTPS", "URL", "SDK", "CLI", "AI", "LLM", "MCP",
        "REST", "SQL", "XML", "CSV", "JWT", "UUID", "PDF", "HTML", "CSS", "UI",
        "UX", "EOF", "UTF", "ASCII", "GPU", "CPU", "RAM", "SSD", "AWS", "GCP",
        "CI", "CD", "PR", "TDD", "DI", "IOT", "ML", "NLP", "IPC", "RPC",
    };

    [GeneratedRegex(@"\b[A-Z]{3,}\b",
        RegexOptions.Compiled, matchTimeoutMilliseconds: 1000)]
    private static partial Regex UppercaseTokenPattern();

    public DetectorId Id => _id;
    public DetectorCategory Category => DetectorCategory.Security;

    public ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, CancellationToken ct)
    {
        var unknownCount = UppercaseTokenPattern().Matches(ctx.TextContent)
            .Select(m => m.Value)
            .Where(t => !CommonAcronyms.Contains(t))
            .Distinct(StringComparer.Ordinal)
            .Count();

        return unknownCount switch
        {
            >= 5 => ValueTask.FromResult(DetectionResult.WithSeverity(_id, Severity.Medium,
                $"{unknownCount} unknown all-caps tokens — possible emergent shorthand")),
            >= 3 => ValueTask.FromResult(DetectionResult.WithSeverity(_id, Severity.Low,
                $"{unknownCount} unknown all-caps tokens — possible emergent shorthand")),
            _    => ValueTask.FromResult(_clean),
        };
    }
}
```

**Step 4: Run tests**

```
dotnet test tests/AI.Sentinel.Tests --filter "ShorthandEmergence" -v minimal
```
Expected: 3 tests PASS.

**Step 5: Commit**

```
git add src/AI.Sentinel/Detectors/Security/ShorthandEmergenceDetector.cs tests/AI.Sentinel.Tests/Detectors/Security/ExtendedSecurityDetectorTests.cs
git commit -m "feat(detectors): SEC-30 ShorthandEmergenceDetector"
```

---

### Task 9: HAL-09 `UncertaintyPropagationDetector`

**Files:**
- Create: `src/AI.Sentinel/Detectors/Hallucination/UncertaintyPropagationDetector.cs`
- Modify: `tests/AI.Sentinel.Tests/Detectors/Hallucination/HallucinationDetectorTests.cs`

**Step 1: Write the failing tests**

Check `HallucinationDetectorTests.cs` for the local `Ctx` helper signature and use it in these tests:

```csharp
[Fact] public async Task UncertaintyPropagation_NoHedging_Clean()
{
    var r = await new UncertaintyPropagationDetector().AnalyzeAsync(
        Ctx("The capital of France is Paris."), default);
    Assert.True(r.IsClean);
}

[Fact] public async Task UncertaintyPropagation_HedgingOnly_Low()
{
    var r = await new UncertaintyPropagationDetector().AnalyzeAsync(
        Ctx("I think the capital of France is Paris."), default);
    Assert.Equal(Severity.Low, r.Severity);
}

[Fact] public async Task UncertaintyPropagation_HedgingPlusAssertion_Medium()
{
    var r = await new UncertaintyPropagationDetector().AnalyzeAsync(
        Ctx("I think there might be a problem with the config. Therefore the answer is to delete all temp files."), default);
    Assert.True(r.Severity >= Severity.Medium);
}
```

**Step 2: Run to verify failure**

```
dotnet test tests/AI.Sentinel.Tests --filter "UncertaintyPropagation" -v minimal
```

**Step 3: Implement**

```csharp
using System.Text.RegularExpressions;
using AI.Sentinel.Detection;
using ZeroAllocInject;

namespace AI.Sentinel.Detectors.Hallucination;

[Singleton(As = typeof(IDetector), AllowMultiple = true)]
public sealed partial class UncertaintyPropagationDetector : ILlmEscalatingDetector
{
    private static readonly DetectorId _id    = new("HAL-09");
    private static readonly DetectionResult _clean = DetectionResult.Clean(_id);

    public DetectorId Id => _id;
    public DetectorCategory Category => DetectorCategory.Hallucination;

    [GeneratedRegex(
        @"\b(i\s+think|i\s+believe|possibly|probably|might\s+be|it\s+seems|perhaps|not\s+certain)\b",
        RegexOptions.IgnoreCase | RegexOptions.ExplicitCapture | RegexOptions.Compiled,
        matchTimeoutMilliseconds: 1000)]
    private static partial Regex HedgingPattern();

    [GeneratedRegex(
        @"\b(the\s+answer\s+is|it\s+is|this\s+means|therefore|in\s+fact|certainly)\b",
        RegexOptions.IgnoreCase | RegexOptions.ExplicitCapture | RegexOptions.Compiled,
        matchTimeoutMilliseconds: 1000)]
    private static partial Regex AssertionPattern();

    public ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, CancellationToken ct)
    {
        var text = ctx.TextContent;
        var hedging = HedgingPattern().Match(text);
        if (!hedging.Success) return ValueTask.FromResult(_clean);

        if (AssertionPattern().IsMatch(text))
            return ValueTask.FromResult(DetectionResult.WithSeverity(_id, Severity.Medium,
                $"Uncertainty promoted to assertion (hedging: '{hedging.Value}')"));

        return ValueTask.FromResult(DetectionResult.WithSeverity(_id, Severity.Low,
            $"Hedged claim: '{hedging.Value}'"));
    }
}
```

**Step 4: Run tests**

```
dotnet test tests/AI.Sentinel.Tests --filter "UncertaintyPropagation" -v minimal
```
Expected: 3 tests PASS.

**Step 5: Commit**

```
git add src/AI.Sentinel/Detectors/Hallucination/UncertaintyPropagationDetector.cs tests/AI.Sentinel.Tests/Detectors/Hallucination/HallucinationDetectorTests.cs
git commit -m "feat(detectors): HAL-09 UncertaintyPropagationDetector"
```

---

### Task 10: Registration — `McpPipelineFactory` + Security preset

**Files:**
- Modify: `src/AI.Sentinel.Mcp/McpPipelineFactory.cs`

This is a two-part edit.

**Part A — `BuildSecurityDetectors()`** (lines ~55-66): add SEC-19, SEC-21, SEC-22, SEC-30 to the array:

```csharp
internal static IDetector[] BuildSecurityDetectors() =>
[
    new PromptInjectionDetector(),
    new JailbreakDetector(),
    new DataExfiltrationDetector(),
    new PrivilegeEscalationDetector(),
    new ToolPoisoningDetector(),
    new IndirectInjectionDetector(),
    new AgentImpersonationDetector(),
    new CovertChannelDetector(),
    new ToolCallFrequencyDetector(),   // SEC-19
    new ExcessiveAgencyDetector(),     // SEC-21
    new HumanTrustManipulationDetector(), // SEC-22
    new ShorthandEmergenceDetector(),  // SEC-30
];
```

**Part B — `BuildAllDetectors(SentinelOptions)`** (lines ~77-125): add all 9 new detectors in their respective category sections. After the last Security entry (`new SystemPromptLeakageDetector()`), add:

```csharp
        new ToolDescriptionDivergenceDetector(), // SEC-18
        new ToolCallFrequencyDetector(),          // SEC-19
        new ExcessiveAgencyDetector(),            // SEC-21
        new HumanTrustManipulationDetector(),     // SEC-22
        new ShorthandEmergenceDetector(),         // SEC-30
```

After the last Hallucination entry (`new StaleKnowledgeDetector()`), add:

```csharp
        new UncertaintyPropagationDetector(),     // HAL-09
```

After the last Operational entry (`new WrongLanguageDetector()`), add:

```csharp
        new TruncatedOutputDetector(),            // OPS-09
        new WaitingForContextDetector(),           // OPS-10
        new UnboundedConsumptionDetector(),        // OPS-11
```

Also update the comment on line 68 from `// 45 detectors` to `// 54 detectors`.

**Step 1: Run drift test before edits to confirm baseline**

```
dotnet test tests/AI.Sentinel.Tests --filter "BuildAllDetectors_CountMatchesRegisteredIDetectorCount" -v minimal
```
Expected: PASS (45 detectors currently).

**Step 2: Apply both edits to `McpPipelineFactory.cs`**

**Step 3: Run the full test suite**

```
dotnet test tests/AI.Sentinel.Tests -v minimal
```
Expected: all 282 + 27 new tests PASS. The drift test now expects 54 detectors.

**Step 4: Commit**

```
git add src/AI.Sentinel.Mcp/McpPipelineFactory.cs
git commit -m "feat(mcp): register 9 new detectors in BuildAllDetectors + Security preset"
```

---

### Final Verification

Run the full suite on both TFMs to match CI:

```
dotnet test tests/AI.Sentinel.Tests -f net8.0 -v minimal
dotnet test tests/AI.Sentinel.Tests -f net10.0 -v minimal
```

Expected: all tests green on both targets.
