using System.Text.Json;
using AI.Sentinel.Detection;
using AI.Sentinel.Detectors.Security;
using AI.Sentinel.Redaction;
using Xunit;

namespace AI.Sentinel.Tests.Redaction;

public class PlaceholderStoreTests
{
    private const string Email = "jan@example.com";
    private const string Secret = "sk-test-0123456789abcdefghij";

    private sealed class ManualClock : TimeProvider
    {
        private DateTimeOffset _now = new(2026, 10, 21, 12, 0, 0, TimeSpan.Zero);

        public override DateTimeOffset GetUtcNow() => _now;

        public void Advance(TimeSpan by) => _now += by;
    }

    private static readonly IRedactingDetector[] Redactors = [new PiiLeakageDetector(), new CredentialExposureDetector()];

    private static PlaceholderStore NewStore(ManualClock? clock = null, int maxEntries = PlaceholderStore.DefaultMaxEntries) =>
        new(PlaceholderStore.DefaultIdleExpiry, maxEntries, clock ?? new ManualClock());

    private static MintedPlaceholder Pii(string token, string value) => new(token, value, RestoreIntoToolArguments: true);

    private static JsonElement Json(string json)
    {
        using var doc = JsonDocument.Parse(json);
        return doc.RootElement.Clone();
    }

    [Fact]
    public void Restore_PiiToken_RestoresValue_SecretTokenStaysLiteral()
    {
        var session = new RedactionSession(Redactors, "k3f9x2");
        var redacted = session.Redact($"mail {Email} with api_key={Secret}");
        var store = NewStore();

        store.Register(session.ExportMinted());

        Assert.Equal("mail [EMAIL_1_k3f9x2] with api_key=[API_KEY_1_k3f9x2]", redacted);
        Assert.Equal($"to {Email} key [API_KEY_1_k3f9x2]", store.RestoreToolArgument("to [EMAIL_1_k3f9x2] key [API_KEY_1_k3f9x2]"));
        Assert.Contains("[API_KEY_1_k3f9x2]", store.KnownTokens());
        Assert.Contains("[EMAIL_1_k3f9x2]", store.KnownTokens());
    }

    [Fact]
    public void Restore_TokensFromTwoSessions_BothRestore()
    {
        var first = new RedactionSession(Redactors, "aaaaa1");
        var second = new RedactionSession(Redactors, "bbbbb2");
        first.Redact($"mail {Email}");
        second.Redact("mail piet@example.org");
        var store = NewStore();

        store.Register(first.ExportMinted());
        store.Register(second.ExportMinted());

        Assert.Equal($"{Email}, piet@example.org", store.RestoreToolArgument("[EMAIL_1_aaaaa1], [EMAIL_1_bbbbb2]"));
        Assert.Equal(2, store.Count);
    }

    [Fact]
    public void Restore_UnknownToken_StaysLiteral()
    {
        var store = NewStore();
        store.Register([Pii("[EMAIL_1_k3f9x2]", Email)]);

        Assert.Equal("[EMAIL_1_zzzzz9] and [EMAIL_1]", store.RestoreToolArgument("[EMAIL_1_zzzzz9] and [EMAIL_1]"));
    }

    [Fact]
    public void Restore_AfterIdleExpiry_LeavesTokenLiteral()
    {
        var clock = new ManualClock();
        var store = new PlaceholderStore(TimeSpan.FromMinutes(30), timeProvider: clock);
        store.Register([Pii("[EMAIL_1_k3f9x2]", Email)]);

        clock.Advance(TimeSpan.FromMinutes(31));

        Assert.Equal("to [EMAIL_1_k3f9x2]", store.RestoreToolArgument("to [EMAIL_1_k3f9x2]"));
        Assert.Equal(0, store.Count);
    }

    [Fact]
    public void Restore_RefreshesIdleTimer()
    {
        var clock = new ManualClock();
        var store = new PlaceholderStore(TimeSpan.FromMinutes(30), timeProvider: clock);
        store.Register([Pii("[EMAIL_1_k3f9x2]", Email)]);

        clock.Advance(TimeSpan.FromMinutes(20));
        Assert.Equal(Email, store.RestoreToolArgument("[EMAIL_1_k3f9x2]"));
        clock.Advance(TimeSpan.FromMinutes(20));

        Assert.Equal(Email, store.RestoreToolArgument("[EMAIL_1_k3f9x2]"));
    }

    [Fact]
    public void Register_OverCap_EvictsLeastRecentlyUsed()
    {
        var store = NewStore(maxEntries: 2);

        store.Register([Pii("[EMAIL_1_aaaaa1]", "a@example.com")]);
        store.Register([Pii("[EMAIL_1_bbbbb2]", "b@example.com")]);
        store.Register([Pii("[EMAIL_1_ccccc3]", "c@example.com")]);

        Assert.Equal(2, store.Count);
        Assert.Equal("[EMAIL_1_aaaaa1]", store.RestoreToolArgument("[EMAIL_1_aaaaa1]"));
        Assert.Equal("b@example.com", store.RestoreToolArgument("[EMAIL_1_bbbbb2]"));
        Assert.Equal("c@example.com", store.RestoreToolArgument("[EMAIL_1_ccccc3]"));
    }

    [Fact]
    public void Register_OverCap_RestoreCountsAsUse()
    {
        var store = NewStore(maxEntries: 2);
        store.Register([Pii("[EMAIL_1_aaaaa1]", "a@example.com")]);
        store.Register([Pii("[EMAIL_1_bbbbb2]", "b@example.com")]);

        Assert.Equal("a@example.com", store.RestoreToolArgument("[EMAIL_1_aaaaa1]"));
        store.Register([Pii("[EMAIL_1_ccccc3]", "c@example.com")]);

        Assert.Equal("a@example.com", store.RestoreToolArgument("[EMAIL_1_aaaaa1]"));
        Assert.Equal("[EMAIL_1_bbbbb2]", store.RestoreToolArgument("[EMAIL_1_bbbbb2]"));
    }

    // Two sessions can draw the same tag and mint the same token; neither value may reach the other's tool call.
    [Fact]
    public void Register_SameTokenDifferentValue_NeverRestoresEither()
    {
        var store = NewStore();
        store.Register([Pii("[EMAIL_1_k3f9x2]", "a@example.com")]);

        store.Register([Pii("[EMAIL_1_k3f9x2]", "b@example.com")]);

        Assert.Equal("[EMAIL_1_k3f9x2]", store.RestoreToolArgument("[EMAIL_1_k3f9x2]"));
        store.Register([Pii("[EMAIL_1_k3f9x2]", "a@example.com")]);
        Assert.Equal("[EMAIL_1_k3f9x2]", store.RestoreToolArgument("[EMAIL_1_k3f9x2]"));
        Assert.Contains("[EMAIL_1_k3f9x2]", store.KnownTokens());
    }

    private static MintedPlaceholder SecretOf(string token, string value) => new(token, value, RestoreIntoToolArguments: false);

    // #459. One call finds a value as PII, a later one finds the same value as a secret: the PII token must not
    // put the secret back into tool arguments.
    [Fact]
    public void Register_PiiValueLaterSeenAsSecret_PiiTokenStaysLiteral()
    {
        var first = new RedactionSession(Redactors, "aaaaa1");
        var second = new RedactionSession(Redactors, "bbbbb2");
        var store = NewStore();

        first.Redact($"mail {Email}");
        store.Register(first.ExportMinted());
        second.Redact($"password: {Email}");
        var secret = Assert.Single(second.ExportMinted());
        store.Register([secret]);

        Assert.False(secret.RestoreIntoToolArguments);
        Assert.Equal("to [EMAIL_1_aaaaa1]", store.RestoreToolArgument("to [EMAIL_1_aaaaa1]"));
        Assert.Contains("[EMAIL_1_aaaaa1]", store.KnownTokens());
    }

    [Fact]
    public void Register_SecretValueLaterSeenAsPii_PiiTokenStaysLiteral()
    {
        var store = NewStore();
        store.Register([SecretOf("[PASSWORD_1_aaaaa1]", Email)]);

        store.Register([Pii("[EMAIL_1_bbbbb2]", Email)]);

        Assert.Equal("[EMAIL_1_bbbbb2]", store.RestoreToolArgument("[EMAIL_1_bbbbb2]"));
    }

    [Fact]
    public void Register_SecretAndPiiInOneCall_PiiTokenStaysLiteral()
    {
        var store = NewStore();

        store.Register([Pii("[EMAIL_1_aaaaa1]", Email), SecretOf("[PASSWORD_1_aaaaa1]", Email)]);

        Assert.Equal("[EMAIL_1_aaaaa1]", store.RestoreToolArgument("[EMAIL_1_aaaaa1]"));
    }

    [Fact]
    public void Register_SecretWithAnotherValue_PiiStillRestores()
    {
        var store = NewStore();
        store.Register([Pii("[EMAIL_1_aaaaa1]", Email)]);

        store.Register([SecretOf("[PASSWORD_1_bbbbb2]", "piet@example.org")]);

        Assert.Equal(Email, store.RestoreToolArgument("[EMAIL_1_aaaaa1]"));
    }

    // Poisoning is for good: the PII entry stays literal after the secret's entry expires.
    [Fact]
    public void Register_PoisonedPiiToken_StaysLiteralAfterTheSecretExpires()
    {
        var clock = new ManualClock();
        var store = new PlaceholderStore(TimeSpan.FromMinutes(30), timeProvider: clock);
        store.Register([Pii("[EMAIL_1_aaaaa1]", Email)]);
        store.Register([SecretOf("[PASSWORD_1_bbbbb2]", Email)]);

        clock.Advance(TimeSpan.FromMinutes(20));
        Assert.Equal("[EMAIL_1_aaaaa1]", store.RestoreToolArgument("[EMAIL_1_aaaaa1]"));
        store.Register([Pii("[EMAIL_1_aaaaa1]", Email)]);
        clock.Advance(TimeSpan.FromMinutes(20));

        Assert.Equal("[EMAIL_1_aaaaa1]", store.RestoreToolArgument("[EMAIL_1_aaaaa1]"));
        Assert.DoesNotContain("[PASSWORD_1_bbbbb2]", store.KnownTokens());
    }

    // The secret's value is known only by its keyed hash, which leaves with its token, as the size cap and idle
    // expiry require. A value first registered after that is restorable, like any token the store has forgotten.
    [Fact]
    public void Register_PiiAfterTheSecretWasEvicted_Restores()
    {
        var store = NewStore(maxEntries: 1);
        store.Register([SecretOf("[PASSWORD_1_aaaaa1]", Email)]);

        store.Register([Pii("[EMAIL_1_bbbbb2]", Email)]);
        store.Register([Pii("[EMAIL_1_ccccc3]", Email)]);

        Assert.Equal(Email, store.RestoreToolArgument("[EMAIL_1_ccccc3]"));
    }

    [Fact]
    public void Register_PiiAfterTheSecretExpired_Restores()
    {
        var clock = new ManualClock();
        var store = new PlaceholderStore(TimeSpan.FromMinutes(30), timeProvider: clock);
        store.Register([SecretOf("[PASSWORD_1_aaaaa1]", Email)]);

        clock.Advance(TimeSpan.FromMinutes(31));
        store.Register([Pii("[EMAIL_1_bbbbb2]", Email)]);

        Assert.Equal(Email, store.RestoreToolArgument("[EMAIL_1_bbbbb2]"));
    }

    // Two tokens can hold one secret; the value stays a secret until the last of them leaves.
    [Fact]
    public void Register_TwoSecretTokensOneValue_PoisonsUntilBothAreGone()
    {
        var store = NewStore(maxEntries: 2);
        store.Register([SecretOf("[PASSWORD_1_aaaaa1]", Email)]);
        store.Register([SecretOf("[PASSWORD_1_bbbbb2]", Email)]);

        // Each registration over the cap evicts the oldest entry: C evicts the first secret, D the second. A token's
        // restorability is settled before that eviction, so D is judged while the second secret still lives.
        store.Register([Pii("[EMAIL_1_ccccc3]", Email)]);
        store.Register([Pii("[EMAIL_1_ddddd4]", Email)]);
        store.Register([Pii("[EMAIL_1_eeeee5]", Email)]);

        Assert.Equal("[EMAIL_1_ddddd4]", store.RestoreToolArgument("[EMAIL_1_ddddd4]"));
        Assert.Equal(Email, store.RestoreToolArgument("[EMAIL_1_eeeee5]"));
    }

    // Two sessions drew the same tag, so one secret token stands for two values; both stay secrets.
    [Fact]
    public void Register_SecretTokenAgainWithAnotherValue_BothValuesStaySecrets()
    {
        var store = NewStore();
        store.Register([SecretOf("[PASSWORD_1_aaaaa1]", Email)]);
        store.Register([SecretOf("[PASSWORD_1_aaaaa1]", "piet@example.org")]);

        store.Register([Pii("[EMAIL_1_bbbbb2]", Email), Pii("[EMAIL_2_bbbbb2]", "piet@example.org")]);

        Assert.Equal("[EMAIL_1_bbbbb2] [EMAIL_2_bbbbb2]", store.RestoreToolArgument("[EMAIL_1_bbbbb2] [EMAIL_2_bbbbb2]"));
    }

    // A secret token registered twice is still one entry: once it is evicted, its value is no longer a secret.
    [Fact]
    public void Register_SecretTokenTwice_LeavesWithOneEviction()
    {
        var store = NewStore(maxEntries: 1);
        store.Register([SecretOf("[PASSWORD_1_aaaaa1]", Email)]);
        store.Register([SecretOf("[PASSWORD_1_aaaaa1]", Email)]);

        store.Register([Pii("[EMAIL_1_bbbbb2]", Email)]);
        store.Register([Pii("[EMAIL_1_ccccc3]", Email)]);

        Assert.Equal(Email, store.RestoreToolArgument("[EMAIL_1_ccccc3]"));
    }

    [Fact]
    public void Register_SameTokenSameValue_StillRestores()
    {
        var store = NewStore();
        store.Register([Pii("[EMAIL_1_k3f9x2]", Email)]);

        store.Register([Pii("[EMAIL_1_k3f9x2]", Email)]);

        Assert.Equal(Email, store.RestoreToolArgument("[EMAIL_1_k3f9x2]"));
    }

    [Fact]
    public void RestoreToolArguments_WalksNestedJson_KeysUnchanged_InputNotMutated()
    {
        var store = NewStore();
        store.Register([Pii("[EMAIL_1_k3f9x2]", Email), new("[API_KEY_1_k3f9x2]", Secret, RestoreIntoToolArguments: false)]);
        var input = new Dictionary<string, JsonElement>(StringComparer.Ordinal)
        {
            ["to"] = Json("\"[EMAIL_1_k3f9x2]\""),
            ["[EMAIL_1_k3f9x2]"] = Json("""{"cc":["x [EMAIL_1_k3f9x2]",3,true,null],"[EMAIL_1_k3f9x2]":"[API_KEY_1_k3f9x2]"}"""),
            ["n"] = Json("7"),
        };

        var restored = store.RestoreToolArguments(input);

        Assert.NotNull(restored);
        Assert.NotSame(input, restored);
        Assert.Equal(["to", "[EMAIL_1_k3f9x2]", "n"], restored.Keys);
        Assert.Equal(Email, restored["to"].GetString());
        var nested = restored["[EMAIL_1_k3f9x2]"];
        Assert.Equal($"x {Email}", nested.GetProperty("cc")[0].GetString());
        Assert.Equal(3, nested.GetProperty("cc")[1].GetInt32());
        Assert.True(nested.GetProperty("cc")[2].GetBoolean());
        Assert.Equal(JsonValueKind.Null, nested.GetProperty("cc")[3].ValueKind);
        Assert.Equal("[API_KEY_1_k3f9x2]", nested.GetProperty("[EMAIL_1_k3f9x2]").GetString());
        Assert.Equal(7, restored["n"].GetInt32());
        Assert.Equal("[EMAIL_1_k3f9x2]", input["to"].GetString());
        Assert.Equal("x [EMAIL_1_k3f9x2]", input["[EMAIL_1_k3f9x2]"].GetProperty("cc")[0].GetString());
    }

    [Fact]
    public void RestoreToolArguments_NothingToRestore_ReturnsSameInstance()
    {
        var store = NewStore();
        store.Register([Pii("[EMAIL_1_k3f9x2]", Email)]);
        var input = new Dictionary<string, JsonElement>(StringComparer.Ordinal)
        {
            ["q"] = Json("\"plain [EMAIL_1_zzzzz9]\""),
            ["n"] = Json("""{"a":[1,"b"]}"""),
        };

        Assert.Same(input, store.RestoreToolArguments(input));
        Assert.Null(store.RestoreToolArguments(null));
    }

    [Fact]
    public void ToString_NeverPrintsValues()
    {
        var store = NewStore();
        var minted = Pii("[EMAIL_1_k3f9x2]", Email);
        store.Register([minted]);

        Assert.Equal(nameof(PlaceholderStore), store.ToString());
        Assert.Equal("[EMAIL_1_k3f9x2]", minted.ToString());
        Assert.DoesNotContain(Email, $"{minted}", StringComparison.Ordinal);
    }

    [Fact]
    public async Task ConcurrentRegisterAndRestore_NoException()
    {
        var store = new PlaceholderStore(PlaceholderStore.DefaultIdleExpiry, maxEntries: 100);
        var tasks = new Task[8];
        for (var t = 0; t < tasks.Length; t++)
        {
            var worker = t;
            tasks[t] = Task.Run(() =>
            {
                for (var i = 0; i < 500; i++)
                {
                    var token = $"[EMAIL_{i + 1}_w{worker}abcd]";
                    store.Register([Pii(token, $"u{i}@example.com")]);
                    store.RestoreToolArgument($"to {token}");
                    _ = store.KnownTokens();
                    _ = store.Count;
                }
            }, TestContext.Current.CancellationToken);
        }

        await Task.WhenAll(tasks);

        Assert.InRange(store.Count, 1, 100);
    }
}
