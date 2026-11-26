using AI.Sentinel.ClaudeCode.Resident;
using AI.Sentinel.ClaudeCode.SignIn;
using AI.Sentinel.Profiles;
using AI.Sentinel.Tests.ClaudeCode.Resident;
using Xunit;

namespace AI.Sentinel.Tests.ClaudeCode.SignIn;

/// <summary>Where the tokens of a sign-in go (#659): the keychain, or memory; never a file, a log or a printout.</summary>
[Collection("NonParallel")]
public class TokenStorageTests : IDisposable
{
    private readonly FakeOidcServer _server = new();
    private readonly ManualTime _time = new();
    private readonly string _dir = ResidentTestSupport.NewDir();
    private readonly StringWriter _stdout = new();
    private readonly StringWriter _stderr = new();

    public TokenStorageTests()
    {
        _server.ServerKeys.Add(Convert.ToBase64String(ProfileSigningKey.Generate().PublicKey));
    }

    public void Dispose()
    {
        _server.Dispose();
        ResidentTestSupport.Delete(_dir);
        _stdout.Dispose();
        _stderr.Dispose();
        GC.SuppressFinalize(this);
    }

    private Dictionary<string, string?> Env() => new(StringComparer.Ordinal)
    {
        [SignInSettings.ServerVariable] = FakeOidcServer.Server,
        [SignInSettings.IssuerVariable] = FakeOidcServer.Issuer,
        [SignInSettings.ClientIdVariable] = FakeOidcServer.ClientId,
        [ResidentSettings.EnableVariable] = "on",
        [ResidentSettings.DirectoryVariable] = _dir,
    };

    private SignInSettings Settings() => new(new Uri(FakeOidcServer.Server), new Uri(FakeOidcServer.Issuer), FakeOidcServer.ClientId, SignInSettings.DefaultScope);

    private OidcDeviceClient Client() => new(new HttpClient(_server, disposeHandler: false), Settings(), _time, (_, _) => Task.CompletedTask);

    private Task<int> Run(ITokenStore? store, Func<ResidentLaunch, bool>? start = null) =>
        SignInCommand.RunAsync(Env(), _stdout, _stderr, _server, store, (_, _) => Task.CompletedTask, start: start ?? (_ => false), time: _time, ct: TestContext.Current.CancellationToken);

    [Fact]
    public async Task The_refresh_token_goes_into_the_keychain_when_there_is_one()
    {
        var store = new FakeTokenStore();
        await using var host = new HostedResident(_dir, tokens: new TokenSession(Client(), store, _time));
        await host.WaitUntilListeningAsync();

        Assert.Equal(0, await Run(store));

        Assert.Equal("rt-1", store.Secret);
        Assert.Contains("Signed in to acme", _stdout.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_sign_in_that_keeps_no_refresh_token_removes_the_one_of_the_earlier_sign_in()
    {
        _server.IssueRefreshToken = false;
        var store = new FakeTokenStore();
        store.Save("rt-earlier");
        await using var host = new HostedResident(_dir, tokens: new TokenSession(Client(), store, _time));
        await host.WaitUntilListeningAsync();

        Assert.Equal(0, await Run(store));

        Assert.Null(store.Secret);
    }

    [Fact]
    public async Task A_sign_in_that_cannot_remove_the_earlier_refresh_token_says_so_and_fails()
    {
        _server.IssueRefreshToken = false;
        var store = new FakeTokenStore();
        store.Save("rt-earlier");
        await using var host = new HostedResident(_dir, tokens: new TokenSession(Client(), store, _time));
        await host.WaitUntilListeningAsync();
        store.Available = false;

        Assert.Equal(1, await Run(store));

        Assert.Contains("earlier sign-in", _stderr.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_resident_process_that_does_not_take_the_sign_in_is_reported_and_not_called_a_success()
    {
        var store = new FakeTokenStore();
        await using var host = new HostedResident(_dir);
        await host.WaitUntilListeningAsync();

        Assert.Equal(0, await Run(store));

        Assert.Equal("rt-1", store.Secret);
        Assert.DoesNotContain("Signed in to", _stdout.ToString(), StringComparison.Ordinal);
        Assert.Contains("did not take", _stdout.ToString(), StringComparison.Ordinal);
        Assert.Contains("restarts", _stdout.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Without_a_keychain_the_resident_process_holds_the_token_in_memory_only()
    {
        var store = new FakeTokenStore(available: false);
        var session = new TokenSession(Client(), store, _time);
        await using var host = new HostedResident(_dir, tokens: session);
        await host.WaitUntilListeningAsync();

        Assert.Equal(0, await Run(store));

        Assert.Equal("at-1", (await session.GetAccessTokenAsync(TestContext.Current.CancellationToken)).AccessToken);
        Assert.Contains("until the resident process ends", _stdout.ToString(), StringComparison.Ordinal);
        AssertNoTokenOnDisk();
    }

    [Fact]
    public async Task Without_a_keychain_and_without_a_resident_process_the_sign_in_fails_and_says_why()
    {
        var store = new FakeTokenStore(available: false);
        Assert.Equal(1, await Run(store));
        Assert.Contains(ResidentSettings.EnableVariable, _stderr.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_restarted_resident_process_signs_in_again_from_the_keychain_but_not_from_memory()
    {
        var store = new FakeTokenStore();
        store.Save("rt-0");
        _server.ValidRefreshToken = "rt-0";
        var restarted = new TokenSession(Client(), store, _time);
        Assert.Equal("at-1", (await restarted.GetAccessTokenAsync(TestContext.Current.CancellationToken)).AccessToken);
        // The provider rotated the token, so the keychain holds the new one.
        Assert.Equal("rt-1", store.Secret);

        var memoryOnly = new TokenSession(Client(), new FakeTokenStore(available: false), _time);
        Assert.Equal(TokenAnswerKind.SignInRequired, (await memoryOnly.GetAccessTokenAsync(TestContext.Current.CancellationToken)).Kind);
        Assert.Equal(SignInStatus.SignInNeeded, memoryOnly.Status);
    }

    [Fact]
    public async Task A_refused_refresh_token_is_removed_from_the_keychain()
    {
        var store = new FakeTokenStore();
        store.Save("stale");
        _server.ValidRefreshToken = "other";
        var session = new TokenSession(Client(), store, _time);
        Assert.Equal(TokenAnswerKind.SignInRequired, (await session.GetAccessTokenAsync(TestContext.Current.CancellationToken)).Kind);
        Assert.Null(store.Secret);
    }

    [Fact]
    public async Task No_token_is_written_to_a_file_or_printed_or_logged()
    {
        var log = new List<string>();
        var store = new FakeTokenStore(available: false);
        var session = new TokenSession(Client(), store, _time, log.Add);
        await using var host = new HostedResident(_dir, tokens: session);
        await host.WaitUntilListeningAsync();
        Assert.Equal(0, await Run(store));
        _time.Advance(TimeSpan.FromHours(2));
        _ = await session.GetAccessTokenAsync(TestContext.Current.CancellationToken);

        AssertNoTokenOnDisk();
        foreach (var text in new[] { _stdout.ToString(), _stderr.ToString(), string.Join('\n', log) })
        {
            Assert.DoesNotContain("at-", text, StringComparison.Ordinal);
            Assert.DoesNotContain("rt-", text, StringComparison.Ordinal);
        }

        var tokens = new TokenSet("at-secret", "rt-secret", _time.GetUtcNow());
        Assert.DoesNotContain("secret", tokens.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain("secret", new ResidentRequest { Op = ResidentOps.SignIn, Tokens = tokens }.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain("secret", new TokenAnswer(TokenAnswerKind.Token, "at-secret").ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_failed_sign_in_carries_no_token_in_its_message()
    {
        _server.ServerKeys.Clear();
        Assert.Equal(1, await Run(new FakeTokenStore()));
        Assert.DoesNotContain("at-", _stderr.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public void Sign_in_is_off_without_its_settings()
    {
        using var http = new HttpClient();
        Assert.Null(SignInCommand.OpenSession(new Dictionary<string, string?>(StringComparer.Ordinal), http, TextWriter.Null));
    }

    [Fact]
    public void Two_sign_ins_keep_their_refresh_tokens_apart_and_the_name_holds_no_address()
    {
        var one = TokenStores.Account(Settings());
        var other = TokenStores.Account(Settings() with { ClientId = "another" });
        Assert.False(string.Equals(one, other, StringComparison.Ordinal));
        Assert.DoesNotContain("example.com", one, StringComparison.Ordinal);
    }

    [Fact]
    public void The_secret_tool_store_passes_the_secret_on_standard_input_and_never_as_an_argument()
    {
        Assert.SkipUnless(OperatingSystem.IsLinux() || OperatingSystem.IsMacOS(), "a shell script stands in for secret-tool");
        var script = Path.Combine(Directory.CreateTempSubdirectory("st-").FullName, "secret-tool");
        var kept = script + ".kept";
        var argv = script + ".argv";
        File.WriteAllText(script, $"#!/bin/sh\necho \"$@\" >> '{argv}'\ncase \"$1\" in\n store) cat > '{kept}';;\n lookup) cat '{kept}';;\n clear) rm -f '{kept}';;\nesac\n");
        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(script, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }

        try
        {
            var log = new List<string>();
            var store = new SecretToolStore("acct", log.Add, script);

            Assert.True(store.Save("rt-store-me"));
            Assert.Equal("rt-store-me", store.Load());
            Assert.DoesNotContain("rt-store-me", File.ReadAllText(argv), StringComparison.Ordinal);
            Assert.Contains(log, l => l.Contains("secret-tool", StringComparison.Ordinal) || l.Contains(script, StringComparison.Ordinal));
            Assert.DoesNotContain(log, l => l.Contains("rt-store-me", StringComparison.Ordinal));
            Assert.True(store.Delete());
            Assert.Null(store.Load());
        }
        finally
        {
            Directory.Delete(Path.GetDirectoryName(script)!, recursive: true);
        }
    }

    [Fact]
    public void A_missing_secret_tool_means_memory_only()
    {
        var log = new List<string>();
        var store = new SecretToolStore("acct", log.Add, "/nonexistent/secret-tool");
        Assert.False(store.Save("rt-x"));
        Assert.Null(store.Load());
        Assert.True(store.Delete());
        Assert.Contains(log, l => l.Contains("memory only", StringComparison.Ordinal));
        Assert.DoesNotContain(log, l => l.Contains("rt-x", StringComparison.Ordinal));
    }

    /// <summary>The keychain of this machine, where there is one that works. A headless Linux, with no Secret Service, skips.</summary>
    [Fact]
    public void The_keychain_of_the_operating_system_keeps_and_returns_a_secret_where_it_is_available()
    {
        var settings = Settings() with { ClientId = "test-" + Guid.NewGuid().ToString("N") };
        var store = TokenStores.ForCurrentOs(settings);
        Assert.SkipWhen(store is null, "this platform has no keychain");
        var secret = "rt-" + Guid.NewGuid().ToString("N");
        if (!store!.Save(secret))
        {
            Assert.Skip($"the {store.Name} is not available here");
        }

        try
        {
            Assert.Equal(secret, store.Load());
            Assert.True(store.Save(secret + "2"));
            Assert.Equal(secret + "2", store.Load());
        }
        finally
        {
            Assert.True(store.Delete());
        }

        Assert.Null(store.Load());
    }

    // The folders a sign-in could write to: the state folder of the resident process and its temporary files.
    private void AssertNoTokenOnDisk()
    {
        foreach (var root in new[] { _dir, _dir + ".private" }.Where(Directory.Exists))
        {
            foreach (var file in Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories))
            {
                if (file.EndsWith(".sock", StringComparison.Ordinal) || file.EndsWith(".lock", StringComparison.Ordinal))
                {
                    continue;
                }

                var text = File.ReadAllText(file);
                Assert.DoesNotContain("at-", text, StringComparison.Ordinal);
                Assert.DoesNotContain("rt-", text, StringComparison.Ordinal);
            }
        }
    }
}
