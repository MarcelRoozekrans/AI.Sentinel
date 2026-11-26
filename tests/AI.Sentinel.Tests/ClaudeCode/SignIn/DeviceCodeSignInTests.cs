using AI.Sentinel.ClaudeCode.Resident;
using AI.Sentinel.ClaudeCode.SignIn;
using AI.Sentinel.Profiles;
using AI.Sentinel.Tests.ClaudeCode.Resident;
using Xunit;

namespace AI.Sentinel.Tests.ClaudeCode.SignIn;

/// <summary>Sign-in with an OIDC device code (#659), against a fake provider that runs in the process.</summary>
[Collection("NonParallel")]
public partial class DeviceCodeSignInTests : IDisposable
{
    private readonly FakeOidcServer _server = new();
    private readonly ManualTime _time = new();
    private readonly List<TimeSpan> _delays = [];
    private readonly string _dir = ResidentTestSupport.NewDir();
    private readonly SignInSettings _settings = new(new Uri(FakeOidcServer.Server), new Uri(FakeOidcServer.Issuer), FakeOidcServer.ClientId, "openid offline_access");

    public void Dispose()
    {
        _server.Dispose();
        ResidentTestSupport.Delete(_dir);
        GC.SuppressFinalize(this);
    }

    private HttpClient Http() => new(_server, disposeHandler: false);

    private Task Delay(TimeSpan by, CancellationToken ct)
    {
        _delays.Add(by);
        _time.Advance(by);
        return Task.CompletedTask;
    }

    private OidcDeviceClient Client() => new(Http(), _settings, _time, Delay);

    private DeviceCodeSignIn SignIn() => new(Client(), Http(), _settings);

    [Fact]
    public void Nothing_is_configured_by_default()
    {
        Assert.Null(SignInSettings.FromEnvironment(new Dictionary<string, string?>(StringComparer.Ordinal), out var problem));
        Assert.Null(problem);
    }

    [Fact]
    public void A_partial_configuration_is_reported_and_not_used()
    {
        var env = new Dictionary<string, string?>(StringComparer.Ordinal) { [SignInSettings.ServerVariable] = FakeOidcServer.Server };
        Assert.Null(SignInSettings.FromEnvironment(env, out var problem));
        Assert.Contains(SignInSettings.IssuerVariable, problem, StringComparison.Ordinal);
    }

    [Fact]
    public void A_plain_http_provider_is_refused_except_on_loopback()
    {
        var env = new Dictionary<string, string?>(StringComparer.Ordinal)
        {
            [SignInSettings.ServerVariable] = FakeOidcServer.Server,
            [SignInSettings.IssuerVariable] = "http://idp.example.com",
            [SignInSettings.ClientIdVariable] = "c",
        };
        Assert.Null(SignInSettings.FromEnvironment(env, out var problem));
        Assert.Contains("https", problem, StringComparison.Ordinal);

        env[SignInSettings.IssuerVariable] = "http://127.0.0.1:5000";
        env[SignInSettings.ServerVariable] = "http://localhost:6000";
        Assert.NotNull(SignInSettings.FromEnvironment(env, out _));
    }

    [Fact]
    public async Task The_developer_signs_in_after_pending_and_slow_down_answers()
    {
        _server.PollErrors.AddRange(["authorization_pending", "slow_down"]);
        _server.ServerKeys.Add(Convert.ToBase64String(ProfileSigningKey.Generate().PublicKey));
        DeviceAuthorization? shown = null;

        var outcome = await SignIn().RunAsync(a => shown = a, TestContext.Current.CancellationToken);

        Assert.Equal("WDJB-MJHT", shown!.UserCode);
        Assert.Equal(FakeOidcServer.Issuer + "/activate", shown.VerificationUri.AbsoluteUri);
        Assert.Equal("at-1", outcome.Tokens.AccessToken);
        Assert.Equal("rt-1", outcome.Tokens.RefreshToken);
        // The interval is 5 seconds, and slow_down adds 5 to every later wait (RFC 8628).
        Assert.Equal([TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(10)], _delays);
        Assert.Equal(3, _server.PollCount);
    }

    [Fact]
    public async Task The_server_keys_are_pinned_at_sign_in_with_the_access_token()
    {
        var one = ProfileSigningKey.Generate();
        var two = ProfileSigningKey.Generate();
        _server.ServerKeys.AddRange([Convert.ToBase64String(one.PublicKey), Convert.ToBase64String(two.PublicKey)]);

        var outcome = await SignIn().RunAsync(_ => { }, TestContext.Current.CancellationToken);

        Assert.Equal("acme", outcome.Organisation);
        Assert.Equal(2, outcome.Keys.Count);
        Assert.True(outcome.Keys.TryGet(one.KeyId, out _));
        var keysCall = _server.Requests.FindIndex(r => r.EndsWith("/profile-keys", StringComparison.Ordinal));
        Assert.Equal("Bearer at-1", _server.Authorizations[keysCall]);

        var state = new ResidentState(Directory.CreateDirectory(_dir).FullName);
        state.WritePinnedKeys(outcome.Organisation, outcome.Keys);
        var read = state.ReadPinnedKeys();
        Assert.Equal("acme", read!.Value.Organisation);
        Assert.Equal(outcome.Keys.ToBase64(), read.Value.Keys.ToBase64());
    }

    [Fact]
    public async Task A_server_that_names_no_usable_key_fails_the_sign_in()
    {
        _server.ServerKeys.Add("not-a-key");
        var ex = await Assert.ThrowsAsync<SignInException>(() => SignIn().RunAsync(_ => { }, TestContext.Current.CancellationToken));
        Assert.Equal(SignInFailure.Protocol, ex.Kind);

        _server.ServerKeys.Clear();
        ex = await Assert.ThrowsAsync<SignInException>(() => SignIn().RunAsync(_ => { }, TestContext.Current.CancellationToken));
        Assert.Equal(SignInFailure.Protocol, ex.Kind);
    }

    [Fact]
    public async Task A_device_code_that_expires_ends_the_sign_in()
    {
        _server.DeviceLifetimeSeconds = 12;
        _server.PollErrors.AddRange(Enumerable.Repeat("authorization_pending", 50));
        var ex = await Assert.ThrowsAsync<SignInException>(() => SignIn().RunAsync(_ => { }, TestContext.Current.CancellationToken));
        Assert.Equal(SignInFailure.Expired, ex.Kind);
    }

    [Fact]
    public async Task An_expired_token_answer_of_the_provider_ends_the_sign_in()
    {
        _server.PollErrors.Add("expired_token");
        var ex = await Assert.ThrowsAsync<SignInException>(() => SignIn().RunAsync(_ => { }, TestContext.Current.CancellationToken));
        Assert.Equal(SignInFailure.Expired, ex.Kind);
    }

    [Fact]
    public async Task A_refused_authorization_ends_the_sign_in()
    {
        _server.PollErrors.Add("access_denied");
        var ex = await Assert.ThrowsAsync<SignInException>(() => SignIn().RunAsync(_ => { }, TestContext.Current.CancellationToken));
        Assert.Equal(SignInFailure.Denied, ex.Kind);
    }

    [Fact]
    public async Task An_endpoint_on_plain_http_in_the_discovery_document_is_refused()
    {
        _server.DeviceEndpoint = "http://evil.example.com/device";
        var ex = await Assert.ThrowsAsync<SignInException>(() => SignIn().RunAsync(_ => { }, TestContext.Current.CancellationToken));
        Assert.Equal(SignInFailure.Protocol, ex.Kind);
    }
}
