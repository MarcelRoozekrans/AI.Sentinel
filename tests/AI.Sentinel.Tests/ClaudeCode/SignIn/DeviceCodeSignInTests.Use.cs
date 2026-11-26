using AI.Sentinel.ClaudeCode.Resident;
using AI.Sentinel.ClaudeCode.SignIn;
using AI.Sentinel.Profiles;
using AI.Sentinel.Tests.ClaudeCode.Resident;
using Xunit;

namespace AI.Sentinel.Tests.ClaudeCode.SignIn;

/// <summary>Using the tokens: the resident process holds them, refreshes them and sends them on every server request.</summary>
public partial class DeviceCodeSignInTests
{
    private async Task<TokenSession> SignedIn(ITokenStore? store = null)
    {
        _server.ServerKeys.Add(Convert.ToBase64String(ProfileSigningKey.Generate().PublicKey));
        var outcome = await SignIn().RunAsync(_ => { }, TestContext.Current.CancellationToken);
        var session = new TokenSession(Client(), store, _time);
        session.Set(outcome.Tokens);
        return session;
    }

    [Fact]
    public async Task A_refresh_in_flight_cannot_write_the_earlier_account_over_a_new_sign_in()
    {
        var ct = TestContext.Current.CancellationToken;
        var store = new FakeTokenStore();
        store.Save("rt-earlier");
        _server.ValidRefreshToken = "rt-earlier";
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        _server.BeforeRefresh = async () =>
        {
            entered.TrySetResult();
            await release.Task;
        };
        var session = new TokenSession(Client(), store, _time);

        // The earlier account refreshes, and rotates its refresh token, while the new sign-in is handed over.
        var refreshing = session.GetAccessTokenAsync(ct);
        await entered.Task.WaitAsync(ct);
        var setting = Task.Run(() => session.Set(new TokenSet("at-new", "rt-new", _time.GetUtcNow().AddHours(1))), ct);
        release.SetResult();
        await refreshing;

        Assert.Equal(KeychainState.Kept, await setting);
        Assert.Equal("rt-new", store.Secret);
        Assert.Equal("at-new", (await session.GetAccessTokenAsync(ct)).AccessToken);
    }

    [Fact]
    public async Task An_empty_access_token_is_no_token_at_sign_in_nor_at_a_refresh()
    {
        var session = await SignedIn();
        _server.AccessTokenField = "";

        var failure = await Assert.ThrowsAsync<SignInException>(() => SignIn().RunAsync(_ => { }, TestContext.Current.CancellationToken));
        Assert.Equal(SignInFailure.Protocol, failure.Kind);

        // That second sign-in made the fake rotate; the session still holds the refresh token of the first one.
        _server.ValidRefreshToken = "rt-1";
        // Inside the early renewal window the refresh is tried, answers an empty token, and the token that is still valid is kept.
        _time.Advance(TimeSpan.FromSeconds(3590));
        var answer = await session.GetAccessTokenAsync(TestContext.Current.CancellationToken);
        Assert.Equal(TokenAnswerKind.Token, answer.Kind);
        Assert.Equal("at-1", answer.AccessToken);
    }

    [Fact]
    public async Task The_access_token_is_refreshed_without_a_new_sign_in()
    {
        var session = await SignedIn();
        var first = await session.GetAccessTokenAsync(TestContext.Current.CancellationToken);
        Assert.Equal(TokenAnswerKind.Token, first.Kind);
        Assert.Equal("at-1", first.AccessToken);

        _time.Advance(TimeSpan.FromSeconds(3600));
        var second = await session.GetAccessTokenAsync(TestContext.Current.CancellationToken);
        Assert.Equal("at-2", second.AccessToken);
        Assert.Equal(SignInStatus.SignedIn, session.Status);
    }

    [Fact]
    public async Task A_rejected_refresh_token_reports_that_sign_in_is_needed()
    {
        var session = await SignedIn();
        _server.ValidRefreshToken = "someone-else";
        _time.Advance(TimeSpan.FromSeconds(3600));

        var answer = await session.GetAccessTokenAsync(TestContext.Current.CancellationToken);

        Assert.Equal(TokenAnswerKind.SignInRequired, answer.Kind);
        Assert.Equal(SignInStatus.SignInNeeded, session.Status);
        Assert.Equal(TokenAnswerKind.SignInRequired, (await session.GetAccessTokenAsync(TestContext.Current.CancellationToken)).Kind);
    }

    [Fact]
    public async Task A_provider_that_is_down_is_not_a_reason_to_sign_in_again()
    {
        var session = await SignedIn();
        _server.RefreshUnavailable = true;
        _time.Advance(TimeSpan.FromSeconds(3600));

        var answer = await session.GetAccessTokenAsync(TestContext.Current.CancellationToken);
        Assert.Equal(TokenAnswerKind.Unavailable, answer.Kind);
        Assert.Equal(SignInStatus.SignedIn, session.Status);

        _server.RefreshUnavailable = false;
        Assert.Equal("at-2", (await session.GetAccessTokenAsync(TestContext.Current.CancellationToken)).AccessToken);
    }

    [Fact]
    public async Task A_provider_without_refresh_tokens_signs_in_and_then_reports_sign_in_needed_at_expiry()
    {
        _server.IssueRefreshToken = false;
        var session = await SignedIn();

        Assert.Equal("at-1", (await session.GetAccessTokenAsync(TestContext.Current.CancellationToken)).AccessToken);
        _time.Advance(TimeSpan.FromSeconds(3600));
        Assert.Equal(TokenAnswerKind.SignInRequired, (await session.GetAccessTokenAsync(TestContext.Current.CancellationToken)).Kind);
        Assert.Equal(SignInStatus.SignInNeeded, session.Status);
    }

    [Fact]
    public async Task An_access_token_without_a_refresh_token_is_used_until_it_expires_not_until_the_skew()
    {
        var session = new TokenSession(Client(), null, _time);
        session.Set(new TokenSet("at-short", null, _time.GetUtcNow().AddSeconds(20)));

        Assert.Equal("at-short", (await session.GetAccessTokenAsync(TestContext.Current.CancellationToken)).AccessToken);
        _time.Advance(TimeSpan.FromSeconds(21));
        Assert.Equal(TokenAnswerKind.SignInRequired, (await session.GetAccessTokenAsync(TestContext.Current.CancellationToken)).Kind);
    }

    [Fact]
    public async Task The_refresh_request_asks_for_no_scope_and_keeps_the_token_when_the_client_is_not_authorised()
    {
        var session = await SignedIn();
        _time.Advance(TimeSpan.FromSeconds(3600));
        _ = await session.GetAccessTokenAsync(TestContext.Current.CancellationToken);
        var refresh = _server.Bodies.Last(b => b.Contains("grant_type=refresh_token", StringComparison.Ordinal));
        Assert.DoesNotContain("scope", refresh, StringComparison.Ordinal);

        // RFC 6749 section 5.2: unauthorized_client is about the client and the grant type, not about this token.
        var store = new FakeTokenStore();
        store.Save("rt-keep");
        var kept = new TokenSession(Client(), store, _time);
        _server.RefreshError = "unauthorized_client";
        Assert.Equal(TokenAnswerKind.Unavailable, (await kept.GetAccessTokenAsync(TestContext.Current.CancellationToken)).Kind);
        Assert.Equal("rt-keep", store.Secret);
        Assert.Equal(SignInStatus.SignedIn, kept.Status);
    }

    [Fact]
    public async Task A_token_that_lives_zero_seconds_is_refused_and_a_missing_lifetime_gets_the_default()
    {
        _server.ServerKeys.Add(Convert.ToBase64String(ProfileSigningKey.Generate().PublicKey));
        _server.AccessLifetimeSeconds = 0;
        var ex = await Assert.ThrowsAsync<SignInException>(() => SignIn().RunAsync(_ => { }, TestContext.Current.CancellationToken));
        Assert.Equal(SignInFailure.Protocol, ex.Kind);

        _server.AccessLifetimeSeconds = null;
        var outcome = await SignIn().RunAsync(_ => { }, TestContext.Current.CancellationToken);
        Assert.Equal(_time.GetUtcNow().AddHours(1), outcome.Tokens.ExpiresAt);
    }

    [Fact]
    public async Task Polling_goes_on_after_a_connection_timeout_but_slower_and_a_cancel_still_stops_it()
    {
        _server.PollTimeouts = 2;
        _server.ServerKeys.Add(Convert.ToBase64String(ProfileSigningKey.Generate().PublicKey));

        var outcome = await SignIn().RunAsync(_ => { }, TestContext.Current.CancellationToken);

        Assert.Equal("at-1", outcome.Tokens.AccessToken);
        Assert.Equal(3, _delays.Count);
        Assert.True(_delays[1] > _delays[0]);
        Assert.True(_delays[2] > _delays[1]);

        using var cts = new CancellationTokenSource();
        var cancelling = new OidcDeviceClient(Http(), _settings, _time, (_, _) => { cts.Cancel(); cts.Token.ThrowIfCancellationRequested(); return Task.CompletedTask; });
        var authorization = await cancelling.StartAsync(TestContext.Current.CancellationToken);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => cancelling.PollAsync(authorization, cts.Token));
    }

    [Fact]
    public async Task Every_server_request_carries_the_access_token_and_a_missing_sign_in_is_reported()
    {
        var session = await SignedIn();
        using var http = new HttpClient(new BearerTokenHandler(session, _server, new Uri(FakeOidcServer.Server)));
        using var response = await http.GetAsync(new Uri(FakeOidcServer.Server + "/echo"), TestContext.Current.CancellationToken);
        Assert.Equal(System.Net.HttpStatusCode.NoContent, response.StatusCode);
        Assert.Equal("Bearer at-1", _server.Authorizations[^1]);

        var signedOut = new TokenSession(Client(), null, _time);
        using var plain = new HttpClient(new BearerTokenHandler(signedOut, _server, new Uri(FakeOidcServer.Server)));
        await Assert.ThrowsAsync<SignInRequiredException>(() => plain.GetAsync(new Uri(FakeOidcServer.Server + "/echo"), TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task The_token_goes_to_the_bound_server_only_and_a_request_without_an_address_is_refused()
    {
        var session = await SignedIn();
        using var invoker = new HttpMessageInvoker(new BearerTokenHandler(session, _server, new Uri(FakeOidcServer.Server)));
        var before = _server.Requests.Count;

        using var elsewhere = new HttpRequestMessage(HttpMethod.Get, new Uri("https://other.example.org/echo"));
        await Assert.ThrowsAsync<InvalidOperationException>(() => invoker.SendAsync(elsewhere, TestContext.Current.CancellationToken));
        using var nowhere = new HttpRequestMessage(HttpMethod.Get, (Uri?)null);
        await Assert.ThrowsAsync<InvalidOperationException>(() => invoker.SendAsync(nowhere, TestContext.Current.CancellationToken));

        Assert.Equal(before, _server.Requests.Count);
        Assert.Null(nowhere.Headers.Authorization);
        Assert.Null(elsewhere.Headers.Authorization);
    }

    [Fact]
    public async Task A_token_set_issued_by_another_issuer_is_not_taken_by_the_resident_process()
    {
        var session = new TokenSession(Client(), null, _time);
        await using var host = new HostedResident(_dir, tokens: session);
        await host.WaitUntilListeningAsync();
        var client = new ResidentClient(host.Settings);
        var tokens = new TokenSet("at-9", "rt-9", _time.GetUtcNow().AddHours(1));

        foreach (var (issuer, clientId) in new (string?, string?)[]
                 {
                     ("https://idp.other.example.org", FakeOidcServer.ClientId),
                     (FakeOidcServer.Issuer, "another-client"),
                     (null, null),
                 })
        {
            var refused = await client.SendAsync(
                new ResidentRequest { Op = ResidentOps.SignIn, Tokens = tokens, Issuer = issuer, ClientId = clientId }, TimeSpan.FromSeconds(5));
            Assert.False(refused!.Ok);
            Assert.Equal(SignInStatus.SignInNeeded, session.Status);
        }

        var taken = await client.SendAsync(
            new ResidentRequest { Op = ResidentOps.SignIn, Tokens = tokens, Issuer = FakeOidcServer.Issuer + "/", ClientId = FakeOidcServer.ClientId }, TimeSpan.FromSeconds(5));
        Assert.True(taken!.Ok);
        Assert.Equal("at-9", (await session.GetAccessTokenAsync(TestContext.Current.CancellationToken)).AccessToken);
    }

    [Fact]
    public async Task The_resident_process_takes_the_tokens_over_the_local_channel()
    {
        var session = new TokenSession(Client(), null, _time);
        await using var host = new HostedResident(_dir, tokens: session);
        await host.WaitUntilListeningAsync();
        var client = new ResidentClient(host.Settings);

        var before = await client.SendAsync(new ResidentRequest { Op = ResidentOps.SignInStatus }, TimeSpan.FromSeconds(5));
        Assert.Equal("sign_in_needed", before!.SignIn);

        var tokens = new TokenSet("at-9", "rt-9", _time.GetUtcNow().AddHours(1));
        var set = await client.SendAsync(new ResidentRequest { Op = ResidentOps.SignIn, Tokens = tokens, Issuer = FakeOidcServer.Issuer, ClientId = FakeOidcServer.ClientId }, TimeSpan.FromSeconds(5));
        Assert.True(set!.Ok);

        var after = await client.SendAsync(new ResidentRequest { Op = ResidentOps.SignInStatus }, TimeSpan.FromSeconds(5));
        Assert.Equal("signed_in", after!.SignIn);
        Assert.Equal("at-9", (await session.GetAccessTokenAsync(TestContext.Current.CancellationToken)).AccessToken);
    }

    [Fact]
    public async Task A_resident_process_without_sign_in_settings_refuses_the_operation()
    {
        await using var host = new HostedResident(_dir);
        await host.WaitUntilListeningAsync();
        var client = new ResidentClient(host.Settings);
        var response = await client.SendAsync(new ResidentRequest { Op = ResidentOps.SignInStatus }, TimeSpan.FromSeconds(5));
        Assert.False(response!.Ok);
        Assert.Equal("off", response.SignIn);
    }

    [Fact]
    public async Task The_token_goes_to_the_scheme_of_the_bound_server_only()
    {
        var session = await SignedIn();
        using var invoker = new HttpMessageInvoker(new BearerTokenHandler(session, _server, new Uri(FakeOidcServer.Server)));
        var before = _server.Requests.Count;

        using var plain = new HttpRequestMessage(HttpMethod.Get, new Uri("http://sentinel.example.com/echo"));
        await Assert.ThrowsAsync<InvalidOperationException>(() => invoker.SendAsync(plain, TestContext.Current.CancellationToken));

        Assert.Equal(before, _server.Requests.Count);
        Assert.Null(plain.Headers.Authorization);
    }

    [Fact]
    public async Task A_discovery_document_of_another_issuer_is_refused()
    {
        _server.DiscoveryIssuer = "https://other.example.com";
        var ex = await Assert.ThrowsAsync<SignInException>(() => SignIn().RunAsync(_ => { }, TestContext.Current.CancellationToken));
        Assert.Equal(SignInFailure.Protocol, ex.Kind);
    }

    [Fact]
    public async Task A_server_error_is_not_read_as_the_provider_revoking_the_token()
    {
        var store = new FakeTokenStore();
        store.Save("rt-1");
        var session = await SignedIn(store);
        _server.RefreshRaw = (System.Net.HttpStatusCode.ServiceUnavailable, "{\"error\":\"invalid_grant\"}");
        _time.Advance(TimeSpan.FromSeconds(3600));

        Assert.Equal(TokenAnswerKind.Unavailable, (await session.GetAccessTokenAsync(TestContext.Current.CancellationToken)).Kind);
        Assert.Equal("rt-1", store.Secret);
        Assert.Equal(SignInStatus.SignedIn, session.Status);
    }

    [Fact]
    public async Task A_server_error_with_token_fields_installs_no_token()
    {
        var session = await SignedIn();
        _server.RefreshRaw = (System.Net.HttpStatusCode.BadGateway, "{\"access_token\":\"evil\",\"token_type\":\"Bearer\",\"expires_in\":3600}");
        _time.Advance(TimeSpan.FromSeconds(3600));

        Assert.Equal(TokenAnswerKind.Unavailable, (await session.GetAccessTokenAsync(TestContext.Current.CancellationToken)).Kind);
    }

    [Fact]
    public async Task An_access_token_that_is_valid_but_inside_the_skew_is_used_when_the_renewal_fails()
    {
        var session = await SignedIn();
        _server.RefreshUnavailable = true;
        _time.Advance(TimeSpan.FromSeconds(3600 - 20));

        var answer = await session.GetAccessTokenAsync(TestContext.Current.CancellationToken);
        Assert.Equal(TokenAnswerKind.Token, answer.Kind);
        Assert.Equal("at-1", answer.AccessToken);

        _time.Advance(TimeSpan.FromSeconds(30));
        Assert.Equal(TokenAnswerKind.Unavailable, (await session.GetAccessTokenAsync(TestContext.Current.CancellationToken)).Kind);
    }

    [Fact]
    public async Task An_empty_refresh_token_counts_as_none_and_keeps_the_one_in_use()
    {
        var session = await SignedIn();
        _server.RefreshTokenField = string.Empty;
        _time.Advance(TimeSpan.FromSeconds(3600));

        Assert.Equal(TokenAnswerKind.Token, (await session.GetAccessTokenAsync(TestContext.Current.CancellationToken)).Kind);
        Assert.Equal(SignInStatus.SignedIn, session.Status);
    }

    [Fact]
    public async Task An_error_code_that_is_not_a_known_one_is_not_echoed()
    {
        _server.PollErrors.Add("sk-secret-looking-value");
        var ex = await Assert.ThrowsAsync<SignInException>(() => SignIn().RunAsync(_ => { }, TestContext.Current.CancellationToken));
        Assert.DoesNotContain("sk-secret", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_keychain_that_could_not_be_read_at_first_is_read_again()
    {
        var store = new FakeTokenStore();
        store.Save("rt-1");
        var session = new TokenSession(Client(), store, _time);
        _server.ValidRefreshToken = "rt-1";
        store.Available = false;
        Assert.Equal(TokenAnswerKind.SignInRequired, (await session.GetAccessTokenAsync(TestContext.Current.CancellationToken)).Kind);

        store.Available = true;
        Assert.Equal(TokenAnswerKind.Token, (await session.GetAccessTokenAsync(TestContext.Current.CancellationToken)).Kind);
    }
}
