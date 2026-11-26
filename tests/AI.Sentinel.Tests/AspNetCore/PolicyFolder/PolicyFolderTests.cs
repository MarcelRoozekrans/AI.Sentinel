using System.Security.Cryptography;
using System.Text;
using AI.Sentinel.AspNetCore.AdminAudit;
using AI.Sentinel.AspNetCore.PolicyFolder;
using Xunit;
using static AI.Sentinel.Tests.AspNetCore.PolicyFolder.PolicyFolderFixture;

namespace AI.Sentinel.Tests.AspNetCore.PolicyFolder;

public sealed class PolicyFolderTests
{
    /// <summary>One pass compiles the module of each of the two nodes alone. The module of all bundles together only names the
    /// configuration: two bundles may each declare the same default rule, which one module cannot hold.</summary>
    private const int CompilesPerPass = 2;

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static string Rules(string marker) => $"package sentinel\n\nimport rego.v1\n\ndeny contains \"{marker}\" if input.kind == \"shell\"\n";

    [Fact]
    public async Task The_folder_holds_bundles_and_node_configuration_and_all_bundles_compile_into_one_module_named_by_its_hash()
    {
        using var f = new PolicyFolderFixture();
        f.Write("v1");
        f.LinkTo("v1");

        var compiled = new List<string>();
        f.Compiler.OnCompile = (sources, _) => compiled.AddRange(sources.Files.Where(s => string.Equals(s.Path, "profile.rego", StringComparison.Ordinal)).Select(s => s.Text));

        var result = await f.Loader.ReloadAsync(Ct);

        Assert.Equal(PassResult.Published, result);
        var current = f.Loader.Current!;
        Assert.Equal(Organisation, current.Organisation, StringComparer.Ordinal);
        Assert.Equal(CompilesPerPass, f.Compiler.Calls);
        Assert.Equal(current.Modules.Values.Select(m => m.Module).Order(StringComparer.Ordinal), compiled.Order(StringComparer.Ordinal), StringComparer.Ordinal);
        Assert.DoesNotContain(current.Module, compiled, StringComparer.Ordinal);
        Assert.Contains("recursive delete", current.Module, StringComparison.Ordinal);
        Assert.Contains("team asks", current.Module, StringComparison.Ordinal);
        Assert.Equal(Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(current.Module))), current.ModuleHash, StringComparer.Ordinal);
        var team = current.Nodes.NodeFor(Repository)!;
        Assert.Equal("team-a", team.Id, StringComparer.Ordinal);
        Assert.Equal(TimeSpan.FromHours(24), team.ProfileLifetime);
        Assert.True(team.DetailedLogging);
        Assert.Equal("closed", team.FailMode, StringComparer.Ordinal);
        Assert.Equal(["sec", "leads"], current.Nodes.Roles.Select(r => r.Group), StringComparer.Ordinal);
        Assert.Equal("acme", current.Nodes.NodeFor("github.com/acme/other")!.Id, StringComparer.Ordinal);
        Assert.Equal(["acme", "team-a"], current.Modules.Keys.Order(StringComparer.Ordinal), StringComparer.Ordinal);
        Assert.DoesNotContain("team asks", current.Modules["acme"].Module, StringComparison.Ordinal);
        Assert.DoesNotContain("recursive delete", current.Modules["team-a"].Module, StringComparison.Ordinal);
        Assert.Null(current.Nodes.NodeFor("github.com/else/where"));
    }

    [Fact]
    public async Task A_change_of_one_bundle_gives_another_module_hash_and_an_unchanged_folder_is_not_compiled_again()
    {
        using var f = new PolicyFolderFixture();
        f.Write("v1");
        f.LinkTo("v1");
        await f.Loader.ReloadAsync(Ct);
        var first = f.Loader.Current!;

        Assert.Equal(PassResult.Unchanged, await f.Loader.ReloadAsync(Ct));
        Assert.Equal(CompilesPerPass, f.Compiler.Calls);

        f.Write("v2", teamRules: Rules("other"));
        f.LinkTo("v2");
        Assert.Equal(PassResult.Published, await f.Loader.ReloadAsync(Ct));

        Assert.NotEqual(first.ModuleHash, f.Loader.Current!.ModuleHash, StringComparer.Ordinal);
        Assert.Equal(2 * CompilesPerPass, f.Compiler.Calls);
    }

    [Fact]
    public async Task A_path_that_is_a_link_is_read_through_the_link_and_a_swap_picks_up_the_new_version()
    {
        using var f = new PolicyFolderFixture();
        f.Write("v1", orgRules: Rules("one"));
        f.Write("v2", orgRules: Rules("two"));
        f.LinkTo("v1");
        await f.Loader.ReloadAsync(Ct);
        Assert.Contains("one", f.Loader.Current!.Module, StringComparison.Ordinal);

        f.LinkTo("v2");
        await f.Loader.ReloadAsync(Ct);

        Assert.Contains("two", f.Loader.Current!.Module, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_file_changed_during_the_read_publishes_nothing_mixed_and_the_next_pass_publishes_the_new_version()
    {
        using var f = new PolicyFolderFixture();
        f.Write("v1", orgRules: Rules("old-org"), teamRules: Rules("old-team"));
        f.LinkTo("v1");
        // The files are read in order acme.rego, nodes.json, team-a/rules.rego: the filler writes both rules files between them.
        f.Loader.AfterFileRead = (pass, name) =>
        {
            if (pass == 1 && string.Equals(name, "acme.rego", StringComparison.Ordinal))
            {
                File.WriteAllText(Path.Combine(f.Version("v1"), "acme.rego"), Rules("new-org"));
                File.WriteAllText(Path.Combine(f.Version("v1"), "team-a", "rules.rego"), Rules("new-team"));
            }
        };

        var first = await f.Loader.ReloadAsync(Ct);

        Assert.Equal(PassResult.Retry, first);
        Assert.Null(f.Loader.Current);
        f.Loader.AfterFileRead = null;
        Assert.Equal(PassResult.Published, await f.Loader.ReloadAsync(Ct));
        Assert.Contains("new-org", f.Loader.Current!.Module, StringComparison.Ordinal);
        Assert.Contains("new-team", f.Loader.Current.Module, StringComparison.Ordinal);
        Assert.DoesNotContain("old-", f.Loader.Current.Module, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_file_changed_during_compilation_is_found_by_the_second_read_and_nothing_is_published()
    {
        using var f = new PolicyFolderFixture();
        f.Write("v1", orgRules: Rules("before"));
        f.LinkTo("v1");
        f.Compiler.OnCompile = (_, call) =>
        {
            if (call == 1)
            {
                File.WriteAllText(Path.Combine(f.Version("v1"), "acme.rego"), Rules("after"));
            }
        };

        Assert.Equal(PassResult.Retry, await f.Loader.ReloadAsync(Ct));
        Assert.Null(f.Loader.Current);
        Assert.Empty(await f.AuditAsync());

        Assert.Equal(PassResult.Published, await f.Loader.ReloadAsync(Ct));
        Assert.Contains("after", f.Loader.Current!.Module, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_link_swapped_twice_during_compilation_pins_one_version_and_publishes_nothing_mixed()
    {
        using var f = new PolicyFolderFixture();
        f.Write("v1", orgRules: Rules("mark-one"), teamRules: Rules("mark-one"));
        f.Write("v2", orgRules: Rules("mark-two"), teamRules: Rules("mark-two"));
        f.Write("v3", orgRules: Rules("mark-three"), teamRules: Rules("mark-three"));
        f.LinkTo("v1");
        f.Compiler.OnCompile = (sources, call) =>
        {
            if (call == 1)
            {
                // The compile is of the copy of v1, whatever the link does now.
                Assert.All(sources.Files.Where(s => !string.Equals(s.Path, "_sentinel_host/decision.rego", StringComparison.Ordinal)), s => Assert.DoesNotContain("mark-two", s.Text, StringComparison.Ordinal));
                f.LinkTo("v2");
                f.LinkTo("v3");
            }
        };

        Assert.Equal(PassResult.Retry, await f.Loader.ReloadAsync(Ct));
        Assert.Null(f.Loader.Current);

        Assert.Equal(PassResult.Published, await f.Loader.ReloadAsync(Ct));
        var module = f.Loader.Current!.Module;
        Assert.Contains("mark-three", module, StringComparison.Ordinal);
        Assert.DoesNotContain("mark-one", module, StringComparison.Ordinal);
        Assert.DoesNotContain("mark-two", module, StringComparison.Ordinal);
    }

    [Fact]
    public async Task The_old_folder_removed_during_a_read_publishes_nothing_and_the_new_one_is_published_after()
    {
        using var f = new PolicyFolderFixture();
        f.Write("v1", orgRules: Rules("v1"));
        f.Write("v2", orgRules: Rules("v2"));
        f.LinkTo("v1");
        f.Loader.AfterFileRead = (pass, name) =>
        {
            if (pass == 1 && string.Equals(name, "acme.rego", StringComparison.Ordinal))
            {
                f.LinkTo("v2");
                Directory.Delete(f.Version("v1"), recursive: true);
            }
        };

        Assert.Equal(PassResult.Retry, await f.Loader.ReloadAsync(Ct));
        Assert.Null(f.Loader.Current);

        f.Loader.AfterFileRead = null;
        Assert.Equal(PassResult.Published, await f.Loader.ReloadAsync(Ct));
        Assert.Contains("v2", f.Loader.Current!.Module, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_reload_overtaken_by_a_newer_change_does_not_publish_and_the_newer_version_stays_in_force()
    {
        using var f = new PolicyFolderFixture();
        f.Write("v1", orgRules: Rules("older"));
        f.Write("v2", orgRules: Rules("newer"));
        f.LinkTo("v1");
        using var entered = new SemaphoreSlim(0);
        using var release = new ManualResetEventSlim(false);
        f.Compiler.OnCompile = (_, call) =>
        {
            if (call == 1)
            {
                entered.Release();
                release.Wait(Ct);
            }
        };

        var slow = Task.Run(() => f.Loader.ReloadAsync(Ct), Ct);
        await entered.WaitAsync(Ct);
        f.LinkTo("v2");
        var overtaking = Task.Run(() => f.Loader.ReloadAsync(Ct), Ct);
        release.Set();
        var results = await Task.WhenAll(slow, overtaking);

        Assert.Equal([PassResult.Retry, PassResult.Published], results);
        Assert.Contains("newer", f.Loader.Current!.Module, StringComparison.Ordinal);
        Assert.Equal(1, f.Compiler.MaxRunning);
        // A later pass over the same folder keeps it.
        Assert.Equal(PassResult.Unchanged, await f.Loader.ReloadAsync(Ct));
        Assert.Contains("newer", f.Loader.Current.Module, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Reloads_run_one_at_a_time()
    {
        using var f = new PolicyFolderFixture();
        f.Write("v1");
        f.LinkTo("v1");
        f.Compiler.OnCompile = (_, _) => Thread.Sleep(30);

        var results = await Task.WhenAll(Enumerable.Range(0, 6).Select(_ => Task.Run(() => f.Loader.ReloadAsync(Ct), Ct)));

        Assert.Equal(1, f.Compiler.MaxRunning);
        Assert.Equal(1, results.Count(r => r == PassResult.Published));
        Assert.Equal(5, results.Count(r => r == PassResult.Unchanged));
        Assert.Equal(CompilesPerPass, f.Compiler.Calls);
    }

    [Fact]
    public async Task A_missing_folder_is_a_failed_read_that_is_retried_and_publishes_nothing()
    {
        using var f = new PolicyFolderFixture();

        Assert.Equal(PassResult.Retry, await f.Loader.ReloadAsync(Ct));

        Assert.Null(f.Loader.Current);
        Assert.Empty(await f.AuditAsync());
    }

    [Fact]
    public void The_backoff_doubles_and_is_bounded()
    {
        var timing = PolicyFolderTiming.Default;

        Assert.Equal(TimeSpan.FromMilliseconds(250), timing.Backoff(0));
        Assert.Equal(TimeSpan.FromMilliseconds(500), timing.Backoff(1));
        Assert.Equal(TimeSpan.FromSeconds(30), timing.Backoff(20));
        Assert.Equal(TimeSpan.FromSeconds(30), timing.Backoff(1000));
    }

    [Fact]
    public async Task The_running_loader_retries_a_failed_pass_with_backoff_and_follows_a_link_swap_it_got_no_event_for()
    {
        using var f = new PolicyFolderFixture();
        f.Write("v1", orgRules: Rules("v1"));
        f.Write("v2", orgRules: Rules("v2"));
        f.LinkTo("v1");
        f.Compiler.UnavailableReason = "no compiler yet";
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(Ct);
        var run = Task.Run(() => f.Loader.RunAsync(cts.Token), Ct);
        try
        {
            await Task.Delay(250, Ct);
            Assert.Null(f.Loader.Current);

            f.Compiler.UnavailableReason = null;
            await WaitForAsync(() => f.Loader.Current is not null);
            Assert.Contains("v1", f.Loader.Current!.Module, StringComparison.Ordinal);

            f.LinkTo("v2");
            await WaitForAsync(() => f.Loader.Current!.Module.Contains("v2", StringComparison.Ordinal));
        }
        finally
        {
            await cts.CancelAsync();
            await AwaitStoppedAsync(run);
        }
    }

    [Fact]
    public async Task A_change_that_is_notified_is_settled_and_published()
    {
        using var f = new PolicyFolderFixture();
        f.Write("v1", orgRules: Rules("v1"));
        f.LinkTo("v1");
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(Ct);
        var run = Task.Run(() => f.Loader.RunAsync(cts.Token), Ct);
        try
        {
            await WaitForAsync(() => f.Loader.Current is not null);
            File.WriteAllText(Path.Combine(f.Version("v1"), "acme.rego"), Rules("edited"));
            f.Loader.Notify();
            await WaitForAsync(() => f.Loader.Current!.Module.Contains("edited", StringComparison.Ordinal));
        }
        finally
        {
            await cts.CancelAsync();
            await AwaitStoppedAsync(run);
        }
    }

    // The loop can see the cancellation before or after its next check: it ends normally or with the cancellation, nothing else.
    private static async Task AwaitStoppedAsync(Task run)
    {
        try
        {
            await run;
        }
        catch (OperationCanceledException)
        {
        }
    }

    private static async Task WaitForAsync(Func<bool> condition)
    {
        var deadline = DateTime.UtcNow.AddSeconds(15);
        while (!condition())
        {
            Assert.True(DateTime.UtcNow < deadline, "the condition did not come true in time");
            await Task.Delay(10, Ct);
        }
    }
}
