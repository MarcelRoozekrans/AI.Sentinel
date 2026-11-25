using AI.Sentinel.AspNetCore.PolicyFolder;
using AI.Sentinel.Audit;
using AI.Sentinel.Tests.ClaudeCode.Policy;
using Xunit;
using static AI.Sentinel.Tests.AspNetCore.PolicyFolder.PolicyFolderFixture;

namespace AI.Sentinel.Tests.AspNetCore.PolicyFolder;

public sealed class PolicyValidationTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static string Rules(string rule) => $"package sentinel\n\nimport rego.v1\n\n{rule}\n";

    [Theory]
    [InlineData("http.send")]
    [InlineData("net.lookup_ip_addr")]
    [InlineData("opa.runtime")]
    public async Task A_bundle_that_uses_a_builtin_reaching_outside_is_refused_by_the_real_compiler(string builtin)
    {
        var call = builtin switch
        {
            "http.send" => "http.send({\"method\": \"get\", \"url\": \"https://example.com\"})",
            "net.lookup_ip_addr" => "net.lookup_ip_addr(\"example.com\")",
            _ => "opa.runtime()",
        };
        using var f = new PolicyFolderFixture(real: new ChildProcessCompiler());
        f.Write("v1", teamRules: Rules($"deny contains \"x\" if {{\n\tr := {call}\n\tr != null\n}}"));
        f.LinkTo("v1");

        var result = await f.Loader.ReloadAsync(Ct);

        Assert.Equal(PassResult.Rejected, result);
        Assert.Null(f.Loader.Current);
        var entry = Assert.Single(await f.AuditAsync());
        Assert.Equal("rejected_publish", entry.Action);
        Assert.EndsWith(" outside_builtin", entry.Target, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_valid_configuration_compiles_with_the_real_compiler_as_the_one_module_the_plugin_compiles()
    {
        using var f = new PolicyFolderFixture(real: new ChildProcessCompiler());
        f.Write("v1");
        f.LinkTo("v1");

        Assert.Equal(PassResult.Published, await f.Loader.ReloadAsync(Ct));

        Assert.Single(await f.AuditAsync());
    }

    [Fact]
    public async Task A_bundle_that_uses_a_builtin_reaching_outside_is_refused_and_the_last_good_configuration_stays_in_force()
    {
        using var f = new PolicyFolderFixture();
        f.Write("good");
        f.Write("bad", teamRules: Rules("deny contains \"x\" if http.send({\"url\": \"https://example.com\"})"));
        f.LinkTo("good");
        await f.Loader.ReloadAsync(Ct);
        var good = f.Loader.Current!;

        f.LinkTo("bad");
        var result = await f.Loader.ReloadAsync(Ct);

        Assert.Equal(PassResult.Rejected, result);
        Assert.Same(good, f.Loader.Current);
        var entries = await f.AuditAsync();
        Assert.Equal(["publish", "rejected_publish"], entries.Select(e => e.Action), StringComparer.Ordinal);
        Assert.All(entries, e => Assert.Equal("git", e.Channel));
        Assert.EndsWith(" outside_builtin", entries[1].Target, StringComparison.Ordinal);
        Assert.True((await AuditHashChain.VerifyAsync(ToAsync(entries.Select(e => e.ToChainEntry())), Ct)).IsIntact);
    }

    [Fact]
    public async Task A_rejected_configuration_is_audited_once_however_often_it_is_looked_at()
    {
        using var f = new PolicyFolderFixture();
        f.Write("bad", teamRules: Rules("deny contains \"x\" if opa.runtime()"));
        f.LinkTo("bad");

        for (var i = 0; i < 4; i++)
        {
            Assert.Equal(PassResult.Rejected, await f.Loader.ReloadAsync(Ct));
        }

        Assert.Single(await f.AuditAsync());
        Assert.Equal(1, f.Compiler.Calls);
    }

    [Fact]
    public async Task A_publish_is_written_to_the_audit_log_on_the_git_channel_without_any_file_content()
    {
        using var f = new PolicyFolderFixture();
        f.Write("v1");
        f.LinkTo("v1");

        await f.Loader.ReloadAsync(Ct);

        var entry = Assert.Single(await f.AuditAsync());
        Assert.Equal(("publish", "git", "policy-folder"), (entry.Action, entry.Channel, entry.Actor));
        Assert.StartsWith("configuration 1 module ", entry.Target, StringComparison.Ordinal);
        Assert.DoesNotContain("deny", entry.Target, StringComparison.Ordinal);
        Assert.Equal(Organisation, entry.Organisation);
    }

    [Fact]
    public async Task A_rejection_is_followed_by_the_next_good_configuration()
    {
        using var f = new PolicyFolderFixture();
        f.Write("bad", teamRules: Rules("deny contains \"x\" if opa.runtime()"));
        f.Write("fixed");
        f.LinkTo("bad");
        await f.Loader.ReloadAsync(Ct);

        f.LinkTo("fixed");

        Assert.Equal(PassResult.Published, await f.Loader.ReloadAsync(Ct));
        Assert.Equal(["rejected_publish", "publish"], (await f.AuditAsync()).Select(e => e.Action), StringComparer.Ordinal);
    }

    [Fact]
    public async Task A_bundle_below_the_organisation_that_defines_an_allow_rule_is_refused()
    {
        using var f = new PolicyFolderFixture();
        f.Write("v1", teamRules: Rules("allow contains \"all fine\" if input.kind == \"read\""));
        f.LinkTo("v1");

        Assert.Equal(PassResult.Rejected, await f.Loader.ReloadAsync(Ct));

        Assert.Null(f.Loader.Current);
        Assert.EndsWith(" allow_rule_below_organisation", Assert.Single(await f.AuditAsync()).Target, StringComparison.Ordinal);
    }

    [Fact]
    public async Task The_organisation_bundle_may_define_an_allow_rule()
    {
        using var f = new PolicyFolderFixture();
        f.Write("v1", orgRules: Rules("allow contains \"reading is fine\" if input.kind == \"read\""));
        f.LinkTo("v1");

        Assert.Equal(PassResult.Published, await f.Loader.ReloadAsync(Ct));
    }

    [Theory]
    [InlineData("allow contains \"x\" if true", true)]
    [InlineData("allow if true", true)]
    [InlineData("default allow := false", true)]
    [InlineData("allow := true", true)]
    [InlineData("  allow = true", true)]
    [InlineData("allow[x] { x := 1 }", true)]
    [InlineData("allow contains \"x\" if {\n\ttrue\n}", true)]
    [InlineData("# allow if true", false)]
    [InlineData("deny contains \"allow if true\" if input.x", false)]
    [InlineData("deny contains \"x\" if input.y == \"allow\"", false)]
    [InlineData("allowed := true", false)]
    [InlineData("ask contains \"x\" if input.kind == \"fetch\" # allow if true", false)]
    [InlineData("noop if { true } allow contains \"team grant\"", true)]
    [InlineData("noop := 1; allow if true", true)]
    [InlineData("deny contains \"x\" if data.sentinel.allow", false)]
    [InlineData("x := `\nallow if true\n`", false)]
    public void An_allow_rule_is_found_by_its_head_and_not_by_a_comment_or_a_string(string rego, bool expected) =>
        Assert.Equal(expected, ConfigurationCompiler.DefinesAllow(rego));

    [Fact]
    public async Task Two_teams_that_each_define_a_default_for_one_rule_are_both_accepted()
    {
        using var f = new PolicyFolderFixture();
        var team = "package sentinel\n\nimport rego.v1\n\ndefault enabled := false\n\nask contains \"x\" if input.kind == \"fetch\"\n";
        f.Write("v1", teamRules: team);
        File.WriteAllText(Path.Combine(f.Version("v1"), "team-b.rego"), team);
        File.WriteAllText(Path.Combine(f.Version("v1"), "nodes.json"), PolicyFolderFixture.Nodes.Replace(
            "{\"id\": \"team-a\"", "{\"id\": \"team-b\", \"kind\": \"team\"},\n    {\"id\": \"team-a\"", StringComparison.Ordinal));
        f.LinkTo("v1");

        Assert.Equal(PassResult.Published, await f.Loader.ReloadAsync(Ct));
    }

    [Fact]
    public async Task A_comment_before_the_package_declaration_is_accepted_and_kept()
    {
        using var f = new PolicyFolderFixture();
        f.Write("v1", orgRules: "# the policy of acme\n" + OrgRules);
        f.LinkTo("v1");

        Assert.Equal(PassResult.Published, await f.Loader.ReloadAsync(Ct));
        Assert.Contains("# the policy of acme", f.Loader.Current!.Module, StringComparison.Ordinal);
    }

    [Fact]
    public async Task An_import_line_inside_a_raw_string_stays_in_the_string()
    {
        using var f = new PolicyFolderFixture();
        f.Write("v1", orgRules: OrgRules + "\nsecret := `\nimport data.foo\n`\n");
        f.LinkTo("v1");

        Assert.Equal(PassResult.Published, await f.Loader.ReloadAsync(Ct));
        Assert.Contains("`\nimport data.foo\n`", f.Loader.Current!.Module, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("\"nodes\": [null]")]
    [InlineData("\"nodes\": [{\"id\": \"acme\", \"kind\": \"organisation\"}], \"roles\": [null]")]
    [InlineData("\"nodes\": [{\"id\": \"acme\", \"kind\": \"organisation\", \"settings\": {\"profile_lifetime_hours\": 2147483647}}]")]
    public void A_node_configuration_that_cannot_be_read_is_refused_and_does_not_throw(string body) =>
        Assert.Throws<InvalidDataException>(() => NodeConfiguration.Parse(System.Text.Encoding.UTF8.GetBytes("{\"organisation\": \"acme\", " + body + "}")));

    [Fact]
    public void A_path_with_a_link_above_the_folder_is_read_through_its_real_path()
    {
        using var f = new PolicyFolderFixture();
        f.Write("v1");
        var link = Path.Combine(Path.GetDirectoryName(f.Version("v1"))!, "current-" + Guid.NewGuid().ToString("N"));
        Directory.CreateSymbolicLink(link, Path.GetDirectoryName(f.Version("v1"))!);
        try
        {
            Assert.Equal(ConfigurationFiles.Resolve(f.Version("v1")), ConfigurationFiles.Resolve(Path.Combine(link, Path.GetFileName(f.Version("v1")))));
        }
        finally
        {
            Directory.Delete(link);
        }
    }

    [Fact]
    public async Task A_bundle_that_is_no_node_is_refused()
    {
        using var f = new PolicyFolderFixture();
        var dir = f.Write("v1");
        Directory.CreateDirectory(Path.Combine(dir, "team-b"));
        File.WriteAllText(Path.Combine(dir, "team-b", "rules.rego"), Rules("deny contains \"x\" if input.kind == \"fetch\""));
        f.LinkTo("v1");

        Assert.Equal(PassResult.Rejected, await f.Loader.ReloadAsync(Ct));

        Assert.EndsWith(" unknown_bundle", Assert.Single(await f.AuditAsync()).Target, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_bundle_in_another_package_is_refused()
    {
        using var f = new PolicyFolderFixture();
        f.Write("v1", teamRules: "package other\n\nimport rego.v1\n\ndeny contains \"x\" if input.y\n");
        f.LinkTo("v1");

        Assert.Equal(PassResult.Rejected, await f.Loader.ReloadAsync(Ct));

        Assert.EndsWith(" wrong_package", Assert.Single(await f.AuditAsync()).Target, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("{ not json")]
    [InlineData("{\"organisation\": \"acme\", \"nodes\": [{\"id\": \"acme\", \"kind\": \"organisation\", \"settings\": {\"fail_mode\": \"open\"}}]}")]
    [InlineData("{\"organisation\": \"acme\", \"nodes\": []}")]
    [InlineData("{\"organisation\": \"acme\", \"nodes\": [{\"id\": \"acme\", \"kind\": \"organisation\"}], \"repositories\": {\"github.com/a/b\": \"nobody\"}}")]
    [InlineData("{\"organisation\": \"acme\", \"nodes\": [{\"id\": \"acme\", \"kind\": \"organisation\", \"settings\": {\"fail_mode\": \"maybe\"}}]}")]
    [InlineData("{\"organisation\": \"acme\", \"nodes\": [{\"id\": \"acme\", \"kind\": \"organisation\"}, {\"id\": \"acme\", \"kind\": \"team\"}]}")]
    [InlineData("{\"organisation\": \"acme\", \"nodes\": [{\"id\": \"acme\", \"kind\": \"organisation\"}], \"roles\": [{\"group\": \"g\", \"role\": \"team_lead\", \"node\": \"acme\"}]}")]
    [InlineData("{\"organisation\": \"acme\", \"surprise\": 1, \"nodes\": [{\"id\": \"acme\", \"kind\": \"organisation\"}]}")]
    public async Task A_node_configuration_that_does_not_hold_together_is_refused(string nodes)
    {
        using var f = new PolicyFolderFixture();
        f.Write("v1", nodes: nodes);
        f.LinkTo("v1");

        Assert.Equal(PassResult.Rejected, await f.Loader.ReloadAsync(Ct));

        Assert.Null(f.Loader.Current);
        Assert.EndsWith(" invalid_node_configuration", Assert.Single(await f.AuditAsync("fallback-org")).Target, StringComparison.Ordinal);
    }

    [Fact]
    public async Task The_fail_mode_ask_is_accepted_and_closed_is_the_default()
    {
        using var f = new PolicyFolderFixture();
        f.Write("v1", nodes: Nodes.Replace("\"fail_mode\": \"closed\"", "\"fail_mode\": \"ask\"", StringComparison.Ordinal));
        f.LinkTo("v1");

        Assert.Equal(PassResult.Published, await f.Loader.ReloadAsync(Ct));

        Assert.Equal("ask", f.Loader.Current!.Nodes.NodeFor("github.com/acme/other")!.FailMode);
        // team-a leaves it out and inherits the organisation's; an organisation that leaves it out is closed.
        Assert.Equal("ask", f.Loader.Current.Nodes.NodeFor(Repository)!.FailMode);
    }

    [Fact]
    public async Task A_node_that_leaves_the_fail_mode_out_is_closed()
    {
        using var f = new PolicyFolderFixture();
        f.Write("v1", nodes: Nodes.Replace(", \"settings\": {\"fail_mode\": \"closed\"}", "", StringComparison.Ordinal));
        f.LinkTo("v1");

        await f.Loader.ReloadAsync(Ct);

        Assert.Equal("closed", f.Loader.Current!.Nodes.NodeFor(Repository)!.FailMode);
    }

    [Fact]
    public async Task A_node_bundle_that_does_not_compile_on_its_own_is_refused()
    {
        using var f = new PolicyFolderFixture();
        // The profile of team-a is compiled alone: a bundle that leans on a rule of another bundle has to say so by failing here.
        f.Compiler.OnCompile = (sources, _) =>
        {
            if (sources.Files.Any(s => s.Text.Contains("team asks", StringComparison.Ordinal))
                && !sources.Files.Any(s => s.Text.Contains("recursive delete", StringComparison.Ordinal)))
            {
                throw new AI.Sentinel.ClaudeCode.Policy.Rego.RegoCompileException("rego_unsafe_var_error: var org_rule is unsafe");
            }
        };
        f.Write("v1");
        f.LinkTo("v1");

        Assert.Equal(PassResult.Rejected, await f.Loader.ReloadAsync(Ct));

        Assert.EndsWith(" does_not_compile", Assert.Single(await f.AuditAsync()).Target, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_folder_without_a_rego_file_is_refused()
    {
        using var f = new PolicyFolderFixture();
        var dir = f.Write("v1");
        File.Delete(Path.Combine(dir, "acme.rego"));
        File.Delete(Path.Combine(dir, "team-a", "rules.rego"));
        f.LinkTo("v1");

        Assert.Equal(PassResult.Rejected, await f.Loader.ReloadAsync(Ct));
    }

    [Fact]
    public async Task A_link_inside_the_folder_is_not_followed_and_the_folder_is_refused()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        using var f = new PolicyFolderFixture();
        var dir = f.Write("v1");
        File.CreateSymbolicLink(Path.Combine(dir, "team-a", "leak.rego"), "/etc/hostname");
        f.LinkTo("v1");

        Assert.Equal(PassResult.Rejected, await f.Loader.ReloadAsync(Ct));

        Assert.Null(f.Loader.Current);
        Assert.Equal(0, f.Compiler.Calls);
    }

    [Fact]
    public async Task A_compiler_that_cannot_run_is_not_a_rejection_and_publishes_nothing()
    {
        using var f = new PolicyFolderFixture();
        f.Write("v1");
        f.LinkTo("v1");
        f.Compiler.UnavailableReason = "no opa binary on the PATH";

        Assert.Equal(PassResult.Retry, await f.Loader.ReloadAsync(Ct));

        Assert.Null(f.Loader.Current);
        Assert.Empty(await f.AuditAsync());
    }

    [Fact]
    public async Task A_version_the_filler_states_is_the_configuration_version_and_otherwise_the_publishes_are_counted()
    {
        using var f = new PolicyFolderFixture();
        f.Write("v1", nodes: Nodes.Replace("\"organisation\": \"acme\",", "\"organisation\": \"acme\", \"version\": 42,", StringComparison.Ordinal));
        f.Write("v2");
        f.Write("v3", teamRules: Rules("deny contains \"y\" if input.kind == \"fetch\""));
        f.LinkTo("v1");
        await f.Loader.ReloadAsync(Ct);
        Assert.Equal(42, f.Loader.Current!.Version);

        f.LinkTo("v2");
        await f.Loader.ReloadAsync(Ct);
        Assert.Equal(1, f.Loader.Current!.Version);
        f.LinkTo("v3");
        await f.Loader.ReloadAsync(Ct);
        Assert.Equal(2, f.Loader.Current!.Version);
    }

    private static async IAsyncEnumerable<AuditEntry> ToAsync(IEnumerable<AuditEntry> entries)
    {
        foreach (var entry in entries)
        {
            yield return entry;
        }

        await Task.CompletedTask;
    }
}
