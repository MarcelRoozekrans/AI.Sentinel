using System.Diagnostics;
using AI.Sentinel.ClaudeCode.Policy.Rego;
using AI.Sentinel.ClaudeCode.Resident;
using AI.Sentinel.Tests.ClaudeCode.Policy;
using AI.Sentinel.Tests.Helpers;
using Xunit;

namespace AI.Sentinel.Tests.ClaudeCode.Resident;

/// <summary>The resident process (#658): one per user, started by a hook that finds none, gone after 30 idle minutes, no OS service.</summary>
[Collection("NonParallel")]
public class ResidentProcessLifecycleTests : IDisposable
{
    private readonly string _dir = ResidentTestSupport.NewDir();

    public void Dispose()
    {
        ResidentTestSupport.Delete(_dir);
        GC.SuppressFinalize(this);
    }

    private static Dictionary<string, string?> Env(params (string Key, string Value)[] pairs)
    {
        var env = new Dictionary<string, string?>(StringComparer.Ordinal);
        foreach (var (key, value) in pairs)
        {
            env[key] = value;
        }

        return env;
    }

    [Fact]
    public void Without_the_setting_there_is_no_resident_process()
    {
        Assert.Null(ResidentSettings.FromEnvironment(Env()));
        Assert.Null(ResidentSettings.FromEnvironment(Env(("SENTINEL_HOOK_RESIDENT", "off"))));
        Assert.Null(ResidentSettings.FromEnvironment(Env(("SENTINEL_HOOK_POLICY_DIR", "/some/policy"))));
    }

    [Fact]
    public void The_opt_in_turns_it_on_with_a_30_minute_idle_timeout_and_a_short_budget()
    {
        var settings = ResidentSettings.FromEnvironment(Env(("SENTINEL_HOOK_RESIDENT", "on"), ("SENTINEL_HOOK_RESIDENT_DIR", _dir)));

        Assert.NotNull(settings);
        Assert.Equal(_dir, settings.StateDirectory);
        Assert.Equal(TimeSpan.FromMinutes(30), settings.IdleTimeout);
        Assert.Equal(TimeSpan.FromMilliseconds(15), settings.Budget);
    }

    [Fact]
    public void The_budget_can_be_set_in_milliseconds_and_a_bad_value_keeps_the_default()
    {
        var set = ResidentSettings.FromEnvironment(Env(("SENTINEL_HOOK_RESIDENT", "on"), ("SENTINEL_HOOK_RESIDENT_BUDGET_MS", "30")));
        var bad = ResidentSettings.FromEnvironment(Env(("SENTINEL_HOOK_RESIDENT", "on"), ("SENTINEL_HOOK_RESIDENT_BUDGET_MS", "soon")));

        Assert.Equal(TimeSpan.FromMilliseconds(30), set!.Budget);
        Assert.Equal(TimeSpan.FromMilliseconds(15), bad!.Budget);
    }

    [Fact]
    public async Task A_second_process_for_the_same_user_does_not_start_while_the_first_runs()
    {
        await using var first = new HostedResident(_dir);
        await first.WaitUntilListeningAsync();

        var second = await ResidentHost.RunAsync(first.Settings, compilers: null, TestContext.Current.CancellationToken);

        Assert.Equal(ResidentExit.AlreadyRunning, second);
        Assert.False(first.Run.IsCompleted);
        Assert.True(await new ResidentClient(first.Settings).PingAsync());
    }

    [Fact]
    public async Task The_process_exits_after_the_idle_timeout_and_leaves_no_socket_behind()
    {
        await using var host = new HostedResident(_dir, idle: TimeSpan.FromMilliseconds(300));
        await host.WaitUntilListeningAsync();

        var exit = await host.Run.WaitAsync(TimeSpan.FromSeconds(30), TestContext.Current.CancellationToken);

        Assert.Equal(ResidentExit.Idle, exit);
        Assert.False(File.Exists(ResidentPaths.Socket(host.Settings)));
    }

    [Fact]
    public async Task A_request_keeps_the_process_alive_past_its_idle_timeout()
    {
        await using var host = new HostedResident(_dir, idle: TimeSpan.FromMilliseconds(600));
        await host.WaitUntilListeningAsync();
        var client = new ResidentClient(host.Settings);

        for (var i = 0; i < 4; i++)
        {
            await Task.Delay(250, TestContext.Current.CancellationToken);
            Assert.True(await client.PingAsync());
        }

        Assert.False(host.Run.IsCompleted);
    }

    [Fact]
    public async Task A_shutdown_request_ends_the_process()
    {
        await using var host = new HostedResident(_dir);
        await host.WaitUntilListeningAsync();

        Assert.True(await new ResidentClient(host.Settings).ShutdownAsync());

        Assert.Equal(ResidentExit.Shutdown, await host.Run.WaitAsync(TimeSpan.FromSeconds(30), TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task The_channel_and_the_state_folder_are_open_to_the_current_user_only()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        await using var host = new HostedResident(_dir);
        await host.WaitUntilListeningAsync();

        var dir = ResidentPaths.Directory(host.Settings);
        Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute, File.GetUnixFileMode(dir));
        Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(ResidentPaths.Socket(host.Settings)));
    }

    [Fact]
    public async Task A_hook_that_finds_no_process_starts_one_and_one_that_finds_it_does_not()
    {
        var starts = new List<ResidentLaunch>();
        var launch = new ResidentLaunch("sentinel-hook", [ResidentCommand.Verb]);
        var settings = new ResidentSettings(_dir, ResidentSettings.DefaultIdleTimeout, TimeSpan.FromMilliseconds(15));

        var none = ResidentLauncher.EnsureStarted(settings, launch, l => { starts.Add(l); return true; });
        await using var host = new HostedResident(_dir);
        await host.WaitUntilListeningAsync();
        var running = ResidentLauncher.EnsureStarted(settings, launch, l => { starts.Add(l); return true; });

        Assert.Equal(ResidentStart.Started, none);
        Assert.Equal(ResidentStart.AlreadyRunning, running);
        Assert.Equal([launch], starts);
    }

    [Fact]
    public void A_start_that_fails_is_reported_and_the_hook_goes_on_in_process()
    {
        var settings = new ResidentSettings(_dir, ResidentSettings.DefaultIdleTimeout, TimeSpan.FromMilliseconds(15));

        var result = ResidentLauncher.EnsureStarted(settings, new ResidentLaunch("sentinel-hook", [ResidentCommand.Verb]), _ => false);

        Assert.Equal(ResidentStart.Failed, result);
    }

    [Fact]
    public void The_launch_is_the_hook_itself_with_the_resident_verb()
    {
        var launch = ResidentLaunch.ForThisHook();

        Assert.Equal(ResidentCommand.Verb, launch.Arguments[^1]);
        Assert.Equal("--resident", ResidentCommand.Verb);
        Assert.True(ResidentCommand.Matches(["--resident"]));
        Assert.False(ResidentCommand.Matches(["pre-tool-use"]));
    }

    /// <summary>The real thing: a hook process that finds no resident process starts one, detached with its stdio not inherited, so the
    /// hook exits at once and the process stays; the next hook is answered by it. Whatever happens, the test stops the process.</summary>
    [Fact]
    public async Task A_hook_process_starts_the_resident_process_detached_and_the_next_hook_is_answered_by_it()
    {
        var folder = RegoPolicyTestSupport.StandardFolder();
        var work = Path.Combine(Path.GetTempPath(), "sr-e2e-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(work);
        var audit = Path.Combine(work, "audit.ndjson");
        var cache = Path.Combine(work, "cache");
        var settings = new ResidentSettings(_dir, ResidentSettings.DefaultIdleTimeout, TimeSpan.FromSeconds(10));
        try
        {
            var environment = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                [ResidentSettings.EnableVariable] = "on",
                [ResidentSettings.DirectoryVariable] = _dir,
                [HookAuditTestSupport.NdjsonVar] = audit,
            };
            const string Json = """{"session_id":"cc-658","tool_name":"Bash","tool_input":{"command":"rm -rf build"}}""";

            var first = await RegoPolicyTestSupport.RunHookProcessAsync(folder, cache, Json, environment);
            await WaitForAsync(async () => await new ResidentClient(settings).PingAsync());
            // The module is loaded in the process by now or soon: ask until it answers within the real budget.
            var warm = new ResidentClient(settings);
            var policy = PolicySources.Load(folder);
            await WaitForAsync(() => Task.FromResult(warm.Evaluate(folder, policy.Version, cache, "{}") is not null));
            var second = await RegoPolicyTestSupport.RunHookProcessAsync(folder, cache, Json, environment);

            Assert.Equal(2, first.Exit);
            Assert.Contains("recursive delete", first.Stderr, StringComparison.Ordinal);
            Assert.Equal(2, second.Exit);
            Assert.Contains("recursive delete", second.Stderr, StringComparison.Ordinal);
            var lines = await File.ReadAllTextAsync(audit, TestContext.Current.CancellationToken);
            Assert.Contains("decided=in-process", lines, StringComparison.Ordinal);
            Assert.Contains("decided=resident", lines, StringComparison.Ordinal);
            AssertLeftTheSessionOfThisProcess(ResidentPaths.Pid(settings));
        }
        finally
        {
            await StopResidentAsync(settings);
            RegoPolicyTestSupport.Delete(folder);
            RegoPolicyTestSupport.Delete(work);
        }
    }

    /// <summary>The resident process called setsid, so it is the leader of a session of its own: a CLI that kills the process group of
    /// the hook does not reach it. On Linux this reads the session and the group from /proc, on macOS only the session id differs.</summary>
    private static void AssertLeftTheSessionOfThisProcess(string pidFile)
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        var pid = int.Parse(File.ReadAllText(pidFile), System.Globalization.CultureInfo.InvariantCulture);
        Assert.NotEqual(ProcessGroup.SessionOf(0), ProcessGroup.SessionOf(pid));
        Assert.Equal(pid, ProcessGroup.SessionOf(pid));
        if (OperatingSystem.IsLinux())
        {
            // pid (comm) state ppid pgrp session: the name may hold spaces, so count from the last bracket.
            var stat = File.ReadAllText($"/proc/{pid}/stat");
            var fields = stat[(stat.LastIndexOf(')') + 2)..].Split(' ');
            Assert.Equal(pid, int.Parse(fields[2], System.Globalization.CultureInfo.InvariantCulture));
            Assert.Equal(pid, int.Parse(fields[3], System.Globalization.CultureInfo.InvariantCulture));
        }
    }

    [Fact]
    public void Detaching_ignores_a_process_that_is_already_a_group_leader_and_does_nothing_on_windows()
    {
        const int Eperm = 1;

        Assert.Equal(ProcessGroupResult.Detached, ProcessGroup.Detach(() => (123, 0)));
        Assert.Equal(ProcessGroupResult.AlreadyLeader, ProcessGroup.Detach(() => (-1, Eperm)));
        Assert.Equal(ProcessGroupResult.Failed, ProcessGroup.Detach(() => (-1, 12)));
        Assert.Equal(ProcessGroupResult.NotApplicable, ProcessGroup.Detach(() => throw new InvalidOperationException("not called"), isWindows: true));
    }

    private static async Task WaitForAsync(Func<Task<bool>> condition)
    {
        var deadline = DateTime.UtcNow.AddSeconds(60);
        while (!await condition())
        {
            Assert.True(DateTime.UtcNow < deadline, "the resident process did not come up");
            await Task.Delay(100, TestContext.Current.CancellationToken);
        }
    }

    /// <summary>Asks the process to stop and, if it does not, kills it by the pid it wrote, so no test leaves a process behind.</summary>
    private static async Task StopResidentAsync(ResidentSettings settings)
    {
        var pidFile = ResidentPaths.Pid(settings);
        int? pid = File.Exists(pidFile) && int.TryParse(File.ReadAllText(pidFile), System.Globalization.NumberStyles.Integer, System.Globalization.CultureInfo.InvariantCulture, out var parsed) ? parsed : null;
        await new ResidentClient(settings).ShutdownAsync();
        if (pid is null)
        {
            return;
        }

        try
        {
            using var process = Process.GetProcessById(pid.Value);
            if (!process.WaitForExit(TimeSpan.FromSeconds(10)))
            {
                process.Kill(entireProcessTree: true);
                process.WaitForExit();
            }
        }
        catch (ArgumentException)
        {
            // Already gone.
        }
    }
}
