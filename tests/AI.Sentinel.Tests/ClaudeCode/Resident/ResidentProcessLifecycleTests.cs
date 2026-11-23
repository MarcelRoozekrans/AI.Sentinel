using AI.Sentinel.ClaudeCode.Resident;
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
}
