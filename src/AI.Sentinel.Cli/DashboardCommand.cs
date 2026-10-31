using System.CommandLine;
using System.CommandLine.Parsing;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using AI.Sentinel.Audit;
using AI.Sentinel.AspNetCore;
using AI.Sentinel.Sqlite;
using AI.Sentinel.Sqlite.Local;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace AI.Sentinel.Cli;

/// <summary>
/// <c>sentinel dashboard</c>: hosts the embedded AI.Sentinel dashboard over the local audit file on
/// 127.0.0.1. Read-only: it opens the file with <c>SqliteAuditStore.OpenReadOnly</c>, so it never creates the file,
/// upgrades an older schema, appends entries, or runs retention or a size cap. SQLite may still create the -wal and
/// -shm coordination files next to it. No approval store is wired, so the approve and deny endpoints write nothing.
/// </summary>
public static class DashboardCommand
{
    private const int DefaultPort = 5170;
    private const string PathPrefix = "/ai-sentinel";

    private const string DefaultUserHeader = "X-Auth-Request-User";

    public static Command Build() => Build(LocalAudit.DefaultDatabasePath);

    internal static Command Build(Func<string> defaultDatabasePath) =>
        Build(defaultDatabasePath, () => Environment.GetEnvironmentVariable("SENTINEL_APPROVAL_CONFIG"));

    internal static Command Build(Func<string> defaultDatabasePath, Func<string?> approvalConfigFromEnvironment)
    {
        var dbOpt = new Option<string>("--db")
        {
            Description = "Path to the audit SQLite file. Defaults to the file the hooks and the MCP proxy write.",
            DefaultValueFactory = _ => defaultDatabasePath(),
        };
        var portOpt = new Option<int>("--port")
        {
            Description = "Port to listen on (127.0.0.1 only). Use 0 for any free port.",
            DefaultValueFactory = _ => DefaultPort,
        };
        portOpt.Validators.Add(result =>
        {
            var port = result.GetValueOrDefault<int>();
            if (port is < 0 or > 65535)
            {
                result.AddError($"--port must be between 0 and 65535, but was {port.ToString(CultureInfo.InvariantCulture)}.");
            }
        });

        var bindOpt = CreateBindOption();
        var approvalConfigOpt = CreateApprovalConfigOption(approvalConfigFromEnvironment);
        var trustedProxyOpt = CreateTrustedProxyOption();
        var userHeaderOpt = CreateUserHeaderOption();
        var localApproverOpt = new Option<bool>("--local-approver")
        {
            Description = "Let the local operator approve and deny as the current OS user. Loopback only, no proxy.",
        };

        var cmd = new Command("dashboard", "Browse the local audit file in the AI.Sentinel dashboard.")
        {
            dbOpt,
            portOpt,
            bindOpt,
            approvalConfigOpt,
            trustedProxyOpt,
            userHeaderOpt,
            localApproverOpt,
        };

        cmd.Validators.Add(result => ValidateCombination(result, bindOpt, trustedProxyOpt, userHeaderOpt, localApproverOpt));

        cmd.SetAction(async (parseResult, ct) =>
        {
            var settings = ReadSettings(parseResult);
            var db = settings.DbPath;
            var stdout = parseResult.InvocationConfiguration.Output;
            var stderr = parseResult.InvocationConfiguration.Error;

            if (parseResult.GetResult(dbOpt)?.Implicit == true && !Path.IsPathRooted(db))
            {
                await stderr.WriteLineAsync(
                    "No per-user data folder is available, so there is no default audit file. Pass --db <path>.").ConfigureAwait(false);
                return 1;
            }

            return await RunAsync(settings, stdout, stderr, ct).ConfigureAwait(false);
        });

        return cmd;
    }

    private static Option<string> CreateBindOption()
    {
        var opt = new Option<string>("--bind")
        {
            Description = "IP address to listen on. Anything but loopback needs --trusted-proxy.",
            DefaultValueFactory = _ => IPAddress.Loopback.ToString(),
        };
        opt.Validators.Add(result =>
        {
            var value = result.GetValueOrDefault<string>();
            if (!IPAddress.TryParse(value, out _))
            {
                result.AddError($"--bind must be an IP address, but was '{value}'.");
            }
        });
        return opt;
    }

    private static Option<string?> CreateApprovalConfigOption(Func<string?> fromEnvironment) => new("--approval-config")
    {
        Description = "Path to the approval config JSON. Defaults to SENTINEL_APPROVAL_CONFIG when set.",
        DefaultValueFactory = _ =>
        {
            var env = fromEnvironment();
            return string.IsNullOrWhiteSpace(env) ? null : env;
        },
    };

    private static Option<string[]> CreateTrustedProxyOption()
    {
        var opt = new Option<string[]>("--trusted-proxy")
        {
            Description = "CIDR range or address of a reverse proxy whose user header is trusted. Repeatable.",
            AllowMultipleArgumentsPerToken = false,
        };
        opt.Validators.Add(result =>
        {
            foreach (var value in result.GetValueOrDefault<string[]>() ?? [])
            {
                if (!TryParseProxy(value, out _))
                {
                    result.AddError($"--trusted-proxy must be a CIDR range or an IP address, but was '{value}'.");
                }
            }
        });
        return opt;
    }

    private static Option<string> CreateUserHeaderOption()
    {
        var opt = new Option<string>("--user-header")
        {
            Description = "Header the trusted proxy sets to the authenticated user name.",
            DefaultValueFactory = _ => DefaultUserHeader,
        };
        opt.Validators.Add(result =>
        {
            var value = result.GetValueOrDefault<string>();
            if (!IsHeaderToken(value))
            {
                result.AddError($"--user-header must be a valid HTTP header name, but was '{value}'.");
            }
        });
        return opt;
    }

    private static void ValidateCombination(
        CommandResult result,
        Option<string> bindOpt,
        Option<string[]> trustedProxyOpt,
        Option<string> userHeaderOpt,
        Option<bool> localApproverOpt)
    {
        if (result.Errors.Any())
        {
            return;
        }
        var proxies = result.GetValue(trustedProxyOpt) ?? [];
        if (!IPAddress.TryParse(result.GetValue(bindOpt) ?? IPAddress.Loopback.ToString(), out var bind))
        {
            return;
        }
        if (!IPAddress.IsLoopback(bind) && proxies.Length == 0)
        {
            result.AddError("--bind to a non-loopback address needs at least one --trusted-proxy.");
        }
        if (result.GetResult(userHeaderOpt)?.Implicit == false && proxies.Length == 0)
        {
            result.AddError("--user-header only applies together with --trusted-proxy.");
        }
        if (result.GetValue(localApproverOpt))
        {
            if (proxies.Length > 0)
            {
                result.AddError("--local-approver cannot be combined with --trusted-proxy.");
            }
            if (!IPAddress.IsLoopback(bind))
            {
                result.AddError("--local-approver needs a loopback --bind.");
            }
        }
    }

    internal static DashboardSettings ReadSettings(ParseResult parseResult)
    {
        ArgumentNullException.ThrowIfNull(parseResult);
        var command = parseResult.CommandResult.Command;
        T Value<T>(string name) => parseResult.GetValue((Option<T>)command.Options.First(o => string.Equals(o.Name, name, StringComparison.Ordinal)))!;
        var approvalConfig = command.Options.First(o => string.Equals(o.Name, "--approval-config", StringComparison.Ordinal));

        var proxies = new List<IPNetwork>();
        foreach (var value in Value<string[]>("--trusted-proxy") ?? [])
        {
            if (TryParseProxy(value, out var network))
            {
                proxies.Add(network);
            }
        }

        return new DashboardSettings(Value<string>("--db"), Value<int>("--port"))
        {
            Bind = IPAddress.Parse(Value<string>("--bind")),
            ApprovalConfigPath = Value<string?>("--approval-config"),
            ApprovalConfigExplicit = parseResult.GetResult(approvalConfig)?.Implicit == false,
            TrustedProxies = proxies,
            UserHeader = Value<string>("--user-header"),
            LocalApprover = Value<bool>("--local-approver"),
        };
    }

    private static bool TryParseProxy(string value, out IPNetwork network)
    {
        if (value.Contains('/', StringComparison.Ordinal))
        {
            return IPNetwork.TryParse(value, out network);
        }
        if ((value.Contains('.', StringComparison.Ordinal) || value.Contains(':', StringComparison.Ordinal))
            && IPAddress.TryParse(value, out var ip))
        {
            network = new IPNetwork(ip, ip.AddressFamily == AddressFamily.InterNetworkV6 ? 128 : 32);
            return true;
        }
        network = default;
        return false;
    }

    private static bool IsHeaderToken(string? value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return false;
        }
        foreach (var c in value)
        {
            if (!(char.IsAsciiLetterOrDigit(c) || "!#$%&'*+-.^_`|~".Contains(c, StringComparison.Ordinal)))
            {
                return false;
            }
        }
        return true;
    }

    public static async Task<int> RunAsync(
        string dbPath, int port, TextWriter stdout, TextWriter stderr, CancellationToken ct) =>
        await RunAsync(new DashboardSettings(dbPath, port), stdout, stderr, ct).ConfigureAwait(false);

    internal static async Task<int> RunAsync(
        DashboardSettings settings, TextWriter stdout, TextWriter stderr, CancellationToken ct)
    {
        var dashboard = await StartAsync(settings, stdout, stderr, ct).ConfigureAwait(false);
        if (dashboard is null)
        {
            return 1;
        }

        await using (dashboard.ConfigureAwait(false))
        {
            await dashboard.WaitForShutdownAsync(ct).ConfigureAwait(false);
        }
        return 0;
    }

    /// <summary>Starts the dashboard over an existing file. Returns <c>null</c> after writing the reason to <paramref name="stderr"/>.</summary>
    public static async Task<RunningDashboard?> StartAsync(
        string dbPath, int port, TextWriter stdout, TextWriter stderr, CancellationToken ct) =>
        await StartAsync(new DashboardSettings(dbPath, port), stdout, stderr, ct).ConfigureAwait(false);

    internal static async Task<RunningDashboard?> StartAsync(
        DashboardSettings settings, TextWriter stdout, TextWriter stderr, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(settings);
        ArgumentNullException.ThrowIfNull(stdout);
        ArgumentNullException.ThrowIfNull(stderr);

        var dbPath = settings.DbPath;
        var port = settings.Port;
        if (!File.Exists(dbPath))
        {
            await stderr.WriteLineAsync($"Audit file not found: {dbPath}").ConfigureAwait(false);
            return null;
        }

        SqliteAuditStore? store = null;
        WebApplication? app = null;
        var started = false;
        try
        {
            store = SqliteAuditStore.OpenReadOnly(dbPath);

            var verification = await AuditHashChain.VerifyAsync(
                store.QueryAsync(new AuditQuery { PageSize = int.MaxValue }, ct), ct).ConfigureAwait(false);

            app = BuildApp(store, settings);

            await app.StartAsync(ct).ConfigureAwait(false);

            var bound = new Uri(app.Urls.First());
            var url = new Uri($"http://{HostLiteral(settings.Bind)}:{bound.Port.ToString(CultureInfo.InvariantCulture)}{PathPrefix}/");

            await WriteStartupAsync(stdout, verification, url).ConfigureAwait(false);

            started = true;
            return new RunningDashboard(app, store, url);
        }
        catch (IOException ex)
        {
            await stderr.WriteLineAsync(
                $"Could not listen on {HostLiteral(settings.Bind)}:{port.ToString(CultureInfo.InvariantCulture)}: {ex.Message}").ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is Microsoft.Data.Sqlite.SqliteException or InvalidOperationException)
        {
            await stderr.WriteLineAsync($"Could not open the audit file {dbPath}: {ex.Message}").ConfigureAwait(false);
        }
        finally
        {
            if (!started)
            {
                if (app is not null)
                {
                    await app.DisposeAsync().ConfigureAwait(false);
                }
                if (store is not null)
                {
                    await store.DisposeAsync().ConfigureAwait(false);
                }
            }
        }

        return null;
    }

    private static async Task WriteStartupAsync(TextWriter stdout, AuditChainVerification verification, Uri url)
    {
        await stdout.WriteLineAsync(verification.IsIntact
            ? $"Audit chain intact: {verification.EntriesChecked} entries"
            : $"Audit chain broken at entry {verification.FirstBrokenEntryId}").ConfigureAwait(false);
        await stdout.WriteLineAsync($"Dashboard: {url}").ConfigureAwait(false);
    }

    private static string HostLiteral(IPAddress address) =>
        address.AddressFamily == AddressFamily.InterNetworkV6 ? $"[{address.ToString().Split('%')[0]}]" : address.ToString();

    private static WebApplication BuildApp(SqliteAuditStore store, DashboardSettings settings)
    {
        var builder = WebApplication.CreateSlimBuilder();
        builder.Logging.ClearProviders();
        builder.WebHost.UseUrls(string.Create(CultureInfo.InvariantCulture, $"http://{HostLiteral(settings.Bind)}:{settings.Port}"));
        builder.Services.AddRouting();
        builder.Services.AddSingleton<IAuditStore>(store);

        var app = builder.Build();
        app.MapAISentinel(PathPrefix);
        app.MapGet("/", () => Results.Redirect(PathPrefix + "/"));
        return app;
    }
}
