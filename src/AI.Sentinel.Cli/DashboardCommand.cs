using System.CommandLine;
using System.CommandLine.Parsing;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using AI.Sentinel.Approvals.Sqlite;
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
/// <c>sentinel dashboard</c>: hosts the embedded AI.Sentinel dashboard over the local audit file. It listens on
/// 127.0.0.1 unless <c>--bind</c> says otherwise, and a non-loopback bind needs <c>--trusted-proxy</c>. Without an
/// approval config it is read-only: it opens the file with <c>SqliteAuditStore.OpenReadOnly</c>, so it never creates
/// the file, upgrades an older schema, appends entries, or runs retention or a size cap. SQLite may still create the
/// -wal and -shm coordination files next to it. With a sqlite approval config it also lists, approves and denies
/// pending requests, opening the audit file writable to append each decision to the chain; then
/// <c>--local-approver</c> or <c>--trusted-proxy</c> says who may decide. With an Entra PIM config it only points to
/// the portal.
/// </summary>
public static class DashboardCommand
{
    internal sealed record OptionSet(
        Option<string> Db,
        Option<int> Port,
        Option<string> Bind,
        Option<string?> ApprovalConfig,
        Option<string[]> TrustedProxy,
        Option<string> UserHeader,
        Option<bool> LocalApprover,
        Option<string[]> PublicHost)
    {
        /// <summary>Reads the validated settings out of <paramref name="parseResult"/>.</summary>
        internal DashboardSettings Read(ParseResult parseResult)
        {
            ArgumentNullException.ThrowIfNull(parseResult);
            return new DashboardSettings(parseResult.GetRequiredValue(Db), parseResult.GetValue(Port))
            {
                Bind = IPAddress.Parse(parseResult.GetRequiredValue(Bind)),
                ApprovalConfigPath = parseResult.GetValue(ApprovalConfig),
                ApprovalConfigExplicit = parseResult.GetResult(ApprovalConfig)?.Implicit == false,
                TrustedProxies = ParseProxies(parseResult.GetValue(TrustedProxy) ?? []),
                UserHeader = parseResult.GetRequiredValue(UserHeader),
                LocalApprover = parseResult.GetValue(LocalApprover),
                PublicHosts = (parseResult.GetValue(PublicHost) ?? []).Select(NormalisePublicHost).ToArray(),
            };
        }
    }

    private const int DefaultPort = 5170;
    private const string PathPrefix = "/ai-sentinel";

    public static Command Build() => Build(LocalAudit.DefaultDatabasePath);

    internal static Command Build(Func<string> defaultDatabasePath) =>
        Build(defaultDatabasePath, () => Environment.GetEnvironmentVariable("SENTINEL_APPROVAL_CONFIG"));

    internal static Command Build(Func<string> defaultDatabasePath, Func<string?> approvalConfigFromEnvironment) =>
        Build(defaultDatabasePath, approvalConfigFromEnvironment, out _);

    /// <summary>Builds the command and hands back the reader that turns a parse of it into settings.</summary>
    internal static Command Build(
        Func<string> defaultDatabasePath, Func<string?> approvalConfigFromEnvironment, out Func<ParseResult, DashboardSettings> readSettings)
    {
        var dbOpt = new Option<string>("--db")
        {
            Description = "Path to the audit SQLite file. Defaults to the file the hooks and the MCP proxy write.",
            DefaultValueFactory = _ => defaultDatabasePath(),
        };
        var portOpt = CreatePortOption();
        var bindOpt = CreateBindOption();
        var approvalConfigOpt = CreateApprovalConfigOption(approvalConfigFromEnvironment);
        var trustedProxyOpt = CreateTrustedProxyOption();
        var userHeaderOpt = CreateUserHeaderOption();
        var publicHostOpt = CreatePublicHostOption();
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
            publicHostOpt,
        };

        var options = new OptionSet(dbOpt, portOpt, bindOpt, approvalConfigOpt, trustedProxyOpt, userHeaderOpt, localApproverOpt, publicHostOpt);
        readSettings = options.Read;
        cmd.Validators.Add(result => ValidateCombination(result, options));

        cmd.SetAction(async (parseResult, ct) =>
        {
            var settings = options.Read(parseResult);
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

    private static Option<int> CreatePortOption()
    {
        var portOpt = new Option<int>("--port")
        {
            Description = "Port to listen on, on the --bind address (127.0.0.1 by default). Use 0 for any free port.",
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
        return portOpt;
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
            if (!IPAddress.TryParse(value, out var ip))
            {
                result.AddError($"--bind must be an IP address, but was '{value}'.");
            }
            else if (value!.Contains('%', StringComparison.Ordinal)
                || (ip.AddressFamily == AddressFamily.InterNetworkV6 && ip.ScopeId != 0))
            {
                result.AddError("--bind does not support IPv6 scope ids (zone suffixes).");
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
            DefaultValueFactory = _ => DashboardSettings.DefaultUserHeader,
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

    private static Option<string[]> CreatePublicHostOption()
    {
        var opt = new Option<string[]>("--public-host")
        {
            Description = "Host name or IP address the trusted proxy forwards in the Host header. Repeatable. localhost is always accepted.",
            AllowMultipleArgumentsPerToken = false,
        };
        opt.Validators.Add(result =>
        {
            foreach (var value in result.GetValueOrDefault<string[]>() ?? [])
            {
                if (!IsPublicHost(value))
                {
                    result.AddError($"--public-host must be a host name or IP address without scheme, port or path, but was '{value}'.");
                }
            }
        });
        return opt;
    }

    private static bool IsPublicHost(string? value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > 253)
        {
            return false;
        }
        if (value[0] == '[')
        {
            // Brackets only wrap an IPv6 literal, with no port.
            return value[^1] == ']' && IPAddress.TryParse(value[1..^1], out var v6)
                && v6.AddressFamily == AddressFamily.InterNetworkV6 && v6.ScopeId == 0;
        }
        if (IPAddress.TryParse(value, out var ip))
        {
            // Only an IPv6 address or a dotted quad that reads back exactly; 1, 127.1 and 0x7f.1 are not host names.
            return ip.AddressFamily == AddressFamily.InterNetworkV6
                ? ip.ScopeId == 0
                : string.Equals(ip.ToString(), value, StringComparison.Ordinal);
        }
        if (value.Split('.')[^1].All(char.IsAsciiDigit))
        {
            return false; // an all-numeric last label is an IP form, never a DNS name
        }
        return value.Split('.').All(label =>
            label.Length is > 0 and <= 63 && !label.StartsWith('-') && !label.EndsWith('-')
            && label.All(c => char.IsAsciiLetterOrDigit(c) || c == '-'));
    }

    // IPv6 literals travel in brackets in a Host header, so keep them in that form.
    private static string NormalisePublicHost(string value) =>
        IPAddress.TryParse(value, out var ip) && ip.AddressFamily == AddressFamily.InterNetworkV6 && !value.StartsWith('[')
            ? $"[{value}]"
            : value;

    private static void ValidateCombination(CommandResult result, OptionSet options)
    {
        var (_, _, bindOpt, _, trustedProxyOpt, userHeaderOpt, localApproverOpt, publicHostOpt) = options;
        if (result.Errors.Any())
        {
            return;
        }
        var proxies = result.GetValue(trustedProxyOpt) ?? [];
        var bindText = result.GetValue(bindOpt) ?? IPAddress.Loopback.ToString();
        if (!IPAddress.TryParse(bindText, out var bind) || bindText.Contains('%', StringComparison.Ordinal))
        {
            return; // the --bind option validator reports the reason
        }
        if (!IPAddress.IsLoopback(bind) && proxies.Length == 0)
        {
            result.AddError("--bind to a non-loopback address needs at least one --trusted-proxy.");
        }
        if (result.GetResult(userHeaderOpt)?.Implicit == false && proxies.Length == 0)
        {
            result.AddError("--user-header only applies together with --trusted-proxy.");
        }
        if ((result.GetValue(publicHostOpt) ?? []).Length > 0 && proxies.Length == 0)
        {
            result.AddError("--public-host only applies together with --trusted-proxy.");
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

    private static List<IPNetwork> ParseProxies(IEnumerable<string> values)
    {
        var proxies = new List<IPNetwork>();
        foreach (var value in values)
        {
            if (TryParseProxy(value, out var network))
            {
                proxies.Add(network);
            }
        }
        return proxies;
    }

    private static bool TryParseProxy(string value, out IPNetwork network)
    {
        if (value.Contains('/', StringComparison.Ordinal))
        {
            if (!IPNetwork.TryParse(value, out network))
            {
                return false;
            }
            if (network.BaseAddress.IsIPv4MappedToIPv6 && network.PrefixLength >= 96)
            {
                network = new IPNetwork(network.BaseAddress.MapToIPv4(), network.PrefixLength - 96);
            }
            return true;
        }
        if ((value.Contains('.', StringComparison.Ordinal) || value.Contains(':', StringComparison.Ordinal))
            && IPAddress.TryParse(value, out var ip))
        {
            if (ip.IsIPv4MappedToIPv6)
            {
                ip = ip.MapToIPv4();
            }
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
        if (!File.Exists(dbPath))
        {
            await stderr.WriteLineAsync($"Audit file not found: {dbPath}").ConfigureAwait(false);
            return null;
        }

        var plan = await DashboardApprovalPlan.LoadAsync(settings, stderr).ConfigureAwait(false);
        if (plan is null)
        {
            return null;
        }

        SqliteAuditStore? store = null;
        WebApplication? app = null;
        var started = false;
        try
        {
            store = await OpenAuditStoreAsync(dbPath, plan).ConfigureAwait(false);

            var verification = await AuditHashChain.VerifyAsync(
                store.QueryAsync(new AuditQuery { PageSize = int.MaxValue }, ct), ct).ConfigureAwait(false);
            app = BuildApp(store, settings, plan);
            if (!await TryOpenApprovalStoreAsync(app, plan, stderr).ConfigureAwait(false))
            {
                return null;
            }

            await app.StartAsync(ct).ConfigureAwait(false);
            var url = BrowsableUrl(new Uri(app.Urls.First()), settings.Bind);
            await WriteStartupAsync(stdout, verification, url, plan.Describe(settings)).ConfigureAwait(false);
            started = true;
            return new RunningDashboard(app, store, url);
        }
        catch (IOException ex)
        {
            await stderr.WriteLineAsync(
                $"Could not listen on {HostLiteral(settings.Bind)}:{settings.Port.ToString(CultureInfo.InvariantCulture)}: {ex.Message}").ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is Microsoft.Data.Sqlite.SqliteException or InvalidOperationException)
        {
            await stderr.WriteLineAsync($"Could not open the audit file {dbPath}: {ex.Message}").ConfigureAwait(false);
        }
        finally
        {
            if (!started)
            {
                await DisposeAllAsync(app, store).ConfigureAwait(false);
            }
        }

        return null;
    }

    /// <summary>The address to browse to: a wildcard bind is reached through the matching loopback address.</summary>
    internal static Uri BrowsableUrl(Uri bound, IPAddress bind) =>
        new($"http://{HostLiteral(BrowsableAddress(bind))}:{bound.Port.ToString(CultureInfo.InvariantCulture)}{PathPrefix}/");

    private static async Task<SqliteAuditStore> OpenAuditStoreAsync(string dbPath, DashboardApprovalPlan plan)
    {
        var readOnly = SqliteAuditStore.OpenReadOnly(dbPath);
        if (!plan.NeedsWritableAudit)
        {
            return readOnly;
        }

        // The read-only open is what refuses an older schema, so approvals keep that check before the writable open.
        await readOnly.DisposeAsync().ConfigureAwait(false);
        return new SqliteAuditStore(new SqliteAuditStoreOptions { DatabasePath = dbPath });
    }

    // Resolving the store at startup surfaces an unusable database now. The container owns it and disposes it with the app.
    private static async Task<bool> TryOpenApprovalStoreAsync(WebApplication app, DashboardApprovalPlan plan, TextWriter stderr)
    {
        try
        {
            _ = app.Services.GetService<SqliteApprovalStore>();
            return true;
        }
        catch (Exception ex) when (ex is Microsoft.Data.Sqlite.SqliteException or InvalidOperationException
            or IOException or UnauthorizedAccessException)
        {
            await stderr.WriteLineAsync(
                $"Could not open the approval database {plan.DatabasePath}: {ex.Message}").ConfigureAwait(false);
            return false;
        }
    }

    private static async Task DisposeAllAsync(WebApplication? app, SqliteAuditStore? store)
    {
        try
        {
            if (app is not null)
            {
                await app.DisposeAsync().ConfigureAwait(false);
            }
        }
        finally
        {
            if (store is not null)
            {
                await store.DisposeAsync().ConfigureAwait(false);
            }
        }
    }

    private static async Task WriteStartupAsync(TextWriter stdout, AuditChainVerification verification, Uri url, string approvalsLine)
    {
        await stdout.WriteLineAsync(verification.IsIntact
            ? $"Audit chain intact: {verification.EntriesChecked} entries"
            : $"Audit chain broken at entry {verification.FirstBrokenEntryId}").ConfigureAwait(false);
        await stdout.WriteLineAsync($"Dashboard: {url}").ConfigureAwait(false);
        await stdout.WriteLineAsync(approvalsLine).ConfigureAwait(false);
    }

    private static IPAddress BrowsableAddress(IPAddress bind) =>
        bind.Equals(IPAddress.Any) ? IPAddress.Loopback
        : bind.Equals(IPAddress.IPv6Any) ? IPAddress.IPv6Loopback
        : bind;

    private static string HostLiteral(IPAddress address) =>
        address.AddressFamily == AddressFamily.InterNetworkV6 ? $"[{address.ToString().Split('%')[0]}]" : address.ToString();

    // Kestrel leaves an encoded slash in the route value, so the id is read from the raw target and escaped once.
    private static IResult RedirectApprovalLink(HttpContext ctx) =>
        Results.Redirect($"{PathPrefix}/approvals/{Uri.EscapeDataString(ApprovalRequestTarget.IdOf(ctx, trailingSegments: 0))}");

    internal static WebApplication BuildApp(SqliteAuditStore store, DashboardSettings settings, DashboardApprovalPlan plan)
    {
        // An empty builder reads no appsettings files and no environment variables, so nothing can add Kestrel:Endpoints
        // that would override the address below, and no file watchers are created.
        var builder = WebApplication.CreateEmptyBuilder(new WebApplicationOptions());
        builder.WebHost.UseKestrelCore();
        builder.WebHost.UseUrls(string.Create(CultureInfo.InvariantCulture, $"http://{HostLiteral(settings.Bind)}:{settings.Port}"));
        builder.Services.AddRouting();
        builder.Services.AddSingleton<IAuditStore>(store);
        plan.Register(builder.Services);

        var app = builder.Build();

        // The identity middleware must stay first: its non-loopback gate has to cover every route below,
        // including the root redirects and everything MapAISentinel maps.
        app.UseApproverIdentity(settings);
        app.MapAISentinel(PathPrefix);
        app.MapGet("/", () => Results.Redirect(PathPrefix + "/"));
        if (plan.ServesApprovals)
        {
            app.MapGet("/approvals/{id}", RedirectApprovalLink);
        }
        return app;
    }
}
