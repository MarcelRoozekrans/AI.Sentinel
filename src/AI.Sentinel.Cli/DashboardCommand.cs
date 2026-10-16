using System.CommandLine;
using System.Globalization;
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
/// 127.0.0.1. Read-only: it never appends entries and runs no retention or size cap.
/// </summary>
public static class DashboardCommand
{
    private const int DefaultPort = 5170;
    private const string PathPrefix = "/ai-sentinel";

    public static Command Build() => Build(LocalAudit.DefaultDatabasePath);

    internal static Command Build(Func<string> defaultDatabasePath)
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

        var cmd = new Command("dashboard", "Browse the local audit file in the AI.Sentinel dashboard.")
        {
            dbOpt,
            portOpt,
        };

        cmd.SetAction(async (parseResult, ct) =>
        {
            var db = parseResult.GetRequiredValue(dbOpt);
            var port = parseResult.GetValue(portOpt);
            var stdout = parseResult.InvocationConfiguration.Output;
            var stderr = parseResult.InvocationConfiguration.Error;

            if (parseResult.GetResult(dbOpt)?.Implicit == true && !Path.IsPathRooted(db))
            {
                await stderr.WriteLineAsync(
                    "No per-user data folder is available, so there is no default audit file. Pass --db <path>.").ConfigureAwait(false);
                return 1;
            }

            return await RunAsync(db, port, stdout, stderr, ct).ConfigureAwait(false);
        });

        return cmd;
    }

    public static async Task<int> RunAsync(
        string dbPath, int port, TextWriter stdout, TextWriter stderr, CancellationToken ct)
    {
        var dashboard = await StartAsync(dbPath, port, stdout, stderr, ct).ConfigureAwait(false);
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
        string dbPath, int port, TextWriter stdout, TextWriter stderr, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(stdout);
        ArgumentNullException.ThrowIfNull(stderr);

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
            store = new SqliteAuditStore(new SqliteAuditStoreOptions { DatabasePath = dbPath });

            var verification = await AuditHashChain.VerifyAsync(
                store.QueryAsync(new AuditQuery { PageSize = int.MaxValue }, ct), ct).ConfigureAwait(false);

            app = BuildApp(store, port);

            await app.StartAsync(ct).ConfigureAwait(false);

            var bound = new Uri(app.Urls.First());
            var url = new Uri($"http://127.0.0.1:{bound.Port.ToString(CultureInfo.InvariantCulture)}{PathPrefix}/");

            await stdout.WriteLineAsync(verification.IsIntact
                ? $"Audit chain intact: {verification.EntriesChecked} entries"
                : $"Audit chain broken at entry {verification.FirstBrokenEntryId}").ConfigureAwait(false);
            await stdout.WriteLineAsync($"Dashboard: {url}").ConfigureAwait(false);

            started = true;
            return new RunningDashboard(app, store, url);
        }
        catch (IOException ex)
        {
            await stderr.WriteLineAsync(
                $"Could not listen on 127.0.0.1:{port.ToString(CultureInfo.InvariantCulture)}: {ex.Message}").ConfigureAwait(false);
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

    private static WebApplication BuildApp(SqliteAuditStore store, int port)
    {
        var builder = WebApplication.CreateSlimBuilder();
        builder.Logging.ClearProviders();
        builder.WebHost.UseUrls(string.Create(CultureInfo.InvariantCulture, $"http://127.0.0.1:{port}"));
        builder.Services.AddRouting();
        builder.Services.AddSingleton<IAuditStore>(store);

        var app = builder.Build();
        app.MapAISentinel(PathPrefix);
        app.MapGet("/", () => Results.Redirect(PathPrefix + "/"));
        return app;
    }
}
