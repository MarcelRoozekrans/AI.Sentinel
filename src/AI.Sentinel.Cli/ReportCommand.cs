using System.CommandLine;
using System.Globalization;
using System.Text;
using AI.Sentinel.Cli.Report;
using AI.Sentinel.Sqlite;
using AI.Sentinel.Sqlite.Local;
using Microsoft.Data.Sqlite;

namespace AI.Sentinel.Cli;

/// <summary>
/// <c>sentinel report</c>: builds a compliance report from the local audit file, as Markdown, HTML or JSON.
/// Read-only: it opens the file read-only and never creates, migrates or appends to it.
/// Exit codes: 0 when the report was written, 1 for a usage error or an unreadable or missing audit file,
/// 2 when the hash chain is broken. The report is still written when the chain is broken.
/// </summary>
public static class ReportCommand
{
    private const int DefaultPeriodDays = 30;
    private const int ChainBroken = 2;
    private const string DateFormat = "yyyy-MM-dd";
    private static readonly string[] TimestampFormats =
    [
        "yyyy-MM-dd'T'HH:mmK",
        "yyyy-MM-dd'T'HH:mm:ssK",
        "yyyy-MM-dd'T'HH:mm:ss.FFFFFFFK",
    ];

    public static Command Build() => Build(LocalAudit.DefaultDatabasePath);

    internal static Command Build(Func<string> defaultDatabasePath) => Build(defaultDatabasePath, TimeProvider.System);

    internal static Command Build(Func<string> defaultDatabasePath, TimeProvider time)
    {
        ArgumentNullException.ThrowIfNull(defaultDatabasePath);
        ArgumentNullException.ThrowIfNull(time);

        var options = CreateOptions(defaultDatabasePath);
        var cmd = new Command("report", "Build a compliance report from the local audit file.")
        {
            options.Db,
            options.From,
            options.To,
            options.Format,
            options.Output,
        };
        cmd.SetAction((parseResult, ct) => InvokeAsync(parseResult, options, time, ct));
        return cmd;
    }

    private static ReportOptions CreateOptions(Func<string> defaultDatabasePath)
    {
        var format = new Option<string>("--format")
        {
            Description = "Output format: md, html or json.",
            DefaultValueFactory = _ => "md",
        };
        format.AcceptOnlyFromAmong("md", "html", "json");

        return new ReportOptions(
            new Option<string>("--db")
            {
                Description = "Path to the audit SQLite file. Defaults to the file the hooks and the MCP proxy write.",
                DefaultValueFactory = _ => defaultDatabasePath(),
            },
            new Option<string?>("--from")
            {
                Description = "Start of the period: an ISO date (yyyy-MM-dd, from 00:00 UTC) or an ISO 8601 timestamp. Defaults to 30 days before --to.",
            },
            new Option<string?>("--to")
            {
                Description = "End of the period, inclusive: an ISO date (yyyy-MM-dd, to the end of that UTC day) or an ISO 8601 timestamp. Defaults to now.",
            },
            format,
            new Option<string?>("--output")
            {
                Description = "File to write the report to. Defaults to standard output.",
            });
    }

    private static async Task<int> InvokeAsync(ParseResult parseResult, ReportOptions options, TimeProvider time, CancellationToken ct)
    {
        var db = parseResult.GetRequiredValue(options.Db);
        var stdout = parseResult.InvocationConfiguration.Output;
        var stderr = parseResult.InvocationConfiguration.Error;

        if (parseResult.GetResult(options.Db)?.Implicit == true && !Path.IsPathRooted(db))
        {
            await stderr.WriteLineAsync(
                "No per-user data folder is available, so there is no default audit file. Pass --db <path>.").ConfigureAwait(false);
            return 1;
        }

        var period = ReadPeriod(parseResult.GetValue(options.From), parseResult.GetValue(options.To), time.GetUtcNow());
        if (period.Error is not null)
        {
            await stderr.WriteLineAsync(period.Error).ConfigureAwait(false);
            return 1;
        }

        return await RunAsync(
            db, period.From, period.To, parseResult.GetRequiredValue(options.Format), parseResult.GetValue(options.Output),
            time, stdout, stderr, ct).ConfigureAwait(false);
    }

    private static async Task<int> RunAsync(
        string db, DateTimeOffset from, DateTimeOffset to, string format, string? output,
        TimeProvider time, TextWriter stdout, TextWriter stderr, CancellationToken ct)
    {
        if (!File.Exists(db))
        {
            await stderr.WriteLineAsync($"Audit file not found: {db}").ConfigureAwait(false);
            return 1;
        }

        ComplianceReport report;
        try
        {
            var store = SqliteAuditStore.OpenReadOnly(db);
            await using (store.ConfigureAwait(false))
            {
                report = await ComplianceReportBuilder.BuildAsync(store, from, to, Path.GetFullPath(db), time, ct).ConfigureAwait(false);
            }
        }
        catch (Exception ex) when (ex is SqliteException or InvalidOperationException)
        {
            await stderr.WriteLineAsync($"Could not read the audit file {db}: {ex.Message}").ConfigureAwait(false);
            return 1;
        }

        var text = format switch
        {
            "html" => HtmlReportRenderer.Render(report),
            "json" => JsonReportRenderer.Render(report),
            _ => MarkdownReportRenderer.Render(report),
        };

        if (output is null)
        {
            await stdout.WriteAsync(text).ConfigureAwait(false);
        }
        else
        {
            try
            {
                await File.WriteAllTextAsync(output, text, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false), ct).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                await stderr.WriteLineAsync($"Could not write the report to {output}: {ex.Message}").ConfigureAwait(false);
                return 1;
            }
        }

        if (!report.Art12.ChainIntact)
        {
            await stderr.WriteLineAsync(
                $"Audit chain broken at entry {report.Art12.FirstBrokenEntryId}. The report was written and shows the break.").ConfigureAwait(false);
            return ChainBroken;
        }
        return 0;
    }

    private static (DateTimeOffset From, DateTimeOffset To, string? Error) ReadPeriod(string? fromText, string? toText, DateTimeOffset now)
    {
        var to = now;
        if (toText is not null && !TryParseInstant(toText, endOfDay: true, out to))
        {
            return (default, default, InvalidDate("--to", toText));
        }

        var from = to.AddDays(-DefaultPeriodDays);
        if (fromText is not null && !TryParseInstant(fromText, endOfDay: false, out from))
        {
            return (default, default, InvalidDate("--from", fromText));
        }

        if (from > to)
        {
            return (default, default, string.Create(CultureInfo.InvariantCulture,
                $"--from {from.ToUniversalTime():O} is after --to {to.ToUniversalTime():O}."));
        }
        return (from, to, null);
    }

    private static string InvalidDate(string option, string value) =>
        $"{option} must be an ISO date, yyyy-MM-dd, or an ISO 8601 timestamp such as 2026-10-17T09:30:00Z, but was '{value}'.";

    /// <summary>
    /// Parses an ISO date or timestamp. A date alone is a UTC day: its start, or with <paramref name="endOfDay"/> its last
    /// tick, because the end of the period is inclusive. A timestamp without an offset is read as UTC.
    /// </summary>
    private static bool TryParseInstant(string value, bool endOfDay, out DateTimeOffset result)
    {
        if (DateTime.TryParseExact(value, DateFormat, CultureInfo.InvariantCulture, DateTimeStyles.None, out var date))
        {
            var start = new DateTimeOffset(date, TimeSpan.Zero);
            result = !endOfDay ? start
                : date == DateTime.MaxValue.Date ? DateTimeOffset.MaxValue
                : start.AddDays(1).AddTicks(-1);
            return true;
        }

        return DateTimeOffset.TryParseExact(
            value, TimestampFormats, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out result);
    }

    private sealed record ReportOptions(
        Option<string> Db, Option<string?> From, Option<string?> To, Option<string> Format, Option<string?> Output);
}
