using System.Globalization;
using AI.Sentinel.Audit;

namespace AI.Sentinel.Sqlite.Local;

/// <summary>
/// Shared audit setup for the CLIs: reads the <c>AUDIT_SQLITE</c>, <c>AUDIT_NDJSON</c> and
/// <c>AUDIT_MAX_MB</c> environment variables and opens the store and forwarders they describe.
/// Nothing here throws for an unusable file; problems are collected for the CLI to report.
/// </summary>
internal static class LocalAudit
{
    private const long DefaultMaxMegabytes = 100;
    private const long BytesPerMegabyte = 1024L * 1024;
    private static readonly TimeSpan BusyTimeout = TimeSpan.FromSeconds(2);

    /// <summary>The database every CLI writes to by default: <c>&lt;LocalApplicationData&gt;/ai-sentinel/audit.db</c>.</summary>
    public static string DefaultDatabasePath() =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "ai-sentinel", "audit.db");

    /// <summary>Reads the audit settings from <paramref name="env"/>.</summary>
    /// <param name="env">The environment variables.</param>
    /// <param name="prefix"><c>SENTINEL_HOOK_</c> or <c>SENTINEL_MCP_</c>.</param>
    /// <param name="defaultDatabasePath">The database used when <c>AUDIT_SQLITE</c> is unset.</param>
    /// <param name="problems">Receives one message per variable that could not be used.</param>
    public static LocalAuditSettings ReadSettings(
        IReadOnlyDictionary<string, string?> env,
        string prefix,
        string defaultDatabasePath,
        ICollection<string> problems)
    {
        ArgumentNullException.ThrowIfNull(env);
        ArgumentNullException.ThrowIfNull(problems);

        var sqlite = Read(env, prefix + "AUDIT_SQLITE");
        var databasePath = sqlite switch
        {
            null when !Path.IsPathRooted(defaultDatabasePath) => NoDataFolder(problems),
            null => defaultDatabasePath,
            _ when string.Equals(sqlite, "off", StringComparison.OrdinalIgnoreCase) => null,
            _ => sqlite,
        };

        return new LocalAuditSettings(
            databasePath,
            Read(env, prefix + "AUDIT_NDJSON"),
            ReadMaxBytes(env, prefix + "AUDIT_MAX_MB", problems));
    }

    /// <summary>Opens the store and forwarders <paramref name="settings"/> describe. Never throws for
    /// an unusable file: SQLite falls back to the in-memory ring buffer and NDJSON is skipped, each
    /// with one entry in <see cref="LocalAuditSession.Problems"/>.</summary>
    /// <param name="settings">From <see cref="ReadSettings"/>.</param>
    /// <param name="source">One of <see cref="AuditSources"/>, stamped on every entry.</param>
    /// <param name="onProblem">Optional. Invoked once per distinct problem as it is recorded, including
    /// problems found during this call, so a long-running CLI can report them without waiting for shutdown.</param>
    public static LocalAuditSession Open(LocalAuditSettings settings, string source, Action<string>? onProblem = null)
    {
        ArgumentNullException.ThrowIfNull(settings);
        var problems = new LocalAuditProblems(onProblem);
        var store = OpenStore(settings, problems);
        var forwarders = OpenForwarders(settings, problems);
        return new LocalAuditSession(store, source, forwarders, problems);
    }

    /// <summary>An unset HOME makes the per-user data folder empty and the default path relative, which
    /// would put a database in the current directory. Recording is switched off instead.</summary>
    private static string? NoDataFolder(ICollection<string> problems)
    {
        problems.Add("No per-user data folder was found, so audit recording is off. Set the AUDIT_SQLITE variable to a database path to record.");
        return null;
    }

    private static string? Read(IReadOnlyDictionary<string, string?> env, string name) =>
        env.TryGetValue(name, out var value) && !string.IsNullOrWhiteSpace(value) ? value.Trim() : null;

    private static long? ReadMaxBytes(IReadOnlyDictionary<string, string?> env, string name, ICollection<string> problems)
    {
        var raw = Read(env, name);
        if (raw is null) return DefaultMaxMegabytes * BytesPerMegabyte;

        if (long.TryParse(raw, NumberStyles.None, CultureInfo.InvariantCulture, out var megabytes)
            && megabytes <= long.MaxValue / BytesPerMegabyte)
        {
            return megabytes == 0 ? null : megabytes * BytesPerMegabyte;
        }

        problems.Add($"{name} must be a whole number of megabytes, or 0 for no cap; using the default of {DefaultMaxMegabytes}.");
        return DefaultMaxMegabytes * BytesPerMegabyte;
    }

    private static IAuditStore OpenStore(LocalAuditSettings settings, LocalAuditProblems problems)
    {
        if (settings.DatabasePath is not { } path) return new RingBufferAuditStore();

        SqliteAuditStore store;
        try
        {
            CreatePrivateDirectory(path);
            CreatePrivateFile(path);
            store = new SqliteAuditStore(new SqliteAuditStoreOptions
            {
                DatabasePath = path,
                BusyTimeout = BusyTimeout,
                MaxDatabaseSizeBytes = settings.MaxDatabaseSizeBytes,
                EnforceSizeCapOnOpen = true,
                VacuumAfterTrim = false,
            });
        }
#pragma warning disable CA1031 // Any failure to open falls back to memory; it must not stop the CLI.
        catch (Exception ex)
#pragma warning restore CA1031
        {
            problems.Add($"Could not open the audit database {path}: {ex.GetType().Name}: {ex.Message}. Recording in memory only.");
            return new RingBufferAuditStore();
        }

        RestrictToOwner(path, problems);
        return store;
    }

    private static List<IAuditForwarder> OpenForwarders(LocalAuditSettings settings, LocalAuditProblems problems)
    {
        var forwarders = new List<IAuditForwarder>();
        if (settings.NdjsonPath is not { } path) return forwarders;

        try
        {
            CreatePrivateFile(path);
            forwarders.Add(new NdjsonFileAuditForwarder(new NdjsonFileAuditForwarderOptions
            {
                FilePath = path,
                OnError = problems.Add,
            }));
        }
#pragma warning disable CA1031 // An unusable NDJSON file is skipped; it must not stop the CLI.
        catch (Exception ex)
#pragma warning restore CA1031
        {
            problems.Add($"Could not open the audit NDJSON file {path}: {ex.GetType().Name}: {ex.Message}. NDJSON output is off.");
        }
        return forwarders;
    }

    private static void CreatePrivateDirectory(string databasePath)
    {
        var dir = Path.GetDirectoryName(Path.GetFullPath(databasePath));
        if (string.IsNullOrEmpty(dir)) return;

        if (OperatingSystem.IsWindows())
        {
            Directory.CreateDirectory(dir);
        }
        else
        {
            Directory.CreateDirectory(dir, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }
    }

    /// <summary>On Unix, creates <paramref name="path"/> as an empty 0600 file unless it exists, so the
    /// file is never readable by others, not even briefly. SQLite opens a zero-byte file as an empty
    /// database and gives its <c>-wal</c> and <c>-shm</c> files the database's mode.</summary>
    private static void CreatePrivateFile(string path)
    {
        if (OperatingSystem.IsWindows() || File.Exists(path)) return;

        try
        {
            using var created = new FileStream(path, new FileStreamOptions
            {
                Mode = FileMode.CreateNew,
                Access = FileAccess.Write,
                UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite,
            });
        }
        catch (IOException) when (File.Exists(path))
        {
            // Another process created it first; it is used as it is.
        }
    }

    /// <summary>Safety net: sets 0600 on the database and the WAL side files SQLite created alongside it.
    /// A failure leaves the store usable and is reported.</summary>
    private static void RestrictToOwner(string databasePath, LocalAuditProblems problems)
    {
        if (OperatingSystem.IsWindows()) return;

        try
        {
            foreach (var file in new[] { databasePath, databasePath + "-wal", databasePath + "-shm" })
            {
                if (File.Exists(file))
                {
                    File.SetUnixFileMode(file, UnixFileMode.UserRead | UnixFileMode.UserWrite);
                }
            }
        }
#pragma warning disable CA1031 // A permission failure leaves the store usable; report it and carry on.
        catch (Exception ex)
#pragma warning restore CA1031
        {
            problems.Add($"Could not restrict the audit database {databasePath} to its owner: {ex.GetType().Name}: {ex.Message}.");
        }
    }
}
