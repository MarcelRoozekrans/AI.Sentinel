using System.Globalization;
using AI.Sentinel.Authorization;
using Microsoft.Data.Sqlite;
using Xunit;

namespace AI.Sentinel.Sqlite.Tests;

/// <summary>
/// Cross-checks the C# <see cref="SentinelDenyCodes.PolicyDenied"/> constant against the SQLite
/// column DEFAULT clause in <c>SqliteSchema.cs</c>. The two MUST stay in lockstep — when a
/// non-AUTHZ entry is appended, the C# null-coalesce supplies <c>SentinelDenyCodes.PolicyDenied</c>
/// and the column DEFAULT is the fallback for legacy rows. If either side drifts (someone changes
/// the DEFAULT to <c>'denied'</c> on a future schema migration, or renames the constant for
/// "uniformity"), this test fails before any audit-consumer / SIEM-dashboard / wire-format
/// regression ships.
/// </summary>
public sealed class SqliteSchemaDefaultMatchesConstantTests : IDisposable
{
    private readonly string _dbPath = Path.Combine(
        Path.GetTempPath(),
        string.Create(CultureInfo.InvariantCulture, $"sentinel-default-{Guid.NewGuid():N}.db"));

    public void Dispose()
    {
        TryDelete(_dbPath);
        TryDelete(_dbPath + "-wal");
        TryDelete(_dbPath + "-shm");
    }

    private static void TryDelete(string path)
    {
        try { if (File.Exists(path)) File.Delete(path); }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }

    [Fact]
    public async Task PolicyCodeColumn_Default_MatchesSentinelDenyCodesPolicyDenied()
    {
        // Step 1: open a SqliteAuditStore to drive schema init (matches the surrounding test
        // pattern in SqliteSchemaMigrationTests; doesn't need internal access to SqliteSchema).
        await using (var store = new SqliteAuditStore(new SqliteAuditStoreOptions { DatabasePath = _dbPath }))
        {
            // Trigger init — GetSchemaVersionForTestingAsync invokes the schema-init path.
            await store.GetSchemaVersionForTestingAsync(CancellationToken.None);
        }

        // Step 2: open a fresh raw connection and read the column DEFAULT from sqlite metadata.
        var csb = new SqliteConnectionStringBuilder
        {
            DataSource = _dbPath,
            Pooling = false,
            Mode = SqliteOpenMode.ReadOnly,
        };
        await using var conn = new SqliteConnection(csb.ToString());
        await conn.OpenAsync();

        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            SELECT dflt_value FROM pragma_table_info('audit_entries')
             WHERE name = 'policy_code';
            """;
        var raw = (string?)await cmd.ExecuteScalarAsync();
        Assert.NotNull(raw);

        // pragma_table_info returns the default verbatim from the DDL — for a TEXT column with
        // DEFAULT 'policy_denied', that's the literal string "'policy_denied'" (with the SQL
        // single quotes preserved). Strip them to compare against the C# constant.
        var actualDefault = raw!.Trim('\'');
        Assert.Equal(SentinelDenyCodes.PolicyDenied, actualDefault);
    }
}
