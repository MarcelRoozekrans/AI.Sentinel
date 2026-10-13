using System.Globalization;
using System.Runtime.CompilerServices;
using AI.Sentinel.Audit;
using AI.Sentinel.Detection;
using Microsoft.Data.Sqlite;

namespace AI.Sentinel.Sqlite;

/// <summary>
/// Persistent <see cref="IAuditStore"/> backed by a single-file SQLite database.
/// Survives process restarts, links every appended entry into the <see cref="AuditHashChain"/>
/// and continues that chain across restarts, and supports optional time-based retention via a
/// background sweep timer. Several processes may write to one file at once: each append reads
/// the chain head and the next sequence inside its own write transaction.
/// </summary>
public sealed class SqliteAuditStore : IAuditStore, IAsyncDisposable
{
    private readonly SqliteAuditStoreOptions _options;
    private readonly SqliteConnection _connection;
    private readonly SemaphoreSlim _writeLock = new(1, 1);
    private readonly Timer? _retentionTimer;
    private bool _disposed;

    public SqliteAuditStore(SqliteAuditStoreOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentException.ThrowIfNullOrWhiteSpace(options.DatabasePath, nameof(options));
        _options = options;

        var dir = Path.GetDirectoryName(options.DatabasePath);
        if (!string.IsNullOrEmpty(dir))
        {
            Directory.CreateDirectory(dir);
        }

        // Pooling=false: connection is single-instance, owned for store lifetime.
        // Without this, Dispose returns the connection to the pool which keeps the
        // file handle open and prevents tests from deleting the .db file.
        var csb = new SqliteConnectionStringBuilder
        {
            DataSource = options.DatabasePath,
            Pooling = false,
            Mode = SqliteOpenMode.ReadWriteCreate,
        };
        _connection = new SqliteConnection(csb.ToString());
        try
        {
            _connection.Open();

            // Schema bootstrap is synchronous in ctor — failure here surfaces immediately
            // rather than on first append.
            SqliteSchema.InitializeAsync(_connection, CancellationToken.None).GetAwaiter().GetResult();
        }
        catch
        {
            // Nothing else owns the connection yet; leaving it open would hold its file handle,
            // and any lock, until the finalizer runs.
            _connection.Dispose();
            throw;
        }

        var hasTimeRetention = options.RetentionPeriod is { } r && r > TimeSpan.Zero;
        var hasSizeCap = options.MaxDatabaseSizeBytes is { } b && b > 0;
        if (hasTimeRetention || hasSizeCap)
        {
            _retentionTimer = new Timer(
                static state => ((SqliteAuditStore)state!).SweepRetention(),
                this,
                options.RetentionSweepInterval,
                options.RetentionSweepInterval);
        }
    }

    public async ValueTask<AuditEntry> AppendAsync(AuditEntry entry, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(entry);
        ObjectDisposedException.ThrowIf(_disposed, this);

        await _writeLock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            // BEGIN IMMEDIATE takes the write lock before the chain head and sequence are read, so
            // another process cannot append between that read and this insert. The entry and the
            // chain head commit together, so a failed insert never moves the head.
            using var tx = _connection.BeginTransaction();
            long seq;
            string? lastHash;
            using (var head = _connection.CreateCommand())
            {
                head.Transaction = tx;
                head.CommandText = """
                    SELECT (SELECT hash FROM audit_chain_head WHERE id = 1),
                           (SELECT COALESCE(MAX(sequence), 0) + 1 FROM audit_entries);
                    """;
                using var reader = await head.ExecuteReaderAsync(ct).ConfigureAwait(false);
                await reader.ReadAsync(ct).ConfigureAwait(false);
                lastHash = reader.IsDBNull(0) ? null : reader.GetString(0);
                seq = reader.GetInt64(1);
            }

            entry = AuditHashChain.Link(entry, lastHash);
            using var cmd = _connection.CreateCommand();
            cmd.Transaction = tx;
            cmd.CommandText = """
                INSERT INTO audit_entries
                    (id, timestamp, severity, detector_id, hash, previous_hash, summary, sequence, policy_code, session_id, source)
                VALUES
                    ($id, $ts, $sev, $det, $hash, $prev, $summary, $seq, $code, $session, $source);
                INSERT INTO audit_chain_head (id, hash) VALUES (1, $hash)
                    ON CONFLICT (id) DO UPDATE SET hash = excluded.hash;
                """;
            cmd.Parameters.AddWithValue("$id", entry.Id);
            cmd.Parameters.AddWithValue("$ts", entry.Timestamp.UtcTicks);
            cmd.Parameters.AddWithValue("$sev", (int)entry.Severity);
            cmd.Parameters.AddWithValue("$det", entry.DetectorId);
            cmd.Parameters.AddWithValue("$hash", entry.Hash);
            cmd.Parameters.AddWithValue("$prev", (object?)entry.PreviousHash ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$summary", entry.Summary);
            cmd.Parameters.AddWithValue("$seq", seq);
            cmd.Parameters.AddWithValue("$code", (object?)entry.PolicyCode ?? DBNull.Value);
            // session_id is nullable: detectors that don't carry a session pass null and we
            // round-trip that as DBNull for dashboard queries to filter on IS NULL.
            cmd.Parameters.AddWithValue("$session", (object?)entry.SessionId ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$source", (object?)entry.Source ?? DBNull.Value);
            await cmd.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
            await tx.CommitAsync(ct).ConfigureAwait(false);
            return entry;
        }
        finally
        {
            _writeLock.Release();
        }
    }

    public async IAsyncEnumerable<AuditEntry> QueryAsync(
        AuditQuery query,
        [EnumeratorCancellation] CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(query);
        ObjectDisposedException.ThrowIf(_disposed, this);

        await _writeLock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            using var cmd = BuildQueryCommand(query);
            using var reader = await cmd.ExecuteReaderAsync(ct).ConfigureAwait(false);
            while (await reader.ReadAsync(ct).ConfigureAwait(false))
            {
                yield return ReadEntry((SqliteDataReader)reader);
            }
        }
        finally
        {
            _writeLock.Release();
        }
    }

    private SqliteCommand BuildQueryCommand(AuditQuery query)
    {
        var cmd = _connection.CreateCommand();
        var sql = new System.Text.StringBuilder(
            "SELECT id, timestamp, severity, detector_id, hash, previous_hash, summary, policy_code, session_id, source FROM audit_entries WHERE 1=1");

        if (query.MinSeverity.HasValue)
        {
            sql.Append(" AND severity >= $minSev");
            cmd.Parameters.AddWithValue("$minSev", (int)query.MinSeverity.Value);
        }
        if (query.From.HasValue)
        {
            sql.Append(" AND timestamp >= $from");
            cmd.Parameters.AddWithValue("$from", query.From.Value.UtcTicks);
        }
        if (query.To.HasValue)
        {
            sql.Append(" AND timestamp <= $to");
            cmd.Parameters.AddWithValue("$to", query.To.Value.UtcTicks);
        }
        if (!string.IsNullOrEmpty(query.SessionId))
        {
            sql.Append(" AND session_id = $session");
            cmd.Parameters.AddWithValue("$session", query.SessionId);
        }

        sql.Append(query.Reverse
            ? " ORDER BY sequence DESC LIMIT $limit"
            : " ORDER BY sequence ASC LIMIT $limit");
        cmd.Parameters.AddWithValue("$limit", query.PageSize);
        cmd.CommandText = sql.ToString();
        return cmd;
    }

    // TODO(future): the positional reader.GetString(N) calls below mirror the SELECT column order
    // in BuildQueryCommand. If you reorder or add a column between the existing ones, both call
    // sites must move in lockstep. Consider extracting `private const string AuditEntryColumns =`
    // shared by both methods, with named-index constants — defer until either side gets bigger.
    private static AuditEntry ReadEntry(SqliteDataReader reader)
    {
        var id = reader.GetString(0);
        var tsTicks = reader.GetInt64(1);
        var sev = (Severity)reader.GetInt32(2);
        var detectorId = reader.GetString(3);
        var hash = reader.GetString(4);
        var prev = reader.IsDBNull(5) ? null : reader.GetString(5);
        var summary = reader.GetString(6);
        var policyCode = reader.IsDBNull(7) ? null : reader.GetString(7);
        var sessionId = reader.IsDBNull(8) ? null : reader.GetString(8);
        var source = reader.IsDBNull(9) ? null : reader.GetString(9);
        var ts = new DateTimeOffset(tsTicks, TimeSpan.Zero);
        return new AuditEntry(id, ts, hash, prev, sev, detectorId, summary, policyCode, sessionId, source);
    }

    private void SweepRetention()
    {
        if (_disposed) return;

        try
        {
            _writeLock.Wait();
            try
            {
                if (_options.RetentionPeriod is { } retention && retention > TimeSpan.Zero)
                {
                    var cutoff = DateTimeOffset.UtcNow - retention;
                    using var cmd = _connection.CreateCommand();
                    // Delete only the longest expired prefix in append order. Timestamps are taken
                    // before the write lock, so an expired entry can follow a younger one; deleting
                    // by timestamp alone would cut the hash chain in the middle.
                    cmd.CommandText = """
                        DELETE FROM audit_entries
                         WHERE sequence < COALESCE(
                             (SELECT MIN(sequence) FROM audit_entries WHERE timestamp >= $cutoff),
                             (SELECT MAX(sequence) + 1 FROM audit_entries));
                        """;
                    cmd.Parameters.AddWithValue("$cutoff", cutoff.UtcTicks);
                    cmd.ExecuteNonQuery();
                }

                if (_options.MaxDatabaseSizeBytes is { } maxBytes && maxBytes > 0)
                {
                    EnforceSizeCap(maxBytes);
                }
            }
            finally
            {
                _writeLock.Release();
            }
        }
        catch (SqliteException)
        {
            // Background timer; swallow transient errors. Next tick will retry.
        }
        catch (ObjectDisposedException)
        {
            // Race with disposal — nothing to do.
        }
    }

    /// <summary>
    /// Deletes oldest entries in 10%-batches (minimum 100) until the on-disk file size
    /// is under <paramref name="maxBytes"/>. Runs <c>VACUUM</c> after each batch so the
    /// file actually shrinks (SQLite holds onto freed pages until VACUUM reclaims them).
    /// Caller must hold <see cref="_writeLock"/>.
    /// </summary>
    private void EnforceSizeCap(long maxBytes)
    {
        // Bound the loop: in pathological scenarios (huge VACUUM-resistant file, very
        // small cap) we don't want to spin forever per sweep tick.
        const int maxIterations = 8;
        for (int i = 0; i < maxIterations; i++)
        {
            long currentSize;
            try { currentSize = new FileInfo(_options.DatabasePath).Length; }
            catch (IOException) { return; }
            if (currentSize <= maxBytes) return;

            long totalRows;
            using (var countCmd = _connection.CreateCommand())
            {
                countCmd.CommandText = "SELECT COUNT(*) FROM audit_entries;";
                var raw = countCmd.ExecuteScalar();
                totalRows = raw is null or DBNull ? 0L : Convert.ToInt64(raw, CultureInfo.InvariantCulture);
            }
            if (totalRows == 0) return;

            var deleteCount = Math.Max(100L, totalRows / 10);
            using (var del = _connection.CreateCommand())
            {
                del.CommandText = """
                    DELETE FROM audit_entries
                    WHERE id IN (SELECT id FROM audit_entries ORDER BY sequence ASC LIMIT $n);
                    """;
                var p = del.CreateParameter();
                p.ParameterName = "$n";
                p.SqliteType = Microsoft.Data.Sqlite.SqliteType.Integer;
                p.Value = deleteCount;
                del.Parameters.Add(p);
                if (del.ExecuteNonQuery() == 0) return; // safety: nothing deleted, avoid infinite loop
            }

            // VACUUM reclaims freed pages and shrinks the main DB. Schema uses WAL mode,
            // so we must also force a TRUNCATE checkpoint — otherwise the main file
            // can't shrink past whatever the WAL has pinned.
            using (var vacuum = _connection.CreateCommand())
            {
                vacuum.CommandText = "VACUUM;";
                vacuum.ExecuteNonQuery();
            }
            using (var checkpoint = _connection.CreateCommand())
            {
                checkpoint.CommandText = "PRAGMA wal_checkpoint(TRUNCATE);";
                checkpoint.ExecuteNonQuery();
            }
        }
    }

    // ---- Test helpers (exposed via InternalsVisibleTo) ------------------------------------------

    /// <summary>Runs a single retention sweep synchronously. Test hook so the timer-driven sweep
    /// can be exercised deterministically without sleeping on the timer interval.</summary>
    internal Task RunRetentionForTestingAsync(CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        SweepRetention();
        return Task.CompletedTask;
    }

    internal async Task<int> GetSchemaVersionForTestingAsync(CancellationToken ct)
    {
        await _writeLock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            return await SqliteSchema.GetVersionAsync(_connection, ct).ConfigureAwait(false);
        }
        finally
        {
            _writeLock.Release();
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (_disposed) return;
        _disposed = true;

        if (_retentionTimer is not null)
        {
            await _retentionTimer.DisposeAsync().ConfigureAwait(false);
        }

        // Acquire the write lock before tearing down the connection so any
        // concurrent Append/Query that's already past the _disposed check but
        // not yet at WaitAsync can't observe a disposed connection / semaphore.
        // Use a bounded wait so a wedged operation can't block dispose forever.
        var locked = await _writeLock.WaitAsync(TimeSpan.FromSeconds(5)).ConfigureAwait(false);
        try
        {
            _connection.Close();
            await _connection.DisposeAsync().ConfigureAwait(false);
        }
        finally
        {
            if (locked)
            {
                _writeLock.Release();
            }
            _writeLock.Dispose();
        }
    }
}
