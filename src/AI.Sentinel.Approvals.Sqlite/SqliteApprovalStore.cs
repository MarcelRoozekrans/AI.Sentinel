using System.Globalization;
using System.Runtime.CompilerServices;
using System.Text.Json;
using AI.Sentinel.Authorization;
using Microsoft.Data.Sqlite;

namespace AI.Sentinel.Approvals.Sqlite;

/// <summary>
/// Persistent <see cref="IApprovalStore"/> backed by a single-file SQLite database. State
/// survives process restarts. Mirrors <see cref="InMemoryApprovalStore"/>'s contract:
/// dedupe by <c>(caller_id, policy_name)</c>, terminal-state cleanup-on-observation, and
/// time-bound grants. <see cref="WaitForDecisionAsync"/> polls at
/// <see cref="SqliteApprovalStoreOptions.PollInterval"/>.
/// </summary>
public sealed class SqliteApprovalStore : IApprovalStore, IApprovalAdmin, IAsyncDisposable
{
    private readonly SqliteApprovalStoreOptions _options;
    private readonly SqliteConnection _connection;
    private readonly SemaphoreSlim _writeLock = new(1, 1);
    private readonly TimeProvider _time;
    private bool _disposed;

    public SqliteApprovalStore(SqliteApprovalStoreOptions options, TimeProvider? time = null)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentException.ThrowIfNullOrWhiteSpace(options.DatabasePath, nameof(options));
        _options = options;
        _time = time ?? TimeProvider.System;

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
        _connection.Open();

        // Schema bootstrap is synchronous in ctor — failure here surfaces immediately
        // rather than on first call.
        SqliteApprovalSchema.InitializeAsync(_connection, CancellationToken.None).GetAwaiter().GetResult();
    }

    public async ValueTask<ApprovalState> EnsureRequestAsync(
        ISecurityContext caller, ApprovalSpec spec, ApprovalContext context, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(caller);
        ArgumentNullException.ThrowIfNull(spec);
        ArgumentNullException.ThrowIfNull(context);
        ObjectDisposedException.ThrowIf(_disposed, this);

        await _writeLock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            var existing = await TryReadDedupeRowAsync(caller.Id, spec.PolicyName, ct).ConfigureAwait(false);
            if (existing is { } row)
            {
                if (row.State is ApprovalState.Denied)
                {
                    // Terminal observed — delete row inline so the next call creates fresh.
                    // Mirrors InMemoryApprovalStore's cleanup-on-observation semantic.
                    await DeleteRowAsync(row.Id, ct).ConfigureAwait(false);
                }
                return row.State;
            }

            var requestId = $"req-{Guid.NewGuid():N}";
            var now = _time.GetUtcNow();
            await InsertPendingAsync(requestId, caller, spec, context, now, ct).ConfigureAwait(false);
            return new ApprovalState.Pending(requestId, $"sentinel://approve/{requestId}", now);
        }
        finally
        {
            _writeLock.Release();
        }
    }

    private async Task<(string Id, ApprovalState State)?> TryReadDedupeRowAsync(
        string callerId, string policyName, CancellationToken ct)
    {
        using var sel = _connection.CreateCommand();
        sel.CommandText = """
            SELECT id, status, requested_at, approved_at, denied_at, deny_reason, grant_duration_ticks
            FROM approval_requests
            WHERE caller_id = $caller AND policy_name = $policy
            LIMIT 1;
            """;
        sel.Parameters.AddWithValue("$caller", callerId);
        sel.Parameters.AddWithValue("$policy", policyName);
        using var reader = await sel.ExecuteReaderAsync(ct).ConfigureAwait(false);
        if (!await reader.ReadAsync(ct).ConfigureAwait(false))
        {
            return null;
        }
        var id = reader.GetString(0);
        var state = RowToState(
            id: id,
            status: reader.GetString(1),
            requestedAtTicks: reader.GetInt64(2),
            hasApprovedAt: !reader.IsDBNull(3),
            approvedAtTicks: reader.IsDBNull(3) ? 0L : reader.GetInt64(3),
            hasDeniedAt: !reader.IsDBNull(4),
            deniedAtTicks: reader.IsDBNull(4) ? 0L : reader.GetInt64(4),
            denyReason: reader.IsDBNull(5) ? null : reader.GetString(5),
            grantDurationTicks: reader.GetInt64(6));
        return (id, state);
    }

    private async Task DeleteRowAsync(string id, CancellationToken ct)
    {
        using var del = _connection.CreateCommand();
        del.CommandText = "DELETE FROM approval_requests WHERE id = $id;";
        del.Parameters.AddWithValue("$id", id);
        await del.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
    }

    private async Task InsertPendingAsync(
        string requestId, ISecurityContext caller, ApprovalSpec spec, ApprovalContext context,
        DateTimeOffset now, CancellationToken ct)
    {
        using var ins = _connection.CreateCommand();
        ins.CommandText = """
            INSERT INTO approval_requests
                (id, caller_id, policy_name, tool_name, args_json, justification,
                 requested_at, grant_duration_ticks, status)
            VALUES
                ($id, $caller, $policy, $tool, $args, $just, $req, $dur, 'Pending');
            """;
        ins.Parameters.AddWithValue("$id", requestId);
        ins.Parameters.AddWithValue("$caller", caller.Id);
        ins.Parameters.AddWithValue("$policy", spec.PolicyName);
        ins.Parameters.AddWithValue("$tool", context.ToolName);
        ins.Parameters.AddWithValue("$args", SerializeArgs(context.Args));
        ins.Parameters.AddWithValue("$just", (object?)context.Justification ?? DBNull.Value);
        ins.Parameters.AddWithValue("$req", now.UtcTicks);
        ins.Parameters.AddWithValue("$dur", spec.GrantDuration.Ticks);
        await ins.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
    }

    public async ValueTask<ApprovalState> WaitForDecisionAsync(
        string requestId, TimeSpan timeout, CancellationToken ct)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(requestId);
        ObjectDisposedException.ThrowIf(_disposed, this);

        var deadline = _time.GetUtcNow() + timeout;
        while (true)
        {
            var current = await ReadStateAsync(requestId, ct).ConfigureAwait(false);
            if (current is null)
            {
                return new ApprovalState.Denied("unknown request", _time.GetUtcNow());
            }
            if (current is ApprovalState.Active or ApprovalState.Denied)
            {
                return current;
            }

            // Pending — bounded wait.
            if (_time.GetUtcNow() >= deadline)
            {
                return current;
            }

            try
            {
                await Task.Delay(_options.PollInterval, _time, ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return current;
            }
        }
    }

    public async ValueTask ApproveAsync(string requestId, string approverId, string? note, CancellationToken ct)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(requestId);
        ArgumentException.ThrowIfNullOrWhiteSpace(approverId);
        ObjectDisposedException.ThrowIf(_disposed, this);

        await _writeLock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            using var cmd = _connection.CreateCommand();
            cmd.CommandText = """
                UPDATE approval_requests
                   SET status = 'Active',
                       approved_at = $approvedAt,
                       approver_id = $approver,
                       approver_note = $note
                 WHERE id = $id AND status = 'Pending';
                """;
            cmd.Parameters.AddWithValue("$approvedAt", _time.GetUtcNow().UtcTicks);
            cmd.Parameters.AddWithValue("$approver", approverId);
            cmd.Parameters.AddWithValue("$note", (object?)note ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$id", requestId);
            await cmd.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
        }
        finally
        {
            _writeLock.Release();
        }
    }

    public async ValueTask DenyAsync(string requestId, string approverId, string reason, CancellationToken ct)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(requestId);
        ArgumentException.ThrowIfNullOrWhiteSpace(approverId);
        ObjectDisposedException.ThrowIf(_disposed, this);

        await _writeLock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            using var cmd = _connection.CreateCommand();
            cmd.CommandText = """
                UPDATE approval_requests
                   SET status = 'Denied',
                       denied_at = $deniedAt,
                       deny_reason = $reason,
                       approver_id = $approver
                 WHERE id = $id AND status = 'Pending';
                """;
            cmd.Parameters.AddWithValue("$deniedAt", _time.GetUtcNow().UtcTicks);
            cmd.Parameters.AddWithValue("$reason", reason ?? string.Empty);
            cmd.Parameters.AddWithValue("$approver", approverId);
            cmd.Parameters.AddWithValue("$id", requestId);
            await cmd.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
        }
        finally
        {
            _writeLock.Release();
        }
    }

    public async IAsyncEnumerable<PendingRequest> ListPendingAsync(
        [EnumeratorCancellation] CancellationToken ct)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        await _writeLock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            using var cmd = _connection.CreateCommand();
            cmd.CommandText = """
                SELECT id, caller_id, policy_name, tool_name, args_json, justification, requested_at
                FROM approval_requests
                WHERE status = 'Pending'
                ORDER BY requested_at ASC;
                """;
            using var reader = await cmd.ExecuteReaderAsync(ct).ConfigureAwait(false);
            while (await reader.ReadAsync(ct).ConfigureAwait(false))
            {
                var id = reader.GetString(0);
                var callerId = reader.GetString(1);
                var policyName = reader.GetString(2);
                var toolName = reader.GetString(3);
                var argsJson = reader.GetString(4);
                var justification = reader.IsDBNull(5) ? null : reader.GetString(5);
                var requestedAtTicks = reader.GetInt64(6);

                var args = DeserializeArgs(argsJson);
                var requestedAt = new DateTimeOffset(requestedAtTicks, TimeSpan.Zero);
                yield return new PendingRequest(id, callerId, policyName, toolName, args, requestedAt, justification);
            }
        }
        finally
        {
            _writeLock.Release();
        }
    }

    private async Task<ApprovalState?> ReadStateAsync(string requestId, CancellationToken ct)
    {
        await _writeLock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            using var cmd = _connection.CreateCommand();
            cmd.CommandText = """
                SELECT status, requested_at, approved_at, denied_at, deny_reason, grant_duration_ticks
                FROM approval_requests
                WHERE id = $id;
                """;
            cmd.Parameters.AddWithValue("$id", requestId);
            using var reader = await cmd.ExecuteReaderAsync(ct).ConfigureAwait(false);
            if (!await reader.ReadAsync(ct).ConfigureAwait(false))
            {
                return null;
            }
            return RowToState(
                id: requestId,
                status: reader.GetString(0),
                requestedAtTicks: reader.GetInt64(1),
                hasApprovedAt: !reader.IsDBNull(2),
                approvedAtTicks: reader.IsDBNull(2) ? 0L : reader.GetInt64(2),
                hasDeniedAt: !reader.IsDBNull(3),
                deniedAtTicks: reader.IsDBNull(3) ? 0L : reader.GetInt64(3),
                denyReason: reader.IsDBNull(4) ? null : reader.GetString(4),
                grantDurationTicks: reader.GetInt64(5));
        }
        finally
        {
            _writeLock.Release();
        }
    }

    private ApprovalState RowToState(
        string id,
        string status,
        long requestedAtTicks,
        bool hasApprovedAt,
        long approvedAtTicks,
        bool hasDeniedAt,
        long deniedAtTicks,
        string? denyReason,
        long grantDurationTicks)
    {
        var now = _time.GetUtcNow();
        var requestedAt = new DateTimeOffset(requestedAtTicks, TimeSpan.Zero);

        if (string.Equals(status, "Active", StringComparison.Ordinal))
        {
            if (hasApprovedAt)
            {
                var approvedAt = new DateTimeOffset(approvedAtTicks, TimeSpan.Zero);
                var expiresAt = approvedAt + TimeSpan.FromTicks(grantDurationTicks);
                if (expiresAt > now)
                {
                    return new ApprovalState.Active(expiresAt);
                }
            }
            return new ApprovalState.Denied("expired", now);
        }
        if (string.Equals(status, "Denied", StringComparison.Ordinal))
        {
            var deniedAt = hasDeniedAt
                ? new DateTimeOffset(deniedAtTicks, TimeSpan.Zero)
                : now;
            return new ApprovalState.Denied(denyReason ?? "denied", deniedAt);
        }
        return new ApprovalState.Pending(id, $"sentinel://approve/{id}", requestedAt);
    }

    private static string SerializeArgs(JsonElement args)
    {
        // Default JsonElement (ValueKind == Undefined) — store as JSON null so we can round-trip.
        if (args.ValueKind == JsonValueKind.Undefined)
        {
            return "null";
        }
        return args.GetRawText();
    }

    private static JsonElement DeserializeArgs(string json)
    {
        using var doc = JsonDocument.Parse(json);
        return doc.RootElement.Clone();
    }

    public async ValueTask DisposeAsync()
    {
        if (_disposed) return;
        _disposed = true;

        // Acquire the write lock before tearing down the connection so any
        // concurrent op that's already past the _disposed check but not yet
        // at WaitAsync can't observe a disposed connection / semaphore.
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
