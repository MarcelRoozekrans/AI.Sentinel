using System.Globalization;
using System.Text;
using AI.Sentinel.Audit;
using Azure.Identity;
using Azure.Monitor.Ingestion;

namespace AI.Sentinel.AzureSentinel;

/// <summary>
/// Forwards audit entries to Azure Sentinel via the Logs Ingestion API. Failures are
/// SWALLOWED (logged to stderr, never propagated) so audit shipping never breaks the
/// host. Should be wrapped with <see cref="BufferingAuditForwarder{T}"/> — per-entry
/// HTTP roundtrips would crater throughput.
/// </summary>
public sealed class AzureSentinelAuditForwarder : IAuditForwarder
{
    private readonly ILogsIngestionClientWrapper _client;
    private readonly string _ruleId;
    private readonly string _streamName;

    /// <summary>Production constructor: builds a real <see cref="LogsIngestionClient"/> using <see cref="DefaultAzureCredential"/> when no credential is supplied.</summary>
    public AzureSentinelAuditForwarder(AzureSentinelAuditForwarderOptions options)
        : this(BuildClient(options), options)
    {
    }

    internal AzureSentinelAuditForwarder(ILogsIngestionClientWrapper client, AzureSentinelAuditForwarderOptions options)
    {
        ArgumentNullException.ThrowIfNull(client);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentException.ThrowIfNullOrWhiteSpace(options.DcrImmutableId, nameof(options));
        ArgumentException.ThrowIfNullOrWhiteSpace(options.StreamName, nameof(options));
        if (options.DcrEndpoint is null)
        {
            throw new ArgumentException("DcrEndpoint must be set.", nameof(options));
        }
        _client = client;
        _ruleId = options.DcrImmutableId;
        _streamName = options.StreamName;
    }

    private static ILogsIngestionClientWrapper BuildClient(AzureSentinelAuditForwarderOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (options.DcrEndpoint is null)
        {
            throw new ArgumentException("DcrEndpoint must be set.", nameof(options));
        }
        var credential = options.Credential ?? new DefaultAzureCredential();
        return new LogsIngestionClientWrapper(new LogsIngestionClient(options.DcrEndpoint, credential));
    }

    /// <inheritdoc />
    public async ValueTask SendAsync(IReadOnlyList<AuditEntry> batch, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(batch);
        if (batch.Count == 0)
        {
            return;
        }

        try
        {
            await _client.UploadAsync(_ruleId, _streamName, batch, ct).ConfigureAwait(false);
        }
#pragma warning disable CA1031 // Defence-in-depth: a forwarder must NEVER propagate; failures escape the BufferingAuditForwarder<T>.FlushAsync wrapper too late on shutdown.
        catch (Exception ex)
#pragma warning restore CA1031
        {
            LogStderr("send_error", ex.GetType().Name, batch.Count);
        }
    }

    /// <summary>Writes a key=value line to stderr. Mirrors <c>BufferingAuditForwarder</c>'s pattern; lives here so this package does not depend on <c>AI.Sentinel.Mcp</c>.</summary>
    private static void LogStderr(string action, string error, int count)
    {
        var sb = new StringBuilder();
        sb.Append("event=audit_forward action=").Append(action)
          .Append(" forwarder=AzureSentinel error=").Append(error)
          .Append(" count=").Append(count.ToString(CultureInfo.InvariantCulture));
        Console.Error.WriteLine(sb.ToString());
    }
}
