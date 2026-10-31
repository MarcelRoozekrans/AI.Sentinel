using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using AI.Sentinel.Http;
using Microsoft.Extensions.Logging;
using ZeroAlloc.Authorization;

namespace AI.Sentinel.Approvals.Notifications;

/// <summary>
/// Wraps an <see cref="IApprovalStore"/> and posts one JSON payload to a webhook when the inner store reports a newly
/// created request. The POST is awaited, with a fixed timeout and no retry, so a short-lived hook process has sent it
/// before it exits. A failure is logged and never changes the state <see cref="EnsureRequestAsync"/> returns.
/// </summary>
internal class NotifyingApprovalStore : IApprovalStore, IApprovalStoreDecorator
{
    /// <summary>How long one POST may take.</summary>
    internal static readonly TimeSpan PostTimeout = TimeSpan.FromSeconds(3);

    // One handler for the process: a hook posts once and exits, a long-lived host posts rarely, and a handler per
    // notifier would leak sockets.
    private static readonly SocketsHttpHandler SharedHandler = new()
    {
        PooledConnectionLifetime = TimeSpan.FromMinutes(5),
        // A redirect would turn the POST into a GET and send the custom headers to another host; a 3xx is a failure.
        AllowAutoRedirect = false,
    };

    // One client over that handler too: Resolve wraps a plain store on every call, and a client each would never be disposed.
    private static readonly HttpClient SharedClient = NewClient(SharedHandler);

    private readonly IApprovalStore _inner;
    private readonly ApprovalNotifierSettings _settings;
    private readonly HttpClient _http;
    private readonly ILogger? _logger;

    internal NotifyingApprovalStore(
        IApprovalStore inner, ApprovalNotifierSettings settings, HttpMessageHandler handler, ILogger? logger)
    {
        ArgumentNullException.ThrowIfNull(inner);
        ArgumentNullException.ThrowIfNull(settings);
        ArgumentNullException.ThrowIfNull(handler);
        _inner = inner;
        _settings = settings;
        // The timeout is per request, through a linked token; HttpClient.Timeout would be a second, hidden one.
        _http = ReferenceEquals(handler, SharedHandler) ? SharedClient : NewClient(handler);
        _logger = logger;
    }

    private static HttpClient NewClient(HttpMessageHandler handler) =>
        new(handler, disposeHandler: false) { Timeout = Timeout.InfiniteTimeSpan };

    /// <inheritdoc />
    public IApprovalStore Inner => _inner;

    /// <summary>
    /// Wraps <paramref name="inner"/>, as the admin variant when it has an admin surface, over the process-wide handler.
    /// </summary>
    /// <param name="inner">The store to wrap.</param>
    /// <param name="settings">The notifier settings.</param>
    /// <param name="logger">Where a failed POST is logged, or <see langword="null"/> for nowhere.</param>
    internal static IApprovalStore Wrap(IApprovalStore inner, ApprovalNotifierSettings settings, ILogger? logger) =>
        inner is IApprovalAdmin
            ? new NotifyingApprovalAdminStore(inner, settings, SharedHandler, logger)
            : new NotifyingApprovalStore(inner, settings, SharedHandler, logger);

    public async ValueTask<ApprovalState> EnsureRequestAsync(
        ISecurityContext caller, ApprovalSpec spec, ApprovalContext context, CancellationToken ct)
    {
        var state = await _inner.EnsureRequestAsync(caller, spec, context, ct).ConfigureAwait(false);
        if (state is ApprovalState.Pending { IsNew: true } pending)
        {
            await NotifyAsync(pending, caller.Id, spec.PolicyName, context, ct).ConfigureAwait(false);
        }
        return state;
    }

    public ValueTask<ApprovalState> WaitForDecisionAsync(string requestId, TimeSpan timeout, CancellationToken ct) =>
        _inner.WaitForDecisionAsync(requestId, timeout, ct);

    private async ValueTask NotifyAsync(
        ApprovalState.Pending pending, string callerId, string policy, ApprovalContext context, CancellationToken ct)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(PostTimeout);
        try
        {
            var payload = ApprovalNotification.Create(pending, callerId, policy, context, _settings);
            var json = JsonSerializer.Serialize(payload, ApprovalNotificationJsonContext.Default.ApprovalNotification);
            using var request = new HttpRequestMessage(HttpMethod.Post, _settings.Url)
            {
                Content = new StringContent(json, Encoding.UTF8, "application/json"),
            };
            foreach (var (name, value) in _settings.Headers)
            {
                // The config loader rejects every name the request headers refuse, so this is not expected to fail.
                if (!request.Headers.TryAddWithoutValidation(name, value))
                {
                    _logger?.LogWarning(
                        "Approval webhook header {HeaderName} was not added for request {RequestId}.", name, pending.RequestId);
                }
            }

            // The body is never read, so the connection is released as soon as the headers are in.
            using var response = await _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, timeout.Token)
                .ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                _logger?.LogWarning(
                    "Approval webhook {Endpoint} answered {StatusCode} for request {RequestId}.",
                    SafeHttp.DescribeOrigin(_settings.Url), (int)response.StatusCode, pending.RequestId);
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
#pragma warning disable CA1031 // A webhook failure must never fail or change the approval; it is logged.
        catch (Exception ex)
#pragma warning restore CA1031
        {
            // Only the exception type: its message can carry the URL with its query string.
            _logger?.LogWarning(
                "Approval webhook {Endpoint} failed for request {RequestId}: {Failure}.",
                SafeHttp.DescribeOrigin(_settings.Url), pending.RequestId,
                ex is OperationCanceledException ? "timed out" : ex.GetType().Name);
        }
    }
}
