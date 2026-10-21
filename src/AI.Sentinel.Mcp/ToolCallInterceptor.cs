using System.Globalization;
using System.Text.Json;
using AI.Sentinel.Approvals;
using AI.Sentinel.Audit;
using AI.Sentinel.Authorization;
using AI.Sentinel.ClaudeCode;
using AI.Sentinel.Domain;
using AI.Sentinel.Mcp.Authorization;
using AI.Sentinel.Redaction;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;
using ZeroAlloc.Authorization;

namespace AI.Sentinel.Mcp;

/// <summary>
/// Builds the <see cref="McpRequestFilter{TParams,TResult}"/> that pre-scans
/// <c>tools/call</c> arguments and post-scans the result via
/// <see cref="SentinelPipeline.ScanMessagesAsync"/>.
/// </summary>
/// <remarks>
/// Fail-open semantics for pipeline bugs: any exception out of
/// <see cref="SentinelPipeline.ScanMessagesAsync"/> is logged to <c>stderr</c>
/// and the call forwards. Only a <see cref="SentinelError.ThreatDetected"/>
/// yields a block. Blocks raise <see cref="McpProtocolException"/> with
/// <see cref="McpErrorCode.InternalError"/> so the SDK emits a JSON-RPC error
/// (plain <see cref="McpException"/> would be swallowed by the tool-call
/// wrapper into a <see cref="CallToolResult"/> with <c>IsError=true</c>).
/// When an <see cref="IToolCallGuard"/> is supplied it runs BEFORE the request
/// pre-scan; deny decisions are written to the optional <see cref="IAuditStore"/>
/// (when provided) and then surfaced as an <see cref="McpProtocolException"/>.
/// When a <see cref="PlaceholderStore"/> is supplied, the result's text blocks, allowlisted embedded text resources
/// and structured content are redacted before they reach the agent, and the redacted result is what the response
/// scan judges. Without one, the result is scanned as in 3.0 and a finding falls back to its severity action.
/// </remarks>
internal static class ToolCallInterceptor
{
    // Static cache: parsed once at type init, kept alive for the process. Avoids per-call JsonDocument allocation.
    private static readonly JsonElement EmptyJsonObject = JsonDocument.Parse("{}").RootElement;

    public static McpRequestFilter<CallToolRequestParams, CallToolResult> Create(
        SentinelPipeline pipeline,
        int maxScanBytes,
        TextWriter stderr,
        IToolCallGuard? guard = null,
        IAuditStore? audit = null,
        Func<CallToolRequestParams, ISecurityContext>? callerResolver = null,
        IApprovalStore? approvalStore = null,
        TimeSpan? approvalWait = null,
        IReadOnlyList<IAuditForwarder>? forwarders = null,
        SessionId? sessionId = null,
        PlaceholderStore? placeholders = null)
    {
        var forwarderSnapshot = AuditForwarding.Snapshot(forwarders);
        var redaction = placeholders is null ? null : new RedactionSetup(placeholders, ResourceReadInterceptor.ParseMimeAllowlist());
        return next => (ctx, ct) => InvokeAsync(pipeline, maxScanBytes, stderr, guard, audit, forwarderSnapshot,
            callerResolver, approvalStore, approvalWait, sessionId, redaction, next, ctx, ct);
    }

    /// <summary>The proxy's placeholder store and the MIME allowlist for embedded text resources.</summary>
    private sealed record RedactionSetup(PlaceholderStore Placeholders, HashSet<string> AllowedMimes);

    private static async ValueTask<CallToolResult> InvokeAsync(
        SentinelPipeline pipeline,
        int maxScanBytes,
        TextWriter stderr,
        IToolCallGuard? guard,
        IAuditStore? audit,
        IAuditForwarder[] forwarders,
        Func<CallToolRequestParams, ISecurityContext>? callerResolver,
        IApprovalStore? approvalStore,
        TimeSpan? approvalWait,
        SessionId? sessionId,
        RedactionSetup? redaction,
        McpRequestHandler<CallToolRequestParams, CallToolResult> next,
        RequestContext<CallToolRequestParams> ctx,
        CancellationToken ct)
    {
        var req = ctx.Params ?? throw new McpProtocolException(
            "missing tool call parameters", McpErrorCode.InvalidParams);

        if (guard is not null)
        {
            await AuthorizeAsync(guard, audit, forwarders, callerResolver, approvalStore, approvalWait, sessionId, req, stderr, ct).ConfigureAwait(false);
        }

        var requestMessages = MessageBuilder.BuildToolCallRequest(req, maxScanBytes);
        var preError = await ScanSafelyAsync(pipeline, requestMessages, stderr, phase: "request", sessionId, ct).ConfigureAwait(false);
        await BlockIfThreatAsync(preError, req.Name, stderr, phase: "request").ConfigureAwait(false);

        var result = await next(ctx, ct).ConfigureAwait(false);

        if (redaction is not null)
        {
            return await RedactResponseAsync(pipeline, maxScanBytes, stderr, sessionId, redaction, req, result, ct).ConfigureAwait(false);
        }

        var responseMessages = MessageBuilder.BuildToolCallResponse(req, result, maxScanBytes);
        var postError = await ScanSafelyAsync(pipeline, responseMessages, stderr, phase: "response", sessionId, ct).ConfigureAwait(false);
        await BlockIfThreatAsync(postError, req.Name, stderr, phase: "response").ConfigureAwait(false);

        await stderr.WriteLineAsync(
            $"[sentinel-mcp] event=tools/call decision=Allow tool={req.Name}"
        ).ConfigureAwait(false);
        return result;
    }

    /// <summary>
    /// Redacts the result in place and scans the redacted copy with the arguments as context. A threat blocks and
    /// nothing is written back or audited as redacted. Otherwise the redacted content is written back, its
    /// placeholders are registered and the redactions are audited. A pipeline failure fails open, as the 3.0 scan
    /// does, and logs only the exception type, because its message can carry the value.
    /// </summary>
    private static async ValueTask<CallToolResult> RedactResponseAsync(
        SentinelPipeline pipeline,
        int maxScanBytes,
        TextWriter stderr,
        SessionId? sessionId,
        RedactionSetup redaction,
        CallToolRequestParams req,
        CallToolResult result,
        CancellationToken ct)
    {
        // The result is deserialized fresh for this request, so it is rewritten in place.
        var (content, apply, oversize) = MessageBuilder.CollectRedactable(result, maxScanBytes, redaction.AllowedMimes);

        HostRedactionResult scanned;
        try
        {
            scanned = await McpRedaction.RedactAndScanAsync(
                pipeline, redaction.Placeholders, MessageBuilder.BuildToolCallRequest(req, maxScanBytes),
                content, oversize, Microsoft.Extensions.AI.ChatRole.Assistant, sessionId, ct).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            await stderr.WriteLineAsync(
                $"[sentinel-mcp] event=tools/call decision=FailOpen phase=response reason={ex.GetType().Name}"
            ).ConfigureAwait(false);
            return result;
        }

        await BlockIfThreatAsync(scanned.Error, req.Name, stderr, phase: "response").ConfigureAwait(false);

        McpRedaction.WriteBack(scanned, apply, redaction.Placeholders);
        var redactedSuffix = string.Empty;
        if (scanned.Redacted)
        {
            await AppendRedactionsSafelyAsync(pipeline, scanned, stderr, ct).ConfigureAwait(false);
            redactedSuffix = " redacted=" + McpRedaction.TotalRedacted(scanned).ToString(CultureInfo.InvariantCulture);
        }

        if (scanned.Error is SentinelError.RateLimitExceeded)
        {
            redactedSuffix += " reason=rate_limited";
        }

        await stderr.WriteLineAsync(
            $"[sentinel-mcp] event=tools/call decision=Allow tool={req.Name}{redactedSuffix}"
        ).ConfigureAwait(false);
        return result;
    }

    private static async ValueTask AppendRedactionsSafelyAsync(
        SentinelPipeline pipeline, HostRedactionResult scanned, TextWriter stderr, CancellationToken ct)
    {
        try
        {
            await pipeline.AppendRedactionsAsync(scanned, scanned.SessionId, ct).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            await stderr.WriteLineAsync(
                $"[sentinel-mcp] event=tools/call decision=AuditFailed phase=redaction reason={ex.GetType().Name}"
            ).ConfigureAwait(false);
        }
    }

    private static async ValueTask AuthorizeAsync(
        IToolCallGuard guard,
        IAuditStore? audit,
        IAuditForwarder[] forwarders,
        Func<CallToolRequestParams, ISecurityContext>? callerResolver,
        IApprovalStore? approvalStore,
        TimeSpan? approvalWait,
        SessionId? sessionId,
        CallToolRequestParams req,
        TextWriter stderr,
        CancellationToken ct)
    {
        var caller = callerResolver?.Invoke(req) ?? EnvironmentSecurityContext.FromEnvironment();
        var args = ToJsonElement(req.Arguments);
        var decision = await guard.AuthorizeAsync(caller, req.Name, args, ct).ConfigureAwait(false);
        if (decision.Allowed) return;

        if (decision is AuthorizationDecision.RequireApprovalDecision r)
        {
            await HandleRequireApprovalAsync(guard, audit, forwarders, approvalStore, approvalWait, caller, args, sessionId, req, r, stderr, ct).ConfigureAwait(false);
            return;
        }

        // Defensive `??` below: see AuthorizationChatClient.AuditDenyAsync for rationale.
        var deny = decision as AuthorizationDecision.DenyDecision;
        var policyName = deny?.PolicyName ?? "?";
        var reason = deny?.Reason ?? "?";
        var policyCode = deny?.Code ?? SentinelDenyCodes.PolicyDenied;

        if (audit is not null)
        {
            var entry = AuditEntryAuthorizationExtensions.AuthorizationDeny(
                sender: new AgentId(string.IsNullOrWhiteSpace(caller.Id) ? "anonymous" : caller.Id),
                receiver: new AgentId(req.Name),
                session: sessionId ?? SessionId.New(),
                callerId: caller.Id,
                roles: caller.Roles,
                toolName: req.Name,
                policyName: policyName,
                reason: reason,
                policyCode: policyCode);
            await audit.AppendAndForwardAsync(entry, forwarders, ct).ConfigureAwait(false);
        }

        await stderr.WriteLineAsync(
            $"[sentinel-mcp] event=tools/call decision=AuthzDeny tool={req.Name} caller={caller.Id} policy={policyName}"
        ).ConfigureAwait(false);

        throw new McpProtocolException(
            $"Authorization denied [{policyCode}] by policy '{policyName}': {reason}",
            McpErrorCode.InvalidRequest);
    }

    /// <summary>
    /// Handles a <see cref="AuthorizationDecision.RequireApprovalDecision"/>: audits as AUTHZ-DENY
    /// with a request-id reason, optionally blocks on <see cref="IApprovalStore.WaitForDecisionAsync"/>
    /// (when the proxy was started with <c>SENTINEL_MCP_APPROVAL_WAIT_SEC</c>), and finally throws an
    /// <see cref="McpProtocolException"/> carrying the receipt text. Returns normally only when the
    /// wait re-evaluated to Allow.
    /// </summary>
    private static async ValueTask HandleRequireApprovalAsync(
        IToolCallGuard guard,
        IAuditStore? audit,
        IAuditForwarder[] forwarders,
        IApprovalStore? approvalStore,
        TimeSpan? approvalWait,
        ISecurityContext caller,
        JsonElement args,
        SessionId? sessionId,
        CallToolRequestParams req,
        AuthorizationDecision.RequireApprovalDecision r,
        TextWriter stderr,
        CancellationToken ct)
    {
        if (audit is not null)
        {
            var approvalEntry = AuditEntryAuthorizationExtensions.AuthorizationDeny(
                sender: new AgentId(string.IsNullOrWhiteSpace(caller.Id) ? "anonymous" : caller.Id),
                receiver: new AgentId(req.Name),
                session: sessionId ?? SessionId.New(),
                callerId: caller.Id,
                roles: caller.Roles,
                toolName: req.Name,
                policyName: r.PolicyName,
                reason: $"approval required (requestId={r.RequestId})",
                policyCode: SentinelDenyCodes.ApprovalRequired);
            await audit.AppendAndForwardAsync(approvalEntry, forwarders, ct).ConfigureAwait(false);
        }

        if (approvalStore is not null && approvalWait is { } wait && wait > TimeSpan.Zero)
        {
            await stderr.WriteLineAsync(
                $"[sentinel-mcp] event=tools/call decision=ApprovalWait tool={req.Name} caller={caller.Id} requestId={r.RequestId} waitSec={wait.TotalSeconds.ToString("0", CultureInfo.InvariantCulture)}"
            ).ConfigureAwait(false);

            var state = await approvalStore.WaitForDecisionAsync(r.RequestId, wait, ct).ConfigureAwait(false);
            if (state is ApprovalState.Active)
            {
                // Re-evaluate after activation; second guard call sees the active grant.
                var second = await guard.AuthorizeAsync(caller, req.Name, args, ct).ConfigureAwait(false);
                if (second.Allowed) return;
            }
        }

        await stderr.WriteLineAsync(
            $"[sentinel-mcp] event=tools/call decision=ApprovalRequired tool={req.Name} caller={caller.Id} policy={r.PolicyName} requestId={r.RequestId}"
        ).ConfigureAwait(false);

        throw new McpProtocolException(
            ApprovalReceipt.Format(req.Name, r),
            McpErrorCode.InvalidRequest);
    }

    private static JsonElement ToJsonElement(IDictionary<string, JsonElement>? args)
    {
        if (args is null || args.Count == 0)
        {
            return EmptyJsonObject;
        }

        var json = JsonSerializer.Serialize(args, McpJsonContext.Default.IDictionaryStringJsonElement);
        using var doc = JsonDocument.Parse(json);
        return doc.RootElement.Clone();
    }

    private static async ValueTask<SentinelError?> ScanSafelyAsync(
        SentinelPipeline pipeline,
        Microsoft.Extensions.AI.ChatMessage[] messages,
        TextWriter stderr,
        string phase,
        SessionId? sessionId,
        CancellationToken ct)
    {
        try
        {
            return await pipeline.ScanMessagesAsync(messages, ct: ct, sessionId: sessionId).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            await stderr.WriteLineAsync(
                $"[sentinel-mcp] event=tools/call decision=FailOpen phase={phase} reason={ex.GetType().Name}"
            ).ConfigureAwait(false);
            return null;
        }
    }

    private static async ValueTask BlockIfThreatAsync(
        SentinelError? error, string toolName, TextWriter stderr, string phase)
    {
        if (error is not SentinelError.ThreatDetected threat) return;

        await stderr.WriteLineAsync(
            $"[sentinel-mcp] event=tools/call decision=Block tool={toolName} detector={threat.Result.DetectorId.Value} severity={threat.Result.Severity} phase={phase}"
        ).ConfigureAwait(false);

        throw new McpProtocolException(
            $"Blocked by AI.Sentinel: {threat.Result.DetectorId.Value} {threat.Result.Severity}: {threat.Result.Reason}",
            McpErrorCode.InternalError);
    }
}
