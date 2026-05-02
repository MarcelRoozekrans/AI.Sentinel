using System.Globalization;
using System.Text.Json;
using AI.Sentinel.Approvals;
using AI.Sentinel.Audit;
using AI.Sentinel.Authorization;
using AI.Sentinel.ClaudeCode;
using AI.Sentinel.Domain;
using AI.Sentinel.Mcp.Authorization;
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
        TimeSpan? approvalWait = null) =>
        next => (ctx, ct) => InvokeAsync(pipeline, maxScanBytes, stderr, guard, audit, callerResolver,
            approvalStore, approvalWait, next, ctx, ct);

    private static async ValueTask<CallToolResult> InvokeAsync(
        SentinelPipeline pipeline,
        int maxScanBytes,
        TextWriter stderr,
        IToolCallGuard? guard,
        IAuditStore? audit,
        Func<CallToolRequestParams, ISecurityContext>? callerResolver,
        IApprovalStore? approvalStore,
        TimeSpan? approvalWait,
        McpRequestHandler<CallToolRequestParams, CallToolResult> next,
        RequestContext<CallToolRequestParams> ctx,
        CancellationToken ct)
    {
        var req = ctx.Params ?? throw new McpProtocolException(
            "missing tool call parameters", McpErrorCode.InvalidParams);

        if (guard is not null)
        {
            await AuthorizeAsync(guard, audit, callerResolver, approvalStore, approvalWait, req, stderr, ct).ConfigureAwait(false);
        }

        var requestMessages = MessageBuilder.BuildToolCallRequest(req, maxScanBytes);
        var preError = await ScanSafelyAsync(pipeline, requestMessages, stderr, phase: "request", ct).ConfigureAwait(false);
        await BlockIfThreatAsync(preError, req.Name, stderr, phase: "request").ConfigureAwait(false);

        var result = await next(ctx, ct).ConfigureAwait(false);

        var responseMessages = MessageBuilder.BuildToolCallResponse(req, result, maxScanBytes);
        var postError = await ScanSafelyAsync(pipeline, responseMessages, stderr, phase: "response", ct).ConfigureAwait(false);
        await BlockIfThreatAsync(postError, req.Name, stderr, phase: "response").ConfigureAwait(false);

        await stderr.WriteLineAsync(
            $"[sentinel-mcp] event=tools/call decision=Allow tool={req.Name}"
        ).ConfigureAwait(false);
        return result;
    }

    private static async ValueTask AuthorizeAsync(
        IToolCallGuard guard,
        IAuditStore? audit,
        Func<CallToolRequestParams, ISecurityContext>? callerResolver,
        IApprovalStore? approvalStore,
        TimeSpan? approvalWait,
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
            await HandleRequireApprovalAsync(guard, audit, approvalStore, approvalWait, caller, args, req, r, stderr, ct).ConfigureAwait(false);
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
                sender:     new AgentId(string.IsNullOrWhiteSpace(caller.Id) ? "anonymous" : caller.Id),
                receiver:   new AgentId(req.Name),
                session:    SessionId.New(),
                callerId:   caller.Id,
                roles:      caller.Roles,
                toolName:   req.Name,
                policyName: policyName,
                reason:     reason,
                policyCode: policyCode);
            await audit.AppendAsync(entry, ct).ConfigureAwait(false);
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
        IApprovalStore? approvalStore,
        TimeSpan? approvalWait,
        ISecurityContext caller,
        JsonElement args,
        CallToolRequestParams req,
        AuthorizationDecision.RequireApprovalDecision r,
        TextWriter stderr,
        CancellationToken ct)
    {
        if (audit is not null)
        {
            var approvalEntry = AuditEntryAuthorizationExtensions.AuthorizationDeny(
                sender:     new AgentId(string.IsNullOrWhiteSpace(caller.Id) ? "anonymous" : caller.Id),
                receiver:   new AgentId(req.Name),
                session:    SessionId.New(),
                callerId:   caller.Id,
                roles:      caller.Roles,
                toolName:   req.Name,
                policyName: r.PolicyName,
                reason:     $"approval required (requestId={r.RequestId})",
                policyCode: SentinelDenyCodes.ApprovalRequired);
            await audit.AppendAsync(approvalEntry, ct).ConfigureAwait(false);
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
        CancellationToken ct)
    {
        try
        {
            return await pipeline.ScanMessagesAsync(messages, ct: ct).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            await stderr.WriteLineAsync(
                $"[sentinel-mcp] event=tools/call decision=FailOpen phase={phase} reason={ex.GetType().Name}:{ex.Message}"
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
