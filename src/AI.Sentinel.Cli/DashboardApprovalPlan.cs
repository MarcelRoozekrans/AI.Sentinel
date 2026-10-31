using System.Text.Json;
using AI.Sentinel.Approvals;
using AI.Sentinel.Approvals.Configuration;
using AI.Sentinel.Approvals.Sqlite;
using Microsoft.Extensions.DependencyInjection;

namespace AI.Sentinel.Cli;

/// <summary>What <c>sentinel dashboard</c> does about approvals, decided once from the approval config before anything is opened.</summary>
internal sealed record DashboardApprovalPlan(DashboardApprovalMode Mode, string? DatabasePath, string? Reason)
{
    private static readonly DashboardApprovalPlan None = new(DashboardApprovalMode.Off, null, null);

    /// <summary>The audit file is opened writable only when this dashboard records decisions itself.</summary>
    internal bool NeedsWritableAudit => Mode == DashboardApprovalMode.Sqlite;

    /// <summary>Routes the root approval link and the shared approval pages should exist for.</summary>
    internal bool ServesApprovals => Mode != DashboardApprovalMode.Off;

    /// <summary>
    /// Reads the approval config named by <paramref name="settings"/>. Returns <c>null</c> after writing the reason to
    /// <paramref name="stderr"/> when the config cannot be used.
    /// </summary>
    internal static async Task<DashboardApprovalPlan?> LoadAsync(DashboardSettings settings, TextWriter stderr)
    {
        var path = settings.ApprovalConfigPath;
        if (path is null)
        {
            return NoConfig(settings);
        }

        ApprovalConfig config;
        try
        {
            config = ApprovalConfigLoader.Load(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException or JsonException)
        {
            await stderr.WriteLineAsync($"Could not load the approval config {path}: {ex.Message}").ConfigureAwait(false);
            return null;
        }

        switch (ApprovalBackendSelector.GetBackend(config))
        {
            case ApprovalBackendKind.Sqlite:
                return new DashboardApprovalPlan(DashboardApprovalMode.Sqlite, config.DatabasePath, null);
            case ApprovalBackendKind.EntraPim:
                return new DashboardApprovalPlan(DashboardApprovalMode.EntraPim, null, null);
            case ApprovalBackendKind.InMemory when settings.ApprovalConfigExplicit:
                await stderr.WriteLineAsync(
                    $"The approval config {path} uses the in-memory backend, which keeps nothing between processes. Use the sqlite backend to approve from the dashboard.").ConfigureAwait(false);
                return null;
            case ApprovalBackendKind.InMemory:
                return new DashboardApprovalPlan(DashboardApprovalMode.Off, null, "the in-memory approval backend keeps nothing between processes");
            default:
                return new DashboardApprovalPlan(DashboardApprovalMode.Off, null, "the approval config backend is none");
        }
    }

    /// <summary>Registers the approval pieces on <paramref name="services"/>. Call after the audit store is registered.</summary>
    internal void Register(IServiceCollection services)
    {
        switch (Mode)
        {
            case DashboardApprovalMode.Sqlite:
                services.AddSentinelSqliteApprovalStore(o => o.DatabasePath = DatabasePath!);
                break;
            case DashboardApprovalMode.EntraPim:
                services.AddSingleton<ExternalApprovalPortal>();
                break;
        }
    }

    /// <summary>The <c>Approvals:</c> startup line. It names the header but never a header value.</summary>
    internal string Describe(DashboardSettings settings) => Mode switch
    {
        DashboardApprovalMode.EntraPim => "Approvals: managed in Entra PIM",
        DashboardApprovalMode.Sqlite => $"Approvals: sqlite {DatabasePath}, {DescribeApprover(settings)}",
        _ => Reason is null ? "Approvals: off" : $"Approvals: off ({Reason})",
    };

    private static DashboardApprovalPlan NoConfig(DashboardSettings settings)
    {
        if (settings.TrustedProxies.Count > 0)
        {
            return new DashboardApprovalPlan(DashboardApprovalMode.Off, null, "no approval config, so --trusted-proxy has nothing to approve");
        }
        return settings.LocalApprover
            ? new DashboardApprovalPlan(DashboardApprovalMode.Off, null, "no approval config, so --local-approver has nothing to approve")
            : None;
    }

    private static string DescribeApprover(DashboardSettings settings)
    {
        if (settings.TrustedProxies.Count > 0)
        {
            return $"approver from {settings.UserHeader} via {string.Join(", ", settings.TrustedProxies.Select(p => p.ToString()))}";
        }
        return settings.LocalApprover
            ? $"approver is the local user {Environment.UserName}"
            : "no approver configured, so approve and deny are refused";
    }
}
