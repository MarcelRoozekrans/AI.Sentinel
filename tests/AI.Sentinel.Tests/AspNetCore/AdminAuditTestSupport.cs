using AI.Sentinel.AspNetCore.AdminAudit;
using AI.Sentinel.Profiles;

namespace AI.Sentinel.Tests.AspNetCore;

internal static class AdminAuditTestSupport
{
    public static readonly DateTimeOffset T0 = new(2026, 11, 23, 9, 0, 0, TimeSpan.Zero);

    public static ProfileSigningKey NewKey() => ProfileSigningKey.Generate();

    public static AdminAuditLog NewLog(ProfileSigningKey key, SettableTime time, IAdminAuditStore? store = null) =>
        new(store ?? new InMemoryAdminAuditStore(), new ProfileSigningKeys(key), time);

    public static async Task SeedAsync(AdminAuditLog log, string organisation, int count, CancellationToken ct)
    {
        for (var i = 0; i < count; i++)
        {
            await log.RecordAsync(organisation, AdminAuditAction.Approve, $"user-{i}", $"request-{i}", AdminAuditChannel.Web, ct);
        }
    }

    public static PinnedProfileKeys Pin(ProfileSigningKey key) => PinnedProfileKeys.Create([key.PublicKey]);
}
