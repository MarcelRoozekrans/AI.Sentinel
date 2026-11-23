using System.CommandLine;
using System.Globalization;
using AI.Sentinel.AspNetCore.AdminAudit;
using AI.Sentinel.Profiles;

namespace AI.Sentinel.Cli;

/// <summary>
/// <c>sentinel audit-verify</c>: verifies an export of the administrative audit log offline. It checks the chain, the
/// signed head against pinned public keys, the organisation and, when given, a checkpoint from an earlier export.
/// Exit codes: 0 when the export verified, 1 for a usage error or an unreadable file, 2 when verification failed.
/// </summary>
public static class AdminAuditVerifyCommand
{
    private const int Failed = 2;

    public static Command Build()
    {
        var file = new Argument<string>("export") { Description = "The audit log export file to verify." };
        var organisation = new Option<string>("--organisation") { Description = "The organisation the export must be for.", Required = true };
        var keys = new Option<string[]>("--public-key")
        {
            Description = "A pinned Ed25519 public key of the deployment, base64. Repeat for several keys.",
            Required = true,
            AllowMultipleArgumentsPerToken = true,
        };
        var count = new Option<long?>("--checkpoint-count") { Description = "Entry count of an earlier export or verify run." };
        var hash = new Option<string?>("--checkpoint-hash") { Description = "Last hash of that earlier export." };
        var time = new Option<string?>("--checkpoint-time") { Description = "Export time of that earlier export, as printed by this command." };

        var cmd = new Command("audit-verify", "Verify an administrative audit log export offline.")
        {
            file, organisation, keys, count, hash, time,
        };
        cmd.SetAction((parse, ct) => InvokeAsync(
            parse.InvocationConfiguration.Output, parse.InvocationConfiguration.Error,
            parse.GetRequiredValue(file), parse.GetRequiredValue(organisation), parse.GetRequiredValue(keys),
            parse.GetValue(count), parse.GetValue(hash), parse.GetValue(time), ct));
        return cmd;
    }

    private static async Task<int> InvokeAsync(
        TextWriter stdout, TextWriter stderr, string file, string organisation, string[] keys,
        long? checkpointCount, string? checkpointHash, string? checkpointTime, CancellationToken ct)
    {
        if (!TryReadCheckpoint(checkpointCount ?? 0, checkpointCount.HasValue, checkpointHash, checkpointTime, out var checkpoint, out var checkpointError))
        {
            await stderr.WriteLineAsync(checkpointError).ConfigureAwait(false);
            return 1;
        }

        PinnedProfileKeys pinned;
        try
        {
            pinned = PinnedProfileKeys.FromBase64(keys);
        }
        catch (Exception ex) when (ex is FormatException or ArgumentException)
        {
            await stderr.WriteLineAsync($"--public-key is not a base64 Ed25519 public key: {ex.Message}").ConfigureAwait(false);
            return 1;
        }

        byte[] bytes;
        try
        {
            bytes = await File.ReadAllBytesAsync(file, ct).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            await stderr.WriteLineAsync($"Could not read {file}: {ex.Message}").ConfigureAwait(false);
            return 1;
        }

        var result = await AdminAuditExportVerifier.VerifyAsync(bytes, pinned, organisation, checkpoint, ct).ConfigureAwait(false);
        if (!result.IsValid)
        {
            var at = result.FirstBrokenEntryId is null ? string.Empty : $" First broken entry: {result.FirstBrokenEntryId}.";
            await stderr.WriteLineAsync($"Verification failed: {Describe(result.Rejection)}.{at}").ConfigureAwait(false);
            return Failed;
        }

        await stdout.WriteLineAsync(FormattableString.Invariant(
            $"OK entries={result.SignedCount} last_hash={result.LastHash ?? "-"} exported_at={AdminAuditHead.FormatTime(result.ExportedAt!.Value)}"))
            .ConfigureAwait(false);
        return 0;
    }

    private static bool TryReadCheckpoint(
        long count, bool hasCount, string? hash, string? time, out AdminAuditCheckpoint? checkpoint, out string error)
    {
        checkpoint = null;
        error = string.Empty;
        if (!hasCount && hash is null && time is null)
        {
            return true;
        }
        if (!hasCount || string.IsNullOrEmpty(hash) || !AdminAuditHead.TryParseTime(time, out var at))
        {
            error = "A checkpoint needs --checkpoint-count, --checkpoint-hash and --checkpoint-time, as printed by an earlier run.";
            return false;
        }
        checkpoint = new AdminAuditCheckpoint(count, hash, at);
        return true;
    }

    private static string Describe(AdminAuditRejection reason) => reason switch
    {
        AdminAuditRejection.Malformed => "the file is not a valid audit log export",
        AdminAuditRejection.WrongOrganisation => "the export is for another organisation",
        AdminAuditRejection.UnknownKey => "the head is signed by a key that is not pinned",
        AdminAuditRejection.BadSignature => "the signature of the head does not verify",
        AdminAuditRejection.ChainBroken => "the hash chain is broken",
        AdminAuditRejection.StartMissing => "the export does not start at the first entry",
        AdminAuditRejection.HeadMismatch => "the entries do not match the signed head, so the export is cut off or extended",
        AdminAuditRejection.OlderThanCheckpoint => "the export is older than the checkpoint",
        AdminAuditRejection.CheckpointNotContained => "the export does not contain the checkpoint",
        _ => "unknown",
    };
}
