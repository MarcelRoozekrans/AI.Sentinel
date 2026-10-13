using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace AI.Sentinel.Audit;

/// <summary>
/// The SHA-256 hash chain that makes an <see cref="IAuditStore"/> tamper-evident. Each entry's
/// <see cref="AuditEntry.Hash"/> covers its own fields and the previous entry's hash, so editing,
/// inserting or deleting any entry breaks the link to the entry after it.
/// </summary>
/// <remarks>
/// Stores own the chain: <see cref="IAuditStore.AppendAsync"/> calls <see cref="Link"/> under its
/// write lock with the hash of the entry it appended last. Callers pass entries with an empty
/// <see cref="AuditEntry.Hash"/> and a <see langword="null"/> <see cref="AuditEntry.PreviousHash"/>.
/// </remarks>
public static class AuditHashChain
{
    /// <summary>Returns <paramref name="entry"/> chained after <paramref name="previousHash"/>:
    /// <see cref="AuditEntry.PreviousHash"/> set to it and <see cref="AuditEntry.Hash"/> computed.</summary>
    /// <param name="entry">The entry to link. Its incoming hash fields are ignored.</param>
    /// <param name="previousHash">The hash of the entry appended before it, or <see langword="null"/> for the first entry.</param>
    public static AuditEntry Link(AuditEntry entry, string? previousHash)
    {
        ArgumentNullException.ThrowIfNull(entry);
        var withPrevious = entry with { PreviousHash = previousHash };
        return withPrevious with { Hash = ComputeHash(withPrevious) };
    }

    /// <summary>
    /// Computes the hash <paramref name="entry"/> should carry: lowercase hex SHA-256 over its
    /// <see cref="AuditEntry.PreviousHash"/>, Id, Timestamp, Severity, DetectorId, Summary,
    /// PolicyCode and SessionId. <see cref="AuditEntry.Hash"/> itself is not an input.
    /// </summary>
    /// <remarks>Each string is length-prefixed and <see langword="null"/> is encoded apart from the
    /// empty string, so no two different entries share an encoding.</remarks>
    public static string ComputeHash(AuditEntry entry)
    {
        ArgumentNullException.ThrowIfNull(entry);
        using var sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        AppendString(sha, entry.PreviousHash);
        AppendString(sha, entry.Id);
        AppendInt64(sha, entry.Timestamp.UtcTicks);
        AppendInt64(sha, (long)entry.Severity);
        AppendString(sha, entry.DetectorId);
        AppendString(sha, entry.Summary);
        AppendString(sha, entry.PolicyCode);
        AppendString(sha, entry.SessionId);
        return Convert.ToHexString(sha.GetHashAndReset()).ToLowerInvariant();
    }

    /// <summary>
    /// Checks a sequence of entries, oldest first, for an unbroken chain.
    /// </summary>
    /// <param name="entriesOldestFirst">Every entry of one store in append order, for example
    /// <c>store.QueryAsync(new AuditQuery(PageSize: int.MaxValue), ct)</c>.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <remarks>
    /// Verification starts from the oldest entry present. When retention or a ring buffer has removed
    /// older entries, that entry's <see cref="AuditEntry.PreviousHash"/> is returned as
    /// <see cref="AuditChainVerification.AnchorHash"/>. Removal of entries from the head of the chain
    /// cannot be told apart from retention; compare the anchor with one recorded earlier to detect it.
    /// </remarks>
    public static async ValueTask<AuditChainVerification> VerifyAsync(
        IAsyncEnumerable<AuditEntry> entriesOldestFirst,
        CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(entriesOldestFirst);

        long checkedCount = 0;
        string? anchor = null;
        string? expectedPrevious = null;
        await foreach (var entry in entriesOldestFirst.WithCancellation(ct).ConfigureAwait(false))
        {
            if (checkedCount == 0)
            {
                anchor = entry.PreviousHash;
                expectedPrevious = anchor;
            }

            if (!string.Equals(entry.PreviousHash, expectedPrevious, StringComparison.Ordinal)
                || !string.Equals(entry.Hash, ComputeHash(entry), StringComparison.Ordinal))
            {
                return new AuditChainVerification(false, checkedCount, entry.Id, anchor);
            }

            expectedPrevious = entry.Hash;
            checkedCount++;
        }

        return new AuditChainVerification(true, checkedCount, null, anchor);
    }

    private static void AppendString(IncrementalHash sha, string? value)
    {
        if (value is null)
        {
            AppendInt32(sha, -1);
            return;
        }

        var bytes = Encoding.UTF8.GetBytes(value);
        AppendInt32(sha, bytes.Length);
        sha.AppendData(bytes);
    }

    private static void AppendInt32(IncrementalHash sha, int value)
    {
        Span<byte> buffer = stackalloc byte[sizeof(int)];
        BinaryPrimitives.WriteInt32LittleEndian(buffer, value);
        sha.AppendData(buffer);
    }

    private static void AppendInt64(IncrementalHash sha, long value)
    {
        Span<byte> buffer = stackalloc byte[sizeof(long)];
        BinaryPrimitives.WriteInt64LittleEndian(buffer, value);
        sha.AppendData(buffer);
    }
}
