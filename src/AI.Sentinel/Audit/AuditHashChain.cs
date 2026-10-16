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
    /// PolicyCode, SessionId and Source. <see cref="AuditEntry.Hash"/> itself is not an input.
    /// </summary>
    /// <remarks>
    /// <para>Each string is length-prefixed and <see langword="null"/> is encoded apart from the
    /// empty string, so no two different entries share an encoding.</para>
    /// <para>The encoding is a stored format: hashes already persisted by a store must keep
    /// verifying. The nine inputs below are fixed, in this order, and each is written even when
    /// <see langword="null"/>. A field added to <see cref="AuditEntry"/> after 3.0 must not be
    /// written that way, because a null marker would change the hash of every stored entry. It is
    /// appended after the fixed inputs only when it has a value, as a unique Int32 tag followed by
    /// the value, with tags written in ascending order. An entry that does not set the field then
    /// hashes exactly as before. <c>AuditHashChainTests</c> pins golden hashes for this format.</para>
    /// <para>Rules for such a field:</para>
    /// <list type="bullet">
    /// <item>It must be nullable, so "absent" is <see langword="null"/>. A non-nullable value type
    /// would always have a value, always be written, and so change every existing hash.</item>
    /// <item>A string value is written length-prefixed, as above. Any other value is written at a
    /// fixed width in little-endian byte order, for example Int64 for an integer or a timestamp in
    /// UTC ticks. The tag fixes the field's type, so the encoding stays unambiguous.</item>
    /// <item>Every <see cref="IAuditStore"/> must persist the field, for example as a new SQLite
    /// column, and return it on query. A store that drops it returns entries whose hash no longer
    /// matches, and verification fails.</item>
    /// </list>
    /// </remarks>
    public static string ComputeHash(AuditEntry entry)
    {
        ArgumentNullException.ThrowIfNull(entry);
        using var sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);

        // Fixed 3.0 inputs: never reorder, remove, or skip when null.
        AppendString(sha, entry.PreviousHash);
        AppendString(sha, entry.Id);
        AppendInt64(sha, entry.Timestamp.UtcTicks);
        AppendInt64(sha, (long)entry.Severity);
        AppendString(sha, entry.DetectorId);
        AppendString(sha, entry.Summary);
        AppendString(sha, entry.PolicyCode);
        AppendString(sha, entry.SessionId);
        AppendString(sha, entry.Source);

        // Fields added after 3.0 go here, each nullable and written only when non-null:
        //   if (entry.NewText is { } text) { AppendInt32(sha, <tag>); AppendString(sha, text); }
        //   if (entry.NewCount is { } count) { AppendInt32(sha, <tag>); AppendInt64(sha, count); }
        // Tags start at 1, are never reused, and are written in ascending order. Every store must
        // persist the field too; see the remarks above.
        return Convert.ToHexString(sha.GetHashAndReset()).ToLowerInvariant();
    }

    /// <summary>
    /// Checks a sequence of entries, oldest first, for an unbroken chain.
    /// </summary>
    /// <param name="entriesOldestFirst">Every entry of one store in append order, for example
    /// <c>store.QueryAsync(new AuditQuery { PageSize = int.MaxValue }, ct)</c>.</param>
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
