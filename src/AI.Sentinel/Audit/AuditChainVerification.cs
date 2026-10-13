namespace AI.Sentinel.Audit;

/// <summary>The outcome of <see cref="AuditHashChain.VerifyAsync"/>.</summary>
/// <param name="IsIntact"><see langword="true"/> when every entry links to the one before it and carries the hash its fields produce.</param>
/// <param name="EntriesChecked">How many entries verified cleanly before the first break, or in total when intact.</param>
/// <param name="FirstBrokenEntryId">The Id of the first entry that fails verification, or <see langword="null"/> when intact.
/// After an edit this is the edited entry; after a deletion it is the entry that follows the gap.</param>
/// <param name="AnchorHash">The <see cref="AuditEntry.PreviousHash"/> of the oldest entry checked. <see langword="null"/> means
/// the chain starts at its first entry; a value means older entries were removed, for example by retention.</param>
public sealed record AuditChainVerification(
    bool IsIntact,
    long EntriesChecked,
    string? FirstBrokenEntryId,
    string? AnchorHash);
