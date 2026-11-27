namespace AI.Sentinel.ClaudeCode.Events;

/// <summary>What one forwarding pass did.</summary>
/// <param name="Sent">The events the server took.</param>
/// <param name="Pruned">The entries reported as a gap.</param>
/// <param name="Failed">True when a send did not reach the server; the pass stopped there and the next one starts at the same entry.</param>
internal readonly record struct ForwardResult(int Sent, int Pruned, bool Failed);
