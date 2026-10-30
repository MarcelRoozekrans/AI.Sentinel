using Microsoft.Extensions.AI;

namespace AI.Sentinel.Detection;

/// <summary>The text of a scan a second-stage reviewer should look at for one semantic detector.</summary>
/// <param name="Text">The scored text: the first text that reached the most severe bucket, or, when none reached a
/// bucket, the text most similar to any example set.</param>
/// <param name="Score">Its similarity to the example set of the bucket it reached, or its best similarity to any set
/// when it reached none.</param>
/// <param name="Role">The role of the newest message that contributed the text, or <see langword="null"/> when the
/// detector chooses its own texts.</param>
internal readonly record struct ReviewCandidate(string Text, float Score, ChatRole? Role);
