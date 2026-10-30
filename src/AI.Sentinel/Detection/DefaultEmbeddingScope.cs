namespace AI.Sentinel.Detection;

/// <summary>The default pipeline's scope, resolved once from the resolved default options so its generator is the
/// one the shared detectors were built with, and so named pipelines can inherit it.</summary>
internal sealed record DefaultEmbeddingScope(EmbeddingScope? Scope);
