namespace AI.Sentinel.Tests.Helpers;

internal static class TestOptions
{
    public static SentinelOptions WithFakeEmbeddings() =>
        new() { EmbeddingGenerator = new FakeEmbeddingGenerator() };
}
