using AI.Sentinel.Embeddings;
using Microsoft.Extensions.AI;
using Xunit;

namespace AI.Sentinel.Tests.Detection;

/// <summary>Reads the CLI embedding configuration. Getting this wrong silently is the failure mode
/// #170 is about, so a malformed setting must report why rather than leaving detection quietly off.</summary>
public class SentinelEmbeddingSetupTests
{
    private static Dictionary<string, string?> Env(params (string Key, string? Value)[] entries)
    {
        var env = new Dictionary<string, string?>(StringComparer.Ordinal);
        foreach (var (key, value) in entries) env[key] = value;
        return env;
    }

    [Fact]
    public void NotConfigured_ReturnsNothing_AndReportsNoError()
    {
        var setup = SentinelEmbeddingSetup.TryCreateFromEnvironment(Env(), out var error);

        Assert.Null(setup);
        Assert.Null(error);
    }

    [Fact]
    public void EndpointAndModel_ProduceAGeneratorAndAnExampleCache()
    {
        var dir = Path.Combine(Path.GetTempPath(), "ai-sentinel-setup-" + Guid.NewGuid().ToString("N"));
        try
        {
            using var setup = SentinelEmbeddingSetup.TryCreateFromEnvironment(Env(
                ("SENTINEL_EMBEDDING_ENDPOINT", "https://api.openai.com/v1/embeddings"),
                ("SENTINEL_EMBEDDING_MODEL", "text-embedding-3-small"),
                ("SENTINEL_EMBEDDING_CACHE_DIR", dir)), out var error);

            Assert.Null(error);
            Assert.NotNull(setup);
            var metadata = (EmbeddingGeneratorMetadata)setup!.Generator.GetService(typeof(EmbeddingGeneratorMetadata))!;
            Assert.Equal("text-embedding-3-small", metadata.DefaultModelId);
            Assert.NotNull(setup.ExampleCache);
        }
        finally
        {
            if (Directory.Exists(dir)) Directory.Delete(dir, recursive: true);
        }
    }

    /// <summary>A typo must not leave semantic detection quietly disabled — the operator has to be
    /// told which setting is wrong.</summary>
    [Fact]
    public void MalformedEndpoint_ReportsTheSettingByName()
    {
        var setup = SentinelEmbeddingSetup.TryCreateFromEnvironment(Env(
            ("SENTINEL_EMBEDDING_ENDPOINT", "not a url"),
            ("SENTINEL_EMBEDDING_MODEL", "m")), out var error);

        Assert.Null(setup);
        Assert.NotNull(error);
        Assert.Contains("SENTINEL_EMBEDDING_ENDPOINT", error, StringComparison.Ordinal);
    }

    [Fact]
    public void EndpointWithoutModel_ReportsTheMissingSetting()
    {
        var setup = SentinelEmbeddingSetup.TryCreateFromEnvironment(Env(
            ("SENTINEL_EMBEDDING_ENDPOINT", "https://api.openai.com/v1/embeddings")), out var error);

        Assert.Null(setup);
        Assert.NotNull(error);
        Assert.Contains("SENTINEL_EMBEDDING_MODEL", error, StringComparison.Ordinal);
    }

    [Fact]
    public void NonNumericDimensions_ReportsTheSettingByName()
    {
        var setup = SentinelEmbeddingSetup.TryCreateFromEnvironment(Env(
            ("SENTINEL_EMBEDDING_ENDPOINT", "https://api.openai.com/v1/embeddings"),
            ("SENTINEL_EMBEDDING_MODEL", "m"),
            ("SENTINEL_EMBEDDING_DIMENSIONS", "lots")), out var error);

        Assert.Null(setup);
        Assert.NotNull(error);
        Assert.Contains("SENTINEL_EMBEDDING_DIMENSIONS", error, StringComparison.Ordinal);
    }

    [Fact]
    public void Dimensions_ReachTheGeneratorMetadata()
    {
        var dir = Path.Combine(Path.GetTempPath(), "ai-sentinel-setup-" + Guid.NewGuid().ToString("N"));
        try
        {
            using var setup = SentinelEmbeddingSetup.TryCreateFromEnvironment(Env(
                ("SENTINEL_EMBEDDING_ENDPOINT", "https://api.openai.com/v1/embeddings"),
                ("SENTINEL_EMBEDDING_MODEL", "m"),
                ("SENTINEL_EMBEDDING_DIMENSIONS", "1536"),
                ("SENTINEL_EMBEDDING_CACHE_DIR", dir)), out _);

            var metadata = (EmbeddingGeneratorMetadata)setup!.Generator.GetService(typeof(EmbeddingGeneratorMetadata))!;
            Assert.Equal(1536, metadata.DefaultModelDimensions);
        }
        finally
        {
            if (Directory.Exists(dir)) Directory.Delete(dir, recursive: true);
        }
    }

    /// <summary>The cache file is unauthenticated: anyone who can write the directory can replace the
    /// reference vectors with noise and silently disable semantic detection. The default must be a
    /// per-user location, never a shared temp path.</summary>
    [Fact]
    public void DefaultCacheDirectory_IsUserPrivate_NotSharedTemp()
    {
        var directory = SentinelEmbeddingSetup.DefaultCacheDirectory;

        Assert.False(string.IsNullOrWhiteSpace(directory));
        Assert.NotEqual(
            Path.TrimEndingDirectorySeparator(Path.GetTempPath()),
            Path.TrimEndingDirectorySeparator(directory),
            StringComparer.OrdinalIgnoreCase);

        var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        Assert.True(
            (!string.IsNullOrEmpty(local) && directory.StartsWith(local, StringComparison.OrdinalIgnoreCase))
            || (!string.IsNullOrEmpty(home) && directory.StartsWith(home, StringComparison.OrdinalIgnoreCase)),
            $"default cache directory '{directory}' is not under the user profile");
    }
}
