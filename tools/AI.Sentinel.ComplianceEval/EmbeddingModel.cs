namespace AI.Sentinel.ComplianceEval;

/// <summary>A BERT-style sentence-embedding model published on Hugging Face with an ONNX export.</summary>
internal sealed record EmbeddingModel(string Name, string Repository, Pooling Pooling, int MaxTokens)
{
    /// <summary>The models the tool knows how to run. The first is the one the shipped thresholds are tuned on.</summary>
    public static readonly EmbeddingModel[] Known =
    [
        new("all-MiniLM-L6-v2", "sentence-transformers/all-MiniLM-L6-v2", Pooling.Mean, 256),
        new("bge-base-en-v1.5", "BAAI/bge-base-en-v1.5", Pooling.Cls, 512),
    ];

    /// <summary>Files the tool needs, as paths inside the Hugging Face repository.</summary>
    public static readonly string[] Files = ["onnx/model.onnx", "vocab.txt"];

    /// <summary>Downloads the model into <c>~/.cache/ai-sentinel/models/&lt;name&gt;</c> unless it is already
    /// there, or uses <paramref name="directory"/> when given. Weights never go into the repository.</summary>
    public async Task<string> EnsureAsync(string? directory, CancellationToken ct)
    {
        var target = directory ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".cache", "ai-sentinel", "models", Name);
        Directory.CreateDirectory(target);

        using var http = new HttpClient();
        foreach (var file in Files)
        {
            var local = Path.Combine(target, Path.GetFileName(file));
            if (File.Exists(local)) continue;

            var url = new Uri($"https://huggingface.co/{Repository}/resolve/main/{file}");
            await Console.Error.WriteLineAsync($"Downloading {url} to {local}").ConfigureAwait(false);
            var partial = local + ".partial";
            using (var response = await http.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false))
            {
                response.EnsureSuccessStatusCode();
                var source = await response.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
                await using (source.ConfigureAwait(false))
                {
                    var sink = File.Create(partial);
                    await using (sink.ConfigureAwait(false))
                    {
                        await source.CopyToAsync(sink, ct).ConfigureAwait(false);
                    }
                }
            }

            File.Move(partial, local, overwrite: true);
        }

        return target;
    }
}
