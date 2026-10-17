namespace AI.Sentinel.ComplianceEval;

/// <summary>A BERT-style sentence-embedding model published on Hugging Face with an ONNX export.</summary>
/// <param name="Revision">The Hugging Face commit the files are downloaded from, so a re-run scores with the
/// same weights as the published evaluation.</param>
/// <param name="ModelSha256">SHA-256 of <c>onnx/model.onnx</c> at <paramref name="Revision"/>, checked on every run.</param>
internal sealed record EmbeddingModel(string Name, string Repository, string Revision, string ModelSha256, Pooling Pooling, int MaxTokens)
{
    /// <summary>The models the tool knows how to run. The first is the one the shipped thresholds are tuned on.</summary>
    public static readonly EmbeddingModel[] Known =
    [
        new("all-MiniLM-L6-v2", "sentence-transformers/all-MiniLM-L6-v2",
            "1110a243fdf4706b3f48f1d95db1a4f5529b4d41",
            "6fd5d72fe4589f189f8ebc006442dbb529bb7ce38f8082112682524616046452",
            Pooling.Mean, 256),
        new("bge-base-en-v1.5", "BAAI/bge-base-en-v1.5",
            "a5beb1e3e68b9ab74eb54cfd186867f64f240e1a",
            "9bc579acdba21c253c62a9bf866891355a63ffa3442b52c8a37d75b2ccb91848",
            Pooling.Cls, 512),
    ];

    /// <summary>Files the tool needs, as paths inside the Hugging Face repository.</summary>
    public static readonly string[] Files = ["onnx/model.onnx", "vocab.txt"];

    /// <summary>Downloads the model at <see cref="Revision"/> into
    /// <c>~/.cache/ai-sentinel/models/&lt;name&gt;/&lt;revision&gt;</c> unless it is already there, or uses
    /// <paramref name="directory"/> when given, then checks <see cref="ModelSha256"/>. Weights never go into
    /// the repository.</summary>
    public async Task<string> EnsureAsync(string? directory, CancellationToken ct)
    {
        var target = directory ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".cache", "ai-sentinel", "models", Name, Revision);
        Directory.CreateDirectory(target);

        using var http = new HttpClient();
        foreach (var file in Files)
        {
            var local = Path.Combine(target, Path.GetFileName(file));
            if (File.Exists(local)) continue;

            var url = new Uri($"https://huggingface.co/{Repository}/resolve/{Revision}/{file}");
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

        var model = File.OpenRead(Path.Combine(target, "model.onnx"));
        await using (model.ConfigureAwait(false))
        {
            var actual = Convert.ToHexStringLower(await System.Security.Cryptography.SHA256.HashDataAsync(model, ct).ConfigureAwait(false));
            if (!string.Equals(actual, ModelSha256, StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    $"{target}/model.onnx has SHA-256 {actual}, expected {ModelSha256} for {Repository} at {Revision}. Delete the file to download it again.");
            }
        }

        return target;
    }
}
