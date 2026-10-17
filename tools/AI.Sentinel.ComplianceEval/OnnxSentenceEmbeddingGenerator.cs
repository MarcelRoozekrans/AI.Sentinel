using Microsoft.Extensions.AI;
using Microsoft.ML.OnnxRuntime;
using Microsoft.ML.OnnxRuntime.Tensors;
using Microsoft.ML.Tokenizers;

namespace AI.Sentinel.ComplianceEval;

/// <summary>An <see cref="IEmbeddingGenerator{TInput,TEmbedding}"/> over a local BERT-style ONNX model, pooled
/// and L2-normalised the way sentence-transformers does, so the detectors see what a user's local embedding
/// model would give them.</summary>
internal sealed class OnnxSentenceEmbeddingGenerator : IEmbeddingGenerator<string, Embedding<float>>
{
    private readonly InferenceSession _session;
    private readonly BertTokenizer _tokenizer;
    private readonly EmbeddingModel _model;
    private readonly bool _hasTokenTypeIds;
    private readonly string _outputName;

    public OnnxSentenceEmbeddingGenerator(EmbeddingModel model, string directory)
    {
        _model = model;
        _tokenizer = BertTokenizer.Create(Path.Combine(directory, "vocab.txt"), new BertOptions { LowerCaseBeforeTokenization = true });
        _session = new InferenceSession(Path.Combine(directory, "model.onnx"));
        _hasTokenTypeIds = _session.InputMetadata.ContainsKey("token_type_ids");
        _outputName = _session.OutputMetadata.ContainsKey("last_hidden_state")
            ? "last_hidden_state"
            : _session.OutputMetadata.Keys.First();
    }

    public Task<GeneratedEmbeddings<Embedding<float>>> GenerateAsync(
        IEnumerable<string> values, EmbeddingGenerationOptions? options = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(values);
        var result = new GeneratedEmbeddings<Embedding<float>>();
        foreach (var value in values)
        {
            cancellationToken.ThrowIfCancellationRequested();
            result.Add(new Embedding<float>(Embed(value)));
        }

        return Task.FromResult(result);
    }

    /// <summary>Embeds one sentence. One sentence per run means no padding, so pooling sees only real tokens.</summary>
    private float[] Embed(string text)
    {
        var ids = _tokenizer.EncodeToIds(text, _model.MaxTokens, out _, out _, considerPreTokenization: true, considerNormalization: true);
        var length = ids.Count;
        var shape = new[] { 1, length };

        var inputIds = new DenseTensor<long>(shape);
        var mask = new DenseTensor<long>(shape);
        var types = new DenseTensor<long>(shape);
        for (var i = 0; i < length; i++)
        {
            inputIds[0, i] = ids[i];
            mask[0, i] = 1;
            types[0, i] = 0;
        }

        var inputs = new List<NamedOnnxValue>
        {
            NamedOnnxValue.CreateFromTensor("input_ids", inputIds),
            NamedOnnxValue.CreateFromTensor("attention_mask", mask),
        };
        if (_hasTokenTypeIds) inputs.Add(NamedOnnxValue.CreateFromTensor("token_type_ids", types));

        using var outputs = _session.Run(inputs, [_outputName]);
        var hidden = outputs[0].AsTensor<float>();
        var dimensions = hidden.Dimensions[2];

        var vector = new float[dimensions];
        if (_model.Pooling == Pooling.Cls)
        {
            for (var d = 0; d < dimensions; d++) vector[d] = hidden[0, 0, d];
        }
        else
        {
            for (var t = 0; t < length; t++)
            {
                for (var d = 0; d < dimensions; d++) vector[d] += hidden[0, t, d];
            }

            for (var d = 0; d < dimensions; d++) vector[d] /= length;
        }

        var norm = MathF.Sqrt(vector.Sum(v => v * v));
        if (norm > 0f)
        {
            for (var d = 0; d < dimensions; d++) vector[d] /= norm;
        }

        return vector;
    }

    public object? GetService(Type serviceType, object? serviceKey = null) =>
        serviceKey is null && serviceType?.IsInstanceOfType(this) == true ? this : null;

    public void Dispose() => _session.Dispose();
}
