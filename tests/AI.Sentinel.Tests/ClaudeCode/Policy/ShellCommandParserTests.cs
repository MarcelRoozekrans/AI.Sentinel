using System.Text.Json;
using AI.Sentinel.ClaudeCode.Policy;
using Xunit;

namespace AI.Sentinel.Tests.ClaudeCode.Policy;

/// <summary>Runs the parser against <c>Corpus/shell-commands.json</c>. The corpus is the contract a later parser, such as the
/// server's, is checked against: every entry has the command line and its expected parse.</summary>
public class ShellCommandParserTests
{
    private static readonly string CorpusPath = Path.Combine(AppContext.BaseDirectory, "Corpus", "shell-commands.json");

    public static TheoryData<string> CorpusNames()
    {
        var data = new TheoryData<string>();
        foreach (var entry in LoadCorpus().EnumerateArray())
        {
            data.Add(entry.GetProperty("name").GetString()!);
        }

        return data;
    }

    private static JsonElement LoadCorpus()
    {
        using var doc = JsonDocument.Parse(File.ReadAllText(CorpusPath));
        return doc.RootElement.Clone();
    }

    [Fact]
    public void Corpus_has_parseable_and_unparseable_entries()
    {
        var entries = LoadCorpus().EnumerateArray().ToArray();
        Assert.True(entries.Length >= 50);
        Assert.Contains(entries, e => e.GetProperty("unparseable").GetBoolean());
        Assert.Contains(entries, e => !e.GetProperty("unparseable").GetBoolean());
        Assert.Equal(entries.Length, entries.Select(e => e.GetProperty("name").GetString()).Distinct(StringComparer.Ordinal).Count());
    }

    [Theory]
    [MemberData(nameof(CorpusNames))]
    public void Parser_matches_the_corpus(string name)
    {
        var entry = LoadCorpus().EnumerateArray().Single(e => string.Equals(e.GetProperty("name").GetString(), name, StringComparison.Ordinal));
        var parsed = ShellCommandParser.Parse(entry.GetProperty("input").GetString()!);

        Assert.Equal(entry.GetProperty("unparseable").GetBoolean(), parsed.Unparseable);
        var expected = entry.GetProperty("commands");
        Assert.Equal(expected.GetArrayLength(), parsed.Commands.Count);
        for (var i = 0; i < parsed.Commands.Count; i++)
        {
            var want = expected[i];
            var got = parsed.Commands[i];
            Assert.Equal(want.GetProperty("operator").GetString(), got.Operator);
            Assert.Equal(want.GetProperty("name").GetString(), got.Name);
            Assert.Equal(Strings(want.GetProperty("args")), got.Args);
            Assert.Equal(Strings(want.GetProperty("assignments")), got.Assignments);
            Assert.Equal(Redirects(want.GetProperty("redirects")), Redirects(got.Redirects));
        }
    }

    [Fact]
    public void Unparseable_input_returns_a_result_and_never_throws()
    {
        string[] inputs = ["'", "\"", "\\", "$(", "`", "<<", ">", "&&", "|", "(", "\0", new string('(', 5000), new string('\'', 5001)];
        foreach (var input in inputs)
        {
            var parsed = ShellCommandParser.Parse(input);
            Assert.NotNull(parsed);
            Assert.True(parsed.Unparseable);
            Assert.Empty(parsed.Commands);
        }
    }

    private static string[] Redirects(JsonElement array) =>
        array.EnumerateArray().Select(r => $"{r.GetProperty("op").GetString()} {r.GetProperty("target").GetString()}").ToArray();

    private static string[] Redirects(IReadOnlyList<ShellRedirect> redirects) =>
        redirects.Select(r => $"{r.Op} {r.Target}").ToArray();

    private static string[] Strings(JsonElement array) => array.EnumerateArray().Select(e => e.GetString()!).ToArray();
}
