using System.Text.Json;

namespace RegoAot;

internal sealed record Case(string Name, string Expected, IReadOnlyList<string> ExpectedReasons, string InputJson);

internal static class Cases
{
    public static readonly string[] Outcomes = ["deny", "ask", "guidance", "allow", "defer"];

    public static List<Case> Load(string dir)
    {
        var cases = new List<Case>();
        foreach (var file in Directory.EnumerateFiles(dir, "*.json").Order(StringComparer.Ordinal))
        {
            var parsed = JsonSerializer.Deserialize(File.ReadAllText(file), SpikeJson.Default.CaseFile)
                ?? throw new InvalidDataException($"{file} is empty");
            if (Array.IndexOf(Outcomes, parsed.Expected) < 0)
            {
                throw new InvalidDataException($"{file}: '{parsed.Expected}' is not one of the five outcomes");
            }

            cases.Add(new Case(Path.GetFileNameWithoutExtension(file), parsed.Expected, parsed.ExpectedReasons, parsed.Input.GetRawText()));
        }

        return cases;
    }
}
