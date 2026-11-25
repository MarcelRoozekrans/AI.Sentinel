using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using AI.Sentinel.ClaudeCode.Policy.Rego;

namespace AI.Sentinel.AspNetCore.PolicyFolder;

/// <summary>
/// Checks and compiles one read of the policy folder (ADR-236). All bundles become one Rego module, which is compiled out of
/// process with the builtins that reach outside the process left out of the capabilities; the plugin compiles the same text.
/// </summary>
internal sealed partial class ConfigurationCompiler(IReadOnlyList<IRegoCompiler> compilers)
{
    private const string SentinelPackage = "sentinel";

    /// <summary>Checks <paramref name="files"/> and compiles them.</summary>
    /// <returns>The module, or the reason the configuration is refused.</returns>
    /// <exception cref="InvalidOperationException">No compiler can run here.</exception>
    /// <exception cref="Exception">The compiler failed for a reason that is not the policy: it timed out or could not start.</exception>
    public ConfigurationVerdict Check(ConfigurationFiles files)
    {
        ArgumentNullException.ThrowIfNull(files);
        NodeConfiguration nodes;
        try
        {
            nodes = NodeConfiguration.Parse(files.NodesJson ?? throw new InvalidDataException("the folder holds no nodes.json"));
        }
        catch (InvalidDataException e)
        {
            return ConfigurationVerdict.Reject(RejectionReasons.InvalidNodeConfiguration, e.Message);
        }

        var rego = files.RegoFiles.ToList();
        if (rego.Count == 0)
        {
            return ConfigurationVerdict.Reject(RejectionReasons.NoPolicy, "the folder holds no .rego file", nodes.Organisation);
        }

        var rejection = CheckBundles(nodes, rego);
        if (rejection is not null)
        {
            return rejection;
        }

        var module = Merge(rego);
        var hash = Hash(module);
        var modules = new Dictionary<string, NodeModule>(StringComparer.Ordinal);
        var byBundle = rego.ToLookup(f => BundleOf(f.Key), StringComparer.Ordinal);
        foreach (var node in nodes.Nodes)
        {
            var own = Merge([.. byBundle[node.Id]]);
            modules[node.Id] = new NodeModule(own, Hash(own));
        }

        return Compile(nodes, module, hash, modules);
    }

    private static string Hash(string module) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(module)));

    private ConfigurationVerdict Compile(NodeConfiguration nodes, string module, string hash, Dictionary<string, NodeModule> modules)
    {
        try
        {
            var compiler = compilers.FirstOrDefault(c => c.Unavailable() is null)
                ?? throw new InvalidOperationException(
                    "no Rego compiler can run here: " + string.Join("; ", compilers.Select(c => $"{c.Name}: {c.Unavailable()}")));
            // The plugin compiles each of these texts on its own, with the host rules added as they are there. All bundles together
            // identify the configuration; each profile carries one node's module, which has to compile alone.
            compiler.CompileWasm(PolicySources.FromFiles([new PolicyFile("profile.rego", module)]), restrictBuiltins: true);
            foreach (var own in modules.Values.DistinctBy(m => m.ModuleHash, StringComparer.Ordinal))
            {
                compiler.CompileWasm(PolicySources.FromFiles([new PolicyFile("profile.rego", own.Module)]), restrictBuiltins: true);
            }

            return ConfigurationVerdict.Accept(nodes, module, hash, modules);
        }
        catch (RegoCompileException e)
        {
            var outside = OutsideBuiltins.NamedIn(e.Message);
            return outside.Count > 0
                ? ConfigurationVerdict.Reject(RejectionReasons.OutsideBuiltin, string.Join(", ", outside), nodes.Organisation)
                : ConfigurationVerdict.Reject(RejectionReasons.DoesNotCompile, "the Rego does not compile", nodes.Organisation);
        }
    }

    private static ConfigurationVerdict? CheckBundles(NodeConfiguration nodes, List<KeyValuePair<string, byte[]>> rego)
    {
        var organisationNode = nodes.Nodes.Single(n => n.IsOrganisation).Id;
        var nodeIds = nodes.Nodes.Select(n => n.Id).ToHashSet(StringComparer.Ordinal);
        foreach (var (path, bytes) in rego)
        {
            var bundle = BundleOf(path);
            if (!nodeIds.Contains(bundle))
            {
                return ConfigurationVerdict.Reject(RejectionReasons.UnknownBundle, $"the bundle '{bundle}' is no node", nodes.Organisation);
            }

            var parsed = Parse(Encoding.UTF8.GetString(bytes));
            if (!string.Equals(parsed.Package, SentinelPackage, StringComparison.Ordinal))
            {
                return ConfigurationVerdict.Reject(RejectionReasons.WrongPackage, $"{path}: the package is not {SentinelPackage}", nodes.Organisation);
            }

            // ADR-232: below the organisation a bundle can only restrict.
            if (!string.Equals(bundle, organisationNode, StringComparison.Ordinal) && DefinesAllow(parsed.Body))
            {
                return ConfigurationVerdict.Reject(
                    RejectionReasons.AllowRuleBelowOrganisation, $"the bundle '{bundle}' defines an allow rule", nodes.Organisation);
            }
        }

        return null;
    }

    /// <summary>The bundle of a file: its top folder, or for a file at the top its name.</summary>
    internal static string BundleOf(string path)
    {
        var slash = path.IndexOf('/', StringComparison.Ordinal);
        return slash < 0 ? Path.GetFileNameWithoutExtension(path) : path[..slash];
    }

    /// <summary>Whether Rego text has a rule head named <c>allow</c>: <c>allow if</c>, <c>allow contains</c>, <c>allow := ...</c>,
    /// <c>default allow</c> and the like. Comments are left out.</summary>
    internal static bool DefinesAllow(string body) => AllowHead().IsMatch(TopLevel(body));

    private static string Merge(List<KeyValuePair<string, byte[]>> rego)
    {
        var imports = new SortedSet<string>(StringComparer.Ordinal) { "import rego.v1" };
        var text = new StringBuilder();
        foreach (var (path, bytes) in rego)
        {
            var parsed = Parse(Encoding.UTF8.GetString(bytes));
            foreach (var import in parsed.Imports)
            {
                imports.Add(import);
            }

            text.Append("\n# ").Append(path).Append('\n').Append(parsed.Body.Trim('\n')).Append('\n');
        }

        return "package " + SentinelPackage + "\n\n" + string.Join('\n', imports) + "\n" + text;
    }

    private static (string? Package, List<string> Imports, string Body) Parse(string source)
    {
        string? package = null;
        var imports = new List<string>();
        var body = new StringBuilder();
        var lines = source.Replace("\r\n", "\n", StringComparison.Ordinal).Split('\n');
        var insideRaw = RawStringStarts(lines);
        for (var i = 0; i < lines.Length; i++)
        {
            var line = lines[i];
            var trimmed = line.Trim();
            // A line that begins inside a raw string is string content, whatever it looks like. A comment before the package
            // declaration is allowed and stays in the body.
            if (!insideRaw[i] && trimmed.StartsWith("package ", StringComparison.Ordinal) && package is null && StripComments(body.ToString()).Trim().Length == 0)
            {
                package = StripComments(trimmed["package ".Length..]).Trim();
            }
            else if (!insideRaw[i] && trimmed.StartsWith("import ", StringComparison.Ordinal))
            {
                imports.Add(StripComments(trimmed).Trim());
            }
            else
            {
                body.Append(line).Append('\n');
            }
        }

        return (package, imports, body.ToString());
    }

    // For each line, whether it begins inside a raw string, which is quoted by backticks and can span lines.
    private static bool[] RawStringStarts(string[] lines)
    {
        var starts = new bool[lines.Length];
        var raw = false;
        for (var i = 0; i < lines.Length; i++)
        {
            starts[i] = raw;
            var quoted = false;
            for (var j = 0; j < lines[i].Length; j++)
            {
                var c = lines[i][j];
                if (raw)
                {
                    raw = c != '`';
                }
                else if (c == '\\' && quoted)
                {
                    j++;
                }
                else if (c == '"')
                {
                    quoted = !quoted;
                }
                else if (c == '`' && !quoted)
                {
                    raw = true;
                }
                else if (c == '#' && !quoted)
                {
                    break;
                }
            }
        }

        return starts;
    }

    // A # outside a string starts a comment. Double quoted and raw strings are both skipped, the raw ones across lines.
    private static string StripComments(string text) => Scan(text, blankStrings: false, blankNested: false);

    /// <summary>The text with comments removed, string contents emptied and everything inside braces, brackets and parentheses
    /// emptied, so what is left is what stands at the top level of a module: the heads of its rules.</summary>
    private static string TopLevel(string text) => Scan(text, blankStrings: true, blankNested: true);

    private static string Scan(string text, bool blankStrings, bool blankNested)
    {
        var result = new StringBuilder(text.Length);
        var depth = 0;
        var quote = '\0';
        for (var i = 0; i < text.Length; i++)
        {
            var c = text[i];
            var emit = !(blankNested && depth > 0);
            if (quote != '\0')
            {
                // The content of a string is kept or blanked; the quotes that frame it are kept where the text is kept.
                var escape = quote == '"' && c == '\\' && i + 1 < text.Length;
                var closes = !escape && c == quote;
                if (emit && (!blankStrings || closes))
                {
                    result.Append(c);
                    if (escape)
                    {
                        result.Append(text[i + 1]);
                    }
                }

                i += escape ? 1 : 0;
                quote = closes ? '\0' : quote;
            }
            else if (c == '#')
            {
                i = EndOfLine(text, i);
            }
            else if (c is '"' or '`')
            {
                quote = c;
                AppendIf(result, emit, c);
            }
            else if (blankNested && c is '{' or '[' or '(')
            {
                AppendIf(result, depth++ == 0, c);
            }
            else if (blankNested && c is '}' or ']' or ')')
            {
                AppendIf(result, depth > 0 && --depth == 0, c);
            }
            else
            {
                AppendIf(result, emit || c == '\n', c);
            }
        }

        return result.ToString();
    }

    // The index of the last character of the line that starts the comment at <paramref name="from"/>; the newline itself stays.
    private static int EndOfLine(string text, int from)
    {
        var end = text.IndexOf('\n', from);
        return end < 0 ? text.Length : end - 1;
    }

    private static void AppendIf(StringBuilder result, bool condition, char c)
    {
        if (condition)
        {
            result.Append(c);
        }
    }

    [GeneratedRegex(@"(?<![\w.])allow\s*(contains\b|if\b|:=|=|\{|\[|\()", RegexOptions.CultureInvariant | RegexOptions.ExplicitCapture, matchTimeoutMilliseconds: 1000)]
    private static partial Regex AllowHead();
}
