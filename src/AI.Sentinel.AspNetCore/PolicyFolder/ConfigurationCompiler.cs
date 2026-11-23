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
        var hash = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(module)));
        return Compile(nodes, module, hash);
    }

    private ConfigurationVerdict Compile(NodeConfiguration nodes, string module, string hash)
    {
        try
        {
            // The plugin compiles this text on its own: the host rules are added to it as they are there.
            var sources = PolicySources.FromFiles([new PolicyFile("profile.rego", module)]);
            var compiler = compilers.FirstOrDefault(c => c.Unavailable() is null)
                ?? throw new InvalidOperationException(
                    "no Rego compiler can run here: " + string.Join("; ", compilers.Select(c => $"{c.Name}: {c.Unavailable()}")));
            compiler.CompileWasm(sources, restrictBuiltins: true);
            return ConfigurationVerdict.Accept(nodes, module, hash);
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
    internal static bool DefinesAllow(string body) => AllowHead().IsMatch(StripComments(body));

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
        foreach (var line in source.Replace("\r\n", "\n", StringComparison.Ordinal).Split('\n'))
        {
            var trimmed = line.Trim();
            if (trimmed.StartsWith("package ", StringComparison.Ordinal) && package is null && body.ToString().Trim().Length == 0)
            {
                package = StripComments(trimmed["package ".Length..]).Trim();
            }
            else if (trimmed.StartsWith("import ", StringComparison.Ordinal))
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

    // A # outside a string starts a comment. Raw strings and multi-line strings are rare in a policy and not handled.
    private static string StripComments(string text)
    {
        var result = new StringBuilder();
        foreach (var line in text.Split('\n'))
        {
            var quoted = false;
            var end = line.Length;
            for (var i = 0; i < line.Length; i++)
            {
                if (line[i] == '\\' && quoted)
                {
                    i++;
                }
                else if (line[i] == '"')
                {
                    quoted = !quoted;
                }
                else if (line[i] == '#' && !quoted)
                {
                    end = i;
                    break;
                }
            }

            result.Append(line, 0, end).Append('\n');
        }

        return result.ToString();
    }

    [GeneratedRegex(@"^\s*(default\s+)?allow\s*(contains\b|if\b|:=|=|\{|\[|\()", RegexOptions.Multiline | RegexOptions.CultureInvariant | RegexOptions.ExplicitCapture, matchTimeoutMilliseconds: 1000)]
    private static partial Regex AllowHead();
}
