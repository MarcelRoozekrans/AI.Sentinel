
namespace AI.Sentinel.ClaudeCode.Policy.Rego;

/// <summary>Builtins that reach outside the process: a policy using one is refused when it is compiled, and a module that
/// calls one anyway is refused when the call is met.</summary>
internal static class OutsideBuiltins
{
    public static readonly IReadOnlyList<string> Names = ["http.send", "net.lookup_ip_addr", "opa.runtime"];

    private const string CapabilitiesResource = "AI.Sentinel.ClaudeCode.Policy.Rego.capabilities.json";

    /// <summary>
    /// The capabilities document of OPA v1.22.4 without the builtins above. It was made with
    /// <c>opa capabilities --current</c> and by dropping the three builtins from the list, and has to be made again when the
    /// OPA version of the compilers moves. A compiler given it reports each use of a dropped builtin as an undefined function.
    /// </summary>
    public static string Capabilities()
    {
        using var stream = typeof(OutsideBuiltins).Assembly.GetManifestResourceStream(CapabilitiesResource)
            ?? throw new InvalidOperationException($"the resource {CapabilitiesResource} is missing");
        using var reader = new StreamReader(stream);
        return reader.ReadToEnd();
    }

    /// <summary>The names of <see cref="Names"/> that a compiler message mentions.</summary>
    public static List<string> NamedIn(string message) =>
        Names.Where(n => message.Contains(n, StringComparison.Ordinal)).ToList();
}
