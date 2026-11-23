using System.Security.Cryptography;
using System.Text;
using AI.Sentinel.ClaudeCode.Policy.Rego;
using AI.Sentinel.Profiles;

namespace AI.Sentinel.ClaudeCode.Resident;

/// <summary>
/// Evaluates a call against the policy module of the last valid signed profile in the state folder, with no network. This is what
/// keeps a deny rule of the organisation in force while the server cannot be reached. A profile that fails its check, has expired, or
/// names another organisation or repository is not used; what the hook does without one is a later decision, not made here.
/// </summary>
internal static class ProfileDecider
{
    private const string ModulesFolder = "modules";
    private const string ModuleFile = "profile.rego";

    /// <summary>The decision of the cached profile for <paramref name="inputJson"/>.</summary>
    /// <param name="state">The state folder.</param>
    /// <param name="pinned">The keys pinned at sign-in.</param>
    /// <param name="organisation">The organisation signed in to.</param>
    /// <param name="repository">The repository the profile is for.</param>
    /// <param name="now">The current time.</param>
    /// <param name="inputJson">The policy input.</param>
    /// <param name="cacheDirectory">Where the compiled forms are kept.</param>
    /// <param name="compilers">The compilers for a module that is not cached.</param>
    public static ProfileDecision Decide(
        ResidentState state, PinnedProfileKeys pinned, string organisation, string repository, DateTimeOffset now,
        string inputJson, string cacheDirectory, IReadOnlyList<IRegoCompiler>? compilers)
    {
        ArgumentNullException.ThrowIfNull(state);
        var verification = state.ReadProfile(pinned, organisation, repository, now);
        if (verification is null)
        {
            return new ProfileDecision(null, null);
        }

        if (!verification.IsAccepted)
        {
            return new ProfileDecision(null, verification.Rejection);
        }

        using var module = RegoPolicy.Load(ModuleFolder(state, verification.Profile!.Module), cacheDirectory, compilers);
        return new ProfileDecision(module.Evaluate(inputJson), ProfileRejection.None);
    }

    /// <summary>The folder that holds <paramref name="module"/> as a policy folder, named by the hash of the module text and written
    /// once, whole, by moving a finished folder into place.</summary>
    private static string ModuleFolder(ResidentState state, string module)
    {
        var name = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(module)))[..32];
        var root = Path.Combine(state.Directory, ModulesFolder);
        var target = Path.Combine(root, name);
        if (System.IO.Directory.Exists(target))
        {
            return target;
        }

        System.IO.Directory.CreateDirectory(root);
        var temporary = Path.Combine(root, $".{name}.{Environment.ProcessId}.{Guid.NewGuid():N}.tmp");
        System.IO.Directory.CreateDirectory(temporary);
        try
        {
            File.WriteAllText(Path.Combine(temporary, ModuleFile), module);
            System.IO.Directory.Move(temporary, target);
        }
        catch (IOException) when (System.IO.Directory.Exists(target))
        {
            // Another process moved the same module into place first; it is the same text.
        }
        finally
        {
            if (System.IO.Directory.Exists(temporary))
            {
                System.IO.Directory.Delete(temporary, recursive: true);
            }
        }

        return target;
    }
}
