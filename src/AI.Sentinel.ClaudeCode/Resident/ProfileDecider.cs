using System.Security.Cryptography;
using System.Text;
using AI.Sentinel.ClaudeCode.Policy.Rego;
using AI.Sentinel.Profiles;

namespace AI.Sentinel.ClaudeCode.Resident;

/// <summary>
/// Evaluates a call against the policy module of the last valid signed profile in the state folder, with no network. This is what
/// keeps a deny rule of the organisation in force while the server cannot be reached. A profile that fails its check, has expired, or
/// names another organisation or repository is not used; the hook then applies the fail mode, see <see cref="Policy.Repository.HookProfiles"/>.
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
    /// <param name="slot">Which cached profile to read; <see langword="null"/> for the one profile of the state folder.</param>
    public static ProfileDecision Decide(
        ResidentState state, PinnedProfileKeys pinned, string organisation, string repository, DateTimeOffset now,
        string inputJson, string cacheDirectory, IReadOnlyList<IRegoCompiler>? compilers, string? slot = null)
    {
        ArgumentNullException.ThrowIfNull(state);
        var verification = state.ReadProfile(pinned, organisation, repository, now, slot);
        if (verification is null)
        {
            return new ProfileDecision(null, null);
        }

        if (!verification.IsAccepted)
        {
            return new ProfileDecision(null, verification.Rejection);
        }

        return new ProfileDecision(Evaluate(state, verification.Profile!, inputJson, cacheDirectory, compilers), ProfileRejection.None);
    }

    /// <summary>Where the compiled forms of the profile modules of <paramref name="state"/> are kept, by the resident process and by a
    /// hook alike.</summary>
    public static string CompiledDirectory(ResidentState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        return Path.Combine(state.Directory, "compiled");
    }

    /// <summary>The decision of the module of <paramref name="profile"/>, a profile that passed its check, loaded in this process.</summary>
    /// <exception cref="PolicyBundleException">The module loaded and failed while it ran; the hook denies that by name (ADR-237). A module
    /// that does not load throws what the load threw, and the hook blocks the call as an internal error.</exception>
    public static RegoDecision Evaluate(ResidentState state, PolicyProfile profile, string inputJson, string cacheDirectory, IReadOnlyList<IRegoCompiler>? compilers)
    {
        ArgumentNullException.ThrowIfNull(state);
        ArgumentNullException.ThrowIfNull(profile);
        using var module = RegoPolicy.Load(ModuleFolder(state, profile.Module), cacheDirectory, compilers);
        try
        {
            return module.Evaluate(inputJson);
        }
#pragma warning disable CA1031 // Any failure of the run is the module's; its message stays out of the reason, it may echo the input.
        catch (Exception e)
#pragma warning restore CA1031
        {
            throw new PolicyBundleException($"the policy module of the profile failed while it ran ({e.GetType().Name})", e);
        }
    }

    private static bool IsModule(string folder, string module)
    {
        try
        {
            // The compiler loads every .rego file under the folder, so a second file would add rules the profile never signed.
            var sources = System.IO.Directory.EnumerateFiles(folder, "*.rego", SearchOption.AllDirectories).Take(2).Count();
            return sources == 1 && string.Equals(File.ReadAllText(Path.Combine(folder, ModuleFile)), module, StringComparison.Ordinal);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    /// <summary>The folder that holds <paramref name="module"/> as a policy folder, named by the hash of the module text and written
    /// once, whole, by moving a finished folder into place.</summary>
    internal static string ModuleFolder(ResidentState state, string module)
    {
        var name = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(module)))[..32];
        var root = Path.Combine(state.Directory, ModulesFolder);
        var target = Path.Combine(root, name);
        if (System.IO.Directory.Exists(target))
        {
            // The name is the hash of the signed text but does not prove what is in the folder: whoever can write the state folder
            // could have replaced the file. A folder whose file is not the signed text is never evaluated; the decision fails.
            return IsModule(target, module)
                ? target
                : throw new InvalidDataException($"the cached module folder '{target}' does not hold the signed policy module");
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
            // Another process moved the same module into place first; it is checked below.
        }
        finally
        {
            if (System.IO.Directory.Exists(temporary))
            {
                System.IO.Directory.Delete(temporary, recursive: true);
            }
        }

        return IsModule(target, module) ? target : throw new InvalidDataException($"the cached module folder '{target}' does not hold the signed policy module");
    }
}
