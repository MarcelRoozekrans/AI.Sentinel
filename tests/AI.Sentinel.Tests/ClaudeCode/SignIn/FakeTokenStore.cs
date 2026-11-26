using AI.Sentinel.ClaudeCode.SignIn;

namespace AI.Sentinel.Tests.ClaudeCode.SignIn;

/// <summary>A keychain in memory. With <see cref="Available"/> false it behaves as a machine with none: every call fails.</summary>
internal sealed class FakeTokenStore(bool available = true) : ITokenStore
{
    public bool Available { get; set; } = available;

    public string? Secret { get; private set; }

    public int Saves { get; private set; }

    public string Name => "fake keychain";

    public bool Save(string secret)
    {
        if (!Available)
        {
            return false;
        }

        Secret = secret;
        Saves++;
        return true;
    }

    public string? Load() => Available ? Secret : null;

    // A failing keychain fails to remove a secret it holds; one that holds none has nothing to remove, as the contract says.
    public bool Delete()
    {
        if (!Available)
        {
            return Secret is null;
        }

        Secret = null;
        return true;
    }
}
