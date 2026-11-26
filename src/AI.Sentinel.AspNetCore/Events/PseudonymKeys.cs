using System.Security.Cryptography;
using System.Text;

namespace AI.Sentinel.AspNetCore.Events;

/// <summary>Turns an identity into a code that is stable within one organisation and unlinkable across organisations: an HMAC under a
/// key derived per organisation from the deployment's key. It is a separate object from the event store, so the store alone cannot
/// map a code back or forward to an identity.</summary>
internal sealed class PseudonymKeys
{
    private readonly byte[] _master;

    public PseudonymKeys(string base64Key)
    {
        _master = Convert.FromBase64String(base64Key);
        if (_master.Length < 16)
        {
            throw new ArgumentException("The pseudonym key must be at least 16 bytes.", nameof(base64Key));
        }
    }

    public string CodeFor(string organisation, string identity)
    {
        var organisationKey = HMACSHA256.HashData(_master, Encoding.UTF8.GetBytes("organisation:" + organisation));
        var mac = HMACSHA256.HashData(organisationKey, Encoding.UTF8.GetBytes(identity));
        return "dev-" + Convert.ToHexStringLower(mac.AsSpan(0, 8));
    }
}
