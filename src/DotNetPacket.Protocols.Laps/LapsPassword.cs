using System.Text.Json;

namespace DotNetPacket.Protocols.Laps;

/// <summary>A recovered (or observed) LAPS credential for one computer.</summary>
public sealed record LapsResult(
    string Host,
    string? Username,
    string? Password,
    string? Expiration,
    bool V2,
    string? Note = null);

/// <summary>
/// Parsing helpers for Local Administrator Password Solution (MS-LAPS) directory attributes,
/// ported from impacket's <c>examples/GetLAPSPassword.py</c>. Three attributes carry a password:
/// <list type="bullet">
/// <item><c>ms-Mcs-AdmPwd</c> — legacy "LAPS v1": the local-admin password in cleartext.</item>
/// <item><c>msLAPS-Password</c> — Windows LAPS cleartext: a JSON document <c>{"n":user,"p":pass,"t":…}</c>.</item>
/// <item><c>msLAPS-EncryptedPassword</c> — Windows LAPS encrypted: a DPAPI-NG blob (decryption not ported here).</item>
/// </list>
/// LAPS passwords are readable only by principals the ACL permits; recovering one is a
/// privilege/misconfiguration signal, which is why this is a detection-relevant recon path.
/// </summary>
public static class LapsPassword
{
    /// <summary>
    /// Parses a Windows LAPS cleartext <c>msLAPS-Password</c> JSON value, returning the account
    /// name (<c>n</c>) and password (<c>p</c>). Returns nulls if the value is not the expected JSON.
    /// </summary>
    public static (string? Username, string? Password) ParseWindowsLapsCleartext(string json)
    {
        try
        {
            using JsonDocument doc = JsonDocument.Parse(json);
            JsonElement root = doc.RootElement;
            string? user = root.TryGetProperty("n", out JsonElement n) ? n.GetString() : null;
            string? pass = root.TryGetProperty("p", out JsonElement p) ? p.GetString() : null;
            return (user, pass);
        }
        catch (JsonException)
        {
            return (null, null);
        }
    }
}
