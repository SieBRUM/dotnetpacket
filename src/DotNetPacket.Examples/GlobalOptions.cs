using DotNetPacket.Core.Net;
using DotNetPacket.Protocols.Ntlm;
using DotNetPacket.Protocols.Smb;

namespace DotNetPacket.Examples;

/// <summary>
/// Parses the impacket-style global options that apply to any command, wherever they appear on the
/// command line, and configures the process from them:
/// <list type="bullet">
///   <item><description><c>-hashes LMHASH:NTHASH</c> — pass-the-hash (only NTHASH is used for NTLMv2).</description></item>
///   <item><description><c>-no-pass</c> — don't require/derive a password (use with <c>-hashes</c>).</description></item>
///   <item><description><c>-proxy &lt;url&gt;</c> — route all TCP through a SOCKS/HTTP proxy
///   (<c>socks5://[user:pass@]host:port</c>, <c>socks4a://host:port</c>, <c>http://host:port</c>).</description></item>
/// </list>
/// Recognised options (and their values) are stripped from the returned argument array, so each
/// command's existing positional parsing is unchanged. Unknown <c>-flags</c> are left in place.
/// </summary>
internal static class GlobalOptions
{
    public static string[] Apply(string[] args)
    {
        var rest = new List<string>(args.Length);
        for (int i = 0; i < args.Length; i++)
        {
            string a = args[i];
            switch (a)
            {
                case "-hashes" when i + 1 < args.Length:
                    SetHashes(args[++i]);
                    break;
                case "-proxy" when i + 1 < args.Length:
                    ProxyConnector.Default = ProxyEndpoint.Parse(args[++i]);
                    Console.Error.WriteLine($"[*] Routing all connections through proxy {ProxyConnector.Default}");
                    break;
                case "-no-pass":
                    // No prompt in this CLI; meaningful together with -hashes (password slot ignored).
                    break;
                case "-k":
                    Smb2Client.UseKerberos = true;
                    Console.Error.WriteLine("[*] Kerberos authentication enabled (-k): SMB login uses a Kerberos AP-REQ. With a password the KDC's etypes are probed and the strongest is used (AES-256, matching impacket's default); the login's domain is the realm and the host is the SPN (cifs/<host>).");
                    break;
                case "-aesKey" when i + 1 < args.Length:
                    SetAesKey(args[++i]);
                    break;
                case "-dc-ip" when i + 1 < args.Length:
                    Smb2Client.KerberosKdc = args[++i];
                    break;
                case "-target-ip" when i + 1 < args.Length:
                    Smb2Client.TargetIpOverride = args[++i];
                    break;
                default:
                    rest.Add(a);
                    break;
            }
        }

        return rest.ToArray();
    }

    private static void SetHashes(string value)
    {
        // Accept "LMHASH:NTHASH" or just "NTHASH"; only the NT hash is used for NTLMv2.
        string ntHex = value.Contains(':') ? value[(value.LastIndexOf(':') + 1)..] : value;
        ntHex = ntHex.Trim();
        if (ntHex.Length != 32 || !IsHex(ntHex))
        {
            throw new FormatException($"-hashes: '{value}' is not a valid LMHASH:NTHASH (NT hash must be 32 hex chars).");
        }

        NtlmClient.NtHashOverride = Convert.FromHexString(ntHex);
        Console.Error.WriteLine("[*] Pass-the-hash enabled (authenticating with the supplied NT hash; the password argument is ignored).");
    }

    private static void SetAesKey(string value)
    {
        // impacket's -aesKey: a 128-bit (32 hex) or 256-bit (64 hex) AES Kerberos key.
        string hex = value.Trim();
        if ((hex.Length != 32 && hex.Length != 64) || !IsHex(hex))
        {
            throw new FormatException($"-aesKey: '{value}' must be 32 hex chars (AES-128) or 64 hex chars (AES-256).");
        }

        Smb2Client.KerberosAesKey = Convert.FromHexString(hex);
        Smb2Client.UseKerberos = true;
        Console.Error.WriteLine($"[*] Kerberos AES key supplied (-aesKey, aes{(hex.Length == 64 ? "256" : "128")}-cts); authenticating with it (overpass-the-hash).");
    }

    private static bool IsHex(string s)
    {
        foreach (char c in s)
        {
            if (!Uri.IsHexDigit(c))
            {
                return false;
            }
        }

        return true;
    }
}
