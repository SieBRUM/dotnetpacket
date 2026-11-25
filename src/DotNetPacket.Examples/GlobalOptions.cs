using DotNetPacket.Core.Diagnostics;
using DotNetPacket.Core.Net;
using DotNetPacket.Protocols.Krb5;
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
///   <item><description><c>-verbose</c> / <c>-v</c> — trace every message on the wire (connect,
///   direction, byte count) on stderr, for any command; <c>-debug</c> adds a full hex dump. These
///   drive <see cref="PacketTrace"/> and are observability only — no byte changes on the wire.</description></item>
/// </list>
/// Recognised options (and their values) are stripped from the returned argument array, so each
/// command's existing positional parsing is unchanged. Unknown <c>-flags</c> are left in place.
/// </summary>
internal static class GlobalOptions
{
    /// <summary>When set (<c>-save-ccache &lt;file&gt;</c>), kerb-tgt / get-st write the obtained ticket here.</summary>
    public static string? SaveCcachePath { get; set; }

    /// <summary><c>-no-pass</c> was given.</summary>
    public static bool NoPass { get; set; }

    /// <summary><c>-ldaps</c> was given: the LDAP tools connect over TLS (port 636) instead of plaintext 389.</summary>
    public static bool UseLdaps { get; set; }

    /// <summary>
    /// True when authentication does not need a password because a ticket or a hash was supplied
    /// (<c>-hashes</c> / <c>-aesKey</c> / a loaded ccache / <c>-no-pass</c>) — the impacket behaviour
    /// where the password is optional in those cases.
    /// </summary>
    public static bool PasswordOptional =>
        NoPass
        || NtlmClient.NtHashOverride is not null
        || Smb2Client.KerberosAesKey is not null
        || KerberosClient.LoadedTgt is not null;

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
                    // No prompt in this CLI; marks the password optional (use with -hashes / -k / ccache).
                    NoPass = true;
                    break;
                case "-verbose":
                case "-v":
                    // Verbose wire trace: one line per connect and per message (direction + channel +
                    // byte count) on every transport, to stderr. No hex. Realism-neutral (stderr only).
                    PacketTrace.Level = TraceLevel.Verbose;
                    Console.Error.WriteLine("[*] Verbose tracing enabled (-verbose): per-message wire summaries on stderr.");
                    break;
                case "-debug":
                    // Full debug trace: everything -verbose shows, plus a hex dump of every message on
                    // the wire (every transport). Handy for diffing bytes; stderr only, no wire change.
                    PacketTrace.Level = TraceLevel.Debug;
                    Console.Error.WriteLine("[*] Debug tracing enabled (-debug): per-message wire hex dumps on stderr.");
                    break;
                case "-ldaps":
                    // Connect the LDAP tools over TLS (636). Lets a simple bind work against a DC that
                    // refuses plaintext binds (LDAP signing / channel binding enforced). impacket: -use-ldaps.
                    UseLdaps = true;
                    Console.Error.WriteLine("[*] LDAPS enabled (-ldaps): LDAP tools connect over TLS on port 636.");
                    break;
                case "-smb3-seal":
                    // Turn on SMB 3.x session encryption (AES-CCM/GCM TRANSFORM_HEADER) after login; the
                    // only way to reach an `smb encrypt = required` share. Needs an SMB 3.1.1 session.
                    Smb2Client.EncryptionRequested = true;
                    Console.Error.WriteLine("[*] SMB3 encryption enabled (-smb3-seal): post-auth SMB2 messages are AES-encrypted.");
                    break;
                case "-k":
                    Smb2Client.UseKerberos = true;
                    Console.Error.WriteLine("[*] Kerberos authentication enabled (-k): SMB login uses a Kerberos AP-REQ. With a password the KDC's etypes are probed and the strongest is used (AES-256, matching impacket's default); the login's domain is the realm and the host is the SPN (cifs/<host>).");
                    break;
                case "-aesKey" when i + 1 < args.Length:
                    SetAesKey(args[++i]);
                    break;
                case "-ccache" when i + 1 < args.Length:
                    LoadCcache(args[++i]);
                    break;
                case "-save-ccache" when i + 1 < args.Length:
                    SaveCcachePath = args[++i];
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

        // impacket also honours KRB5CCNAME; load it if -k is on and no -ccache was given explicitly.
        if (KerberosClient.LoadedTgt is null && Smb2Client.UseKerberos &&
            Environment.GetEnvironmentVariable("KRB5CCNAME") is { Length: > 0 } ccname && File.Exists(ccname))
        {
            LoadCcache(ccname);
        }

        return rest.ToArray();
    }

    private static void LoadCcache(string path)
    {
        CCacheFile ccache = CCache.Parse(File.ReadAllBytes(path));
        Tgt tgt = CCache.ToTgt(ccache);
        KerberosClient.LoadedTgt = tgt;
        Smb2Client.UseKerberos = true;
        Console.Error.WriteLine($"[*] Loaded TGT for {tgt.User}@{tgt.Realm} (etype {tgt.SessionKeyEtype}) from ccache '{path}'; -k will use it.");
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
