using DotNetPacket.Protocols.Krb5;

namespace DotNetPacket.Examples;

/// <summary>
/// getPac: recover and parse the PAC a Kerberos ticket carries. A service account (whose key we hold)
/// requests, via S4U2self ([MS-SFU]), a ticket to itself on behalf of an impersonated user; that ticket
/// is encrypted under the service's own long-term key, so we can decrypt it (key usage 2) and read the
/// impersonated user's PAC ([MS-PAC]). This is the classic getPac.py flow. Lab-first, authorized use only.
/// </summary>
/// <remarks>
/// The PAC is the identity a ticket asserts — the account RID, primary group, group RIDs and any
/// ExtraSids (SID history / injected privileged SIDs). Golden/silver-ticket and SID-history-injection
/// detections key on exactly these fields (and on the PAC's server/KDC checksums), so this command lets
/// the SOC pull a real PAC off the wire and inspect it.
/// </remarks>
internal static class GetPac
{
    public static int Run(string[] args)
    {
        if (args.Length < 6)
        {
            Console.Error.WriteLine(
                "usage: getpac <dc-host> <service-user> <domain-fqdn> <impersonate-user> <service-key-hex> [krbtgt-key-hex] [port]");
            Console.Error.WriteLine(
                "       service-key-hex: the service account's RC4/NT hash (32 hex) or AES-256 key (64 hex).");
            Console.Error.WriteLine(
                "       krbtgt-key-hex (optional): the krbtgt key to also verify the KDC/PRIVSVR signature.");
            return 2;
        }

        string host = args[1];
        string serviceUser = args[2];
        string realm = args[3].ToUpperInvariant();
        string impersonate = args[4];
        byte[] key = Convert.FromHexString(args[5]);
        byte[]? krbtgtKey = args.Length >= 7 ? Convert.FromHexString(args[6]) : null;
        int port = args.Length >= 8 ? int.Parse(args[7]) : 88;

        int etype = key.Length switch
        {
            16 => Krb5Constants.Rc4Hmac,
            32 => Krb5Constants.Aes256CtsHmacSha1,
            _ => throw new ArgumentException("service-key-hex must be 32 hex (RC4/NT hash) or 64 hex (AES-256)."),
        };

        // 1) Service TGT via the supplied key (overpass-the-hash), then S4U2self for the impersonated user.
        Tgt tgt = etype == Krb5Constants.Rc4Hmac
            ? KerberosClient.GetTgtWithKey(host, realm, serviceUser, key, port)
            : KerberosClient.GetTgtWithKeyEtype(host, realm, serviceUser, key, etype, port);
        Console.WriteLine($"TGT for {serviceUser}@{realm} (etype {tgt.SessionKeyEtype}).");

        byte[] ticket = KerberosClient.GetS4u2SelfTicket(host, tgt, impersonate, port);
        Console.WriteLine($"S4U2self ticket for '{impersonate}' to service '{serviceUser}'.");

        // 2) Decrypt the ticket's enc-part with the service key and lift the PAC out of its auth-data.
        byte[]? pacBlob = KerberosTicket.DecryptPac(ticket, key, etype);
        if (pacBlob is null)
        {
            Console.Error.WriteLine("Ticket carries no AD-WIN2K-PAC (no PAC to parse).");
            return 1;
        }

        Console.WriteLine($"Decrypted ticket; PAC is {pacBlob.Length} bytes.");
        Console.WriteLine();

        // 3) Parse and print the PAC.
        PacInfo pac = Pac.Parse(pacBlob);
        PrintPac(pac);

        // 4) Verify the PAC signatures (forged-PAC detection): the server checksum under the service
        //    key, and — if a krbtgt key was supplied — the KDC signature under it.
        Console.WriteLine();
        PacVerifyResult v = Pac.Verify(pacBlob, key, krbtgtKey);
        Console.WriteLine($"SERVER signature (type {v.ServerType}, service key): {(v.ServerOk ? "VALID" : "INVALID")}");
        Console.WriteLine(v.KdcOk is { } k
            ? $"KDC    signature (type {v.KdcType}, krbtgt key) : {(k ? "VALID" : "INVALID")}"
            : $"KDC    signature (type {v.KdcType}) : not checked (no krbtgt key supplied)");
        return 0;
    }

    private static void PrintPac(PacInfo pac)
    {
        Console.WriteLine($"PAC version {pac.Version}, {pac.Buffers.Count} buffer(s):");
        foreach (PacBuffer b in pac.Buffers)
        {
            Console.WriteLine($"  type {b.Type,-3} ({BufferName(b.Type)})  {b.Size} bytes @ offset {b.Offset}");
        }

        Console.WriteLine();

        if (pac.LogonInfo is { } li)
        {
            Console.WriteLine("LOGON_INFO (KERB_VALIDATION_INFO):");
            Console.WriteLine($"  EffectiveName  : {li.EffectiveName}");
            if (!string.IsNullOrEmpty(li.FullName))
            {
                Console.WriteLine($"  FullName       : {li.FullName}");
            }

            Console.WriteLine($"  LogonDomain    : {li.LogonDomainName}  ({li.LogonDomainSid ?? "?"})");
            if (!string.IsNullOrEmpty(li.LogonServer))
            {
                Console.WriteLine($"  LogonServer    : {li.LogonServer}");
            }

            Console.WriteLine($"  UserId (RID)   : {li.UserId}");
            Console.WriteLine($"  PrimaryGroup   : {li.PrimaryGroupId}");
            Console.WriteLine($"  UserAccCtrl    : 0x{li.UserAccountControl:x8}");
            Console.WriteLine($"  UserFlags      : 0x{li.UserFlags:x8}");
            if (li.LogonTime is { } lt)
            {
                Console.WriteLine($"  LogonTime      : {lt:u}");
            }

            string sidBase = li.LogonDomainSid ?? "<domain>";
            Console.WriteLine($"  Groups ({li.Groups.Count}): {string.Join(", ", li.Groups.Select(g => $"{g.Rid}"))}");
            foreach (PacGroup g in li.Groups)
            {
                Console.WriteLine($"    {sidBase}-{g.Rid}  (attr 0x{g.Attributes:x8})");
            }

            if (li.ExtraSids.Count > 0)
            {
                Console.WriteLine($"  ExtraSids ({li.ExtraSids.Count})  <-- SID history / injected SIDs:");
                foreach (string s in li.ExtraSids)
                {
                    Console.WriteLine($"    {s}");
                }
            }

            Console.WriteLine();
        }

        if (pac.ClientInfo is { } ci)
        {
            Console.WriteLine($"CLIENT_INFO: name='{ci.Name}'" + (ci.ClientId is { } t ? $", authtime={t:u}" : ""));
        }

        if (pac.UpnDnsInfo is { } u && (!string.IsNullOrEmpty(u.Upn) || !string.IsNullOrEmpty(u.DnsDomainName)))
        {
            Console.WriteLine($"UPN_DNS_INFO: upn='{u.Upn}', dnsDomain='{u.DnsDomainName}'");
        }

        if (pac.ServerChecksum is { } sc)
        {
            Console.WriteLine($"SERVER_CHECKSUM: type {sc.Type}, {sc.Signature.Length} bytes {Convert.ToHexString(sc.Signature).ToLowerInvariant()}");
        }

        if (pac.KdcChecksum is { } kc)
        {
            Console.WriteLine($"KDC_CHECKSUM   : type {kc.Type}, {kc.Signature.Length} bytes {Convert.ToHexString(kc.Signature).ToLowerInvariant()}");
        }
    }

    private static string BufferName(uint type) => type switch
    {
        Pac.LogonInfo => "LOGON_INFO",
        Pac.ServerChecksum => "SERVER_CHECKSUM",
        Pac.PrivSvrChecksum => "KDC_CHECKSUM",
        Pac.ClientInfo => "CLIENT_INFO",
        Pac.UpnDnsInfo => "UPN_DNS_INFO",
        11 => "DEVICE_INFO",
        13 => "ATTRIBUTES",
        14 => "REQUESTOR",
        17 => "ATTRIBUTES_INFO",
        _ => "other",
    };
}
