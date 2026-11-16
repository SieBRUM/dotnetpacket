using System.Formats.Asn1;
using System.Security.Cryptography;

namespace DotNetPacket.Protocols.Krb5;

/// <summary>The GSS-API AP-REQ token to present to a service, plus the SMB/GSS session key (the service session key).</summary>
public sealed record KerberosApReq(byte[] GssToken, byte[] SessionKey, int SessionKeyEtype);

/// <summary>
/// Builds the GSS-API Kerberos AP-REQ token a client sends to authenticate to a service (the
/// mechToken inside SPNEGO for an SMB SESSION_SETUP or an LDAP GSS-SPNEGO bind). Faithful port of
/// impacket's <c>krb5.kerberosv5.getKerberosType1</c>: an authenticator carrying the GSS
/// channel-binding checksum (type 0x8003) with impacket's SMB flag set, encrypted under the service
/// session key (key usage 11), inside an AP-REQ with <c>mutual-required</c> ap-options, inside the
/// GSS-API framing (<c>[APPLICATION 0] { krb5-OID, 0x0001, AP-REQ }</c>). Like impacket, no subkey is
/// sent and the SMB session key is the service (TGS) session key.
/// </summary>
public static class KerberosGss
{
    // Mechanism OID 1.2.840.113554.1.2.2 (KRB5 - Kerberos 5), DER-encoded — the inner GSS mech.
    private static readonly byte[] Krb5MechOid = { 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x12, 0x01, 0x02, 0x02 };

    // GSS-API KRB5 AP-REQ token id.
    private static readonly byte[] ApReqTokenId = { 0x01, 0x00 };

    private const int GssChecksumType = 0x8003;          // KRB5 GSS per-RFC-1964 checksum
    private const uint SmbGssFlags = 0x0000003E;         // CONF|INTEG|SEQUENCE|REPLAY|MUTUAL (no DCE_STYLE -> single leg on Samba)

    /// <summary>GSS checksum flags for the LDAP bind: REPLAY|SEQUENCE|CONF|INTEG, no MUTUAL (matches impacket's ldap.py).</summary>
    public const uint LdapGssFlags = 0x0000003C;
    private const int ApReqAuthenticatorUsage = 11;      // KU_AP_REQ_AUTHENTICATOR

    private static Asn1Tag Ctx(int n) => new(TagClass.ContextSpecific, n, isConstructed: true);

    /// <summary>
    /// Builds the GSS AP-REQ token. <paramref name="mutualAuth"/> sets <c>mutual-required</c> ap-options
    /// and the GSS MUTUAL flag (SMB), or leaves them off (LDAP, matching impacket's ldap.py). A caller
    /// may override the GSS checksum flags via <paramref name="gssFlags"/> (e.g. LDAP uses
    /// REPLAY|SEQUENCE|CONF|INTEG without MUTUAL).
    /// </summary>
    public static KerberosApReq BuildApReqToken(ServiceTicket st, bool mutualAuth = true, uint? gssFlags = null)
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;

        byte[] authenticator = BuildAuthenticator(st, now, now.Microsecond, gssFlags ?? SmbGssFlags);
        // Encrypt the authenticator under the service session key (usage 11), in the ticket's etype
        // (RC4 or AES) — Krb5Cipher picks the right profile and confounder size.
        byte[] encAuth = Krb5Cipher.Encrypt(st.SessionKeyEtype, st.SessionKey, ApReqAuthenticatorUsage, authenticator);

        var w = new AsnWriter(AsnEncodingRules.DER);
        using (w.PushSequence(new Asn1Tag(TagClass.Application, Krb5Constants.ApReq)))   // AP-REQ [APPLICATION 14]
        using (w.PushSequence())
        {
            using (w.PushSequence(Ctx(0))) w.WriteInteger(Krb5Constants.Pvno);           // pvno [0]
            using (w.PushSequence(Ctx(1))) w.WriteInteger(Krb5Constants.ApReq);          // msg-type [1] = 14
            // ap-options [2]: mutual-required (bit 2) for SMB; empty for LDAP (matches impacket).
            using (w.PushSequence(Ctx(2))) w.WriteBitString(mutualAuth ? new byte[] { 0x20, 0x00, 0x00, 0x00 } : new byte[4]);
            using (w.PushSequence(Ctx(3))) w.WriteEncodedValue(st.Ticket);               // ticket [3]
            using (w.PushSequence(Ctx(4)))                                               // authenticator [4] EncryptedData
            using (w.PushSequence())
            {
                using (w.PushSequence(Ctx(0))) w.WriteInteger(st.SessionKeyEtype);       // etype [0]
                using (w.PushSequence(Ctx(2))) w.WriteOctetString(encAuth);              // cipher [2]
            }
        }

        byte[] apReq = w.Encode();

        // GSS-API InitialContextToken: [APPLICATION 0] IMPLICIT { krb5-OID, TOK_ID(0x0001), AP-REQ }.
        byte[] inner = Concat(Krb5MechOid, ApReqTokenId, apReq);
        byte[] gssToken = WrapApplication0(inner);

        // Per impacket, the SMB session key is the service (TGS) session key (first 16 bytes for RC4).
        byte[] sessionKey = st.SessionKey.Length > 16 ? st.SessionKey[..16] : st.SessionKey;
        return new KerberosApReq(gssToken, sessionKey, st.SessionKeyEtype);
    }

    // Authenticator ::= [APPLICATION 2] SEQUENCE { vno[0], crealm[1], cname[2], cksum[3], cusec[4], ctime[5], seq[7] }
    // No subkey [6] — matches impacket; the service session key is used for SMB.
    private static byte[] BuildAuthenticator(ServiceTicket st, DateTimeOffset now, int usec, uint gssFlags)
    {
        byte[] gssChecksum = BuildGssChecksum(gssFlags);

        var w = new AsnWriter(AsnEncodingRules.DER);
        using (w.PushSequence(new Asn1Tag(TagClass.Application, Krb5Constants.Authenticator)))
        using (w.PushSequence())
        {
            using (w.PushSequence(Ctx(0))) w.WriteInteger(Krb5Constants.Pvno);                    // authenticator-vno [0]
            using (w.PushSequence(Ctx(1))) w.WriteEncodedValue(Der.GeneralString(st.Realm));       // crealm [1]
            using (w.PushSequence(Ctx(2))) WritePrincipalName(w, st.User);                         // cname [2]
            using (w.PushSequence(Ctx(3)))                                                         // cksum [3]
            using (w.PushSequence())
            {
                using (w.PushSequence(Ctx(0))) w.WriteInteger(GssChecksumType);                    // cksumtype [0] = 0x8003
                using (w.PushSequence(Ctx(1))) w.WriteOctetString(gssChecksum);                    // checksum [1]
            }

            using (w.PushSequence(Ctx(4))) w.WriteInteger(usec);                                   // cusec [4]
            using (w.PushSequence(Ctx(5))) w.WriteGeneralizedTime(now, omitFractionalSeconds: true); // ctime [5]
            using (w.PushSequence(Ctx(7))) w.WriteInteger(0);                                      // seq-number [7] = 0 (impacket)
        }

        return w.Encode();
    }

    // RFC 1964 2.2.1 checksum value: Lgth(4 LE)=16, Bnd(16 zero bytes), Flags(4 LE).
    private static byte[] BuildGssChecksum(uint gssFlags)
    {
        var cksum = new byte[24];
        BitConverter.TryWriteBytes(cksum.AsSpan(0, 4), (uint)16);           // Lgth (channel-binding length)
        BitConverter.TryWriteBytes(cksum.AsSpan(20, 4), gssFlags);          // Flags
        if (!BitConverter.IsLittleEndian)
        {
            Array.Reverse(cksum, 0, 4);
            Array.Reverse(cksum, 20, 4);
        }

        return cksum;
    }

    private static void WritePrincipalName(AsnWriter w, string name)
    {
        using (w.PushSequence())
        {
            using (w.PushSequence(Ctx(0))) w.WriteInteger(Krb5Constants.NtPrincipal);
            using (w.PushSequence(Ctx(1)))
            using (w.PushSequence())
            {
                w.WriteEncodedValue(Der.GeneralString(name));
            }
        }
    }

    // Wrap content in [APPLICATION 0] IMPLICIT (tag 0x60) with a DER length.
    private static byte[] WrapApplication0(byte[] content)
    {
        byte[] len = EncodeDerLength(content.Length);
        var outBuf = new byte[1 + len.Length + content.Length];
        outBuf[0] = 0x60;
        Buffer.BlockCopy(len, 0, outBuf, 1, len.Length);
        Buffer.BlockCopy(content, 0, outBuf, 1 + len.Length, content.Length);
        return outBuf;
    }

    private static byte[] EncodeDerLength(int length)
    {
        if (length < 0x80)
        {
            return new[] { (byte)length };
        }

        var bytes = new List<byte>();
        int v = length;
        while (v > 0)
        {
            bytes.Insert(0, (byte)(v & 0xFF));
            v >>= 8;
        }

        bytes.Insert(0, (byte)(0x80 | bytes.Count));
        return bytes.ToArray();
    }

    private static byte[] Concat(params byte[][] parts)
    {
        int total = 0;
        foreach (byte[] p in parts) total += p.Length;
        var result = new byte[total];
        int offset = 0;
        foreach (byte[] p in parts)
        {
            Buffer.BlockCopy(p, 0, result, offset, p.Length);
            offset += p.Length;
        }

        return result;
    }
}
