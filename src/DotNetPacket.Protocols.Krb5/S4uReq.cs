using System.Formats.Asn1;
using System.Text;

namespace DotNetPacket.Protocols.Krb5;

/// <summary>
/// Builds the two S4U (MS-SFU) TGS-REQ extensions behind impacket's <c>getST.py</c> / the
/// constrained-delegation abuse that <c>findDelegation</c> enumerates targets for:
/// <list type="bullet">
/// <item><b>S4U2self</b> — a service, holding its own TGT, asks the KDC for a service ticket <i>to
/// itself</i> on behalf of an arbitrary user, identified by a <c>PA-FOR-USER</c> pa-data whose
/// checksum (KERB_CHECKSUM_HMAC_MD5, key usage 17, over the S4U byte array) proves the service knows
/// its TGT session key.</item>
/// <item><b>S4U2proxy</b> — using that ticket as an <c>additional-ticket</c> and the
/// <c>cname-in-addl-tkt</c> KDC option (plus a <c>PA-PAC-OPTIONS</c> RBCD flag), the service asks for a
/// ticket to a <i>target</i> SPN on behalf of the same user.</item>
/// </list>
/// The authenticator checksum rule for PA-FOR-USER is special: it is always HMAC-MD5 keyed with the TGT
/// session key, even when the TGT is AES — per MS-SFU 2.2.1 and impacket's getST.
/// </summary>
public static class S4uReq
{
    private static Asn1Tag Ctx(int n) => new(TagClass.ContextSpecific, n, isConstructed: true);

    /// <summary>
    /// Encodes an S4U2self TGS-REQ: the service (<paramref name="tgt"/>) requests a ticket to itself
    /// (<paramref name="selfName"/>, NT-UNKNOWN) on behalf of <paramref name="impersonate"/>@<paramref name="impersonateRealm"/>.
    /// </summary>
    public static byte[] BuildS4u2Self(
        Tgt tgt, string impersonate, string impersonateRealm, string selfName,
        uint nonce, DateTimeOffset till, DateTimeOffset now, int usec, byte[] authConfounder)
    {
        byte[] reqBody = EncodeReqBody(
            Krb5Constants.KdcOptionsS4u2Self, tgt.Realm,
            sname: (Krb5Constants.NtUnknown, new[] { selfName }),
            till, nonce, tgt.SessionKeyEtype, additionalTicket: null);

        byte[] apReq = TgsReq.BuildPaTgsReqApReq(tgt, now, usec, authConfounder, reqBody);
        byte[] paForUser = EncodePaForUser(tgt.SessionKey, impersonate, impersonateRealm);

        return Assemble(apReq, Krb5Constants.PaForUser, paForUser, reqBody);
    }

    /// <summary>
    /// Encodes an S4U2proxy TGS-REQ: using <paramref name="s4u2SelfTicket"/> (the raw [APPLICATION 1]
    /// ticket from the S4U2self reply) as an additional-ticket, request a ticket to <paramref name="targetSpn"/>.
    /// </summary>
    public static byte[] BuildS4u2Proxy(
        Tgt tgt, byte[] s4u2SelfTicket, string targetSpn,
        uint nonce, DateTimeOffset till, DateTimeOffset now, int usec, byte[] authConfounder)
    {
        byte[] reqBody = EncodeReqBody(
            Krb5Constants.KdcOptionsS4u2Proxy, tgt.Realm,
            sname: (Krb5Constants.NtSrvInst, targetSpn.Split('/')),
            till, nonce, tgt.SessionKeyEtype, additionalTicket: s4u2SelfTicket);

        byte[] apReq = TgsReq.BuildPaTgsReqApReq(tgt, now, usec, authConfounder, reqBody);
        byte[] paPacOptions = EncodePaPacOptions();

        return Assemble(apReq, Krb5Constants.PaPacOptions, paPacOptions, reqBody);
    }

    // TGS-REQ ::= [APPLICATION 12] { pvno, msg-type, padata[PA-TGS-REQ, <extra>], req-body }
    private static byte[] Assemble(byte[] apReq, int extraPadataType, byte[] extraPadataValue, byte[] reqBody)
    {
        var w = new AsnWriter(AsnEncodingRules.DER);
        using (w.PushSequence(new Asn1Tag(TagClass.Application, Krb5Constants.TgsReq)))
        using (w.PushSequence())
        {
            using (w.PushSequence(Ctx(1))) w.WriteInteger(Krb5Constants.Pvno);
            using (w.PushSequence(Ctx(2))) w.WriteInteger(Krb5Constants.TgsReq);

            using (w.PushSequence(Ctx(3)))                        // padata [3] SEQUENCE OF
            using (w.PushSequence())
            {
                WritePaData(w, Krb5Constants.PaTgsReq, apReq);    // PA-TGS-REQ
                WritePaData(w, extraPadataType, extraPadataValue); // PA-FOR-USER or PA-PAC-OPTIONS
            }

            using (w.PushSequence(Ctx(4))) w.WriteEncodedValue(reqBody); // req-body [4] (same bytes checksummed)
        }

        return w.Encode();
    }

    // KDC-REQ-BODY ::= { kdc-options[0], realm[2], sname[3], till[5], nonce[7], etype[8], additional-tickets[11]? }
    private static byte[] EncodeReqBody(
        byte[] kdcOptions, string realm, (int NameType, string[] Components) sname,
        DateTimeOffset till, uint nonce, int etype, byte[]? additionalTicket)
    {
        var w = new AsnWriter(AsnEncodingRules.DER);
        using (w.PushSequence())
        {
            using (w.PushSequence(Ctx(0))) w.WriteBitString(kdcOptions);
            using (w.PushSequence(Ctx(2))) w.WriteEncodedValue(Der.GeneralString(realm.ToUpperInvariant()));
            using (w.PushSequence(Ctx(3))) WritePrincipalName(w, sname.NameType, sname.Components);
            using (w.PushSequence(Ctx(5))) w.WriteGeneralizedTime(till, omitFractionalSeconds: true);
            using (w.PushSequence(Ctx(7))) w.WriteInteger(nonce);
            using (w.PushSequence(Ctx(8)))                        // etype [8]: the TGT etype, then RC4
            using (w.PushSequence())
            {
                w.WriteInteger(etype);
                if (etype != Krb5Constants.Rc4Hmac)
                {
                    w.WriteInteger(Krb5Constants.Rc4Hmac);
                }
            }

            if (additionalTicket is not null)
            {
                using (w.PushSequence(Ctx(11)))                   // additional-tickets [11] SEQUENCE OF Ticket
                using (w.PushSequence())
                {
                    w.WriteEncodedValue(additionalTicket);
                }
            }
        }

        return w.Encode();
    }

    // PA-FOR-USER-ENC ::= { userName[0] PrincipalName, userRealm[1] Realm, cksum[2] Checksum, auth-package[3] KerberosString }
    private static byte[] EncodePaForUser(byte[] tgtSessionKey, string impersonate, string realm)
    {
        realm = realm.ToUpperInvariant();                    // keep the checksum and the field consistent
        byte[] s4uByteArray = BuildS4uByteArray(impersonate, realm);
        // MS-SFU: KERB_CHECKSUM_HMAC_MD5 keyed with the TGT session key, key usage 17 — regardless of etype.
        byte[] cksum = Krb5Crypto.Rc4HmacChecksum(tgtSessionKey, 17, s4uByteArray);

        var w = new AsnWriter(AsnEncodingRules.DER);
        using (w.PushSequence())
        {
            using (w.PushSequence(Ctx(0))) WritePrincipalName(w, Krb5Constants.NtPrincipal, new[] { impersonate });
            using (w.PushSequence(Ctx(1))) w.WriteEncodedValue(Der.GeneralString(realm));
            using (w.PushSequence(Ctx(2)))                        // cksum [2] Checksum
            using (w.PushSequence())
            {
                using (w.PushSequence(Ctx(0))) w.WriteInteger(Krb5Constants.Rc4HmacChecksumType); // -138 (hmac-md5)
                using (w.PushSequence(Ctx(1))) w.WriteOctetString(cksum);
            }

            using (w.PushSequence(Ctx(3))) w.WriteEncodedValue(Der.GeneralString("Kerberos"));
        }

        return w.Encode();
    }

    // S4UByteArray = LE32(NT-PRINCIPAL=1) || impersonate || realm || "Kerberos"  (MS-SFU / impacket getST).
    private static byte[] BuildS4uByteArray(string impersonate, string realm)
    {
        var ms = new MemoryStream();
        ms.Write(new byte[] { Krb5Constants.NtPrincipal, 0, 0, 0 }); // name-type NT-PRINCIPAL, little-endian uint32
        ms.Write(Encoding.UTF8.GetBytes(impersonate));
        ms.Write(Encoding.UTF8.GetBytes(realm));
        ms.Write(Encoding.UTF8.GetBytes("Kerberos"));
        return ms.ToArray();
    }

    // PA-PAC-OPTIONS ::= { flags[0] KerberosFlags } with the RBCD bit set.
    private static byte[] EncodePaPacOptions()
    {
        var w = new AsnWriter(AsnEncodingRules.DER);
        using (w.PushSequence())
        {
            using (w.PushSequence(Ctx(0))) w.WriteBitString(Krb5Constants.PacOptionsRbcd);
        }

        return w.Encode();
    }

    private static void WritePaData(AsnWriter w, int type, byte[] value)
    {
        using (w.PushSequence())
        {
            using (w.PushSequence(Ctx(1))) w.WriteInteger(type);
            using (w.PushSequence(Ctx(2))) w.WriteOctetString(value);
        }
    }

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
