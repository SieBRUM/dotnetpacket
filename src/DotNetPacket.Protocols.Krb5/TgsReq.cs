using System.Formats.Asn1;

namespace DotNetPacket.Protocols.Krb5;

/// <summary>
/// Builds a Kerberos TGS-REQ (RFC 4120 5.4.1) for a service ticket — the Kerberoasting request.
/// It carries a PA-TGS-REQ pa-data wrapping an AP-REQ (the TGT + an authenticator encrypted under
/// the TGT session key, key usage 7), and a req-body whose sname is the target SPN. Ported from
/// impacket's <c>getKerberosTGS</c>.
/// </summary>
public static class TgsReq
{
    private static Asn1Tag Ctx(int n) => new(TagClass.ContextSpecific, n, isConstructed: true);

    /// <summary>
    /// Encodes a TGS-REQ requesting a ticket for <paramref name="spn"/>, authenticated with
    /// <paramref name="tgt"/>. <paramref name="now"/>/<paramref name="usec"/> date the authenticator;
    /// <paramref name="authConfounder"/> is the RC4 confounder (fixed for deterministic tests).
    /// </summary>
    public static byte[] Build(Tgt tgt, string spn, uint nonce, DateTimeOffset till, DateTimeOffset now, int usec,
        byte[] authConfounder, int etype = Krb5Constants.Rc4Hmac)
    {
        string[] snameComponents = spn.Split('/');

        // Encode the bare KDC-REQ-BODY first; its checksum goes into the authenticator (usage 6).
        byte[] reqBody = EncodeKdcReqBody(tgt.Realm, snameComponents, till, nonce, etype);
        byte[] apReq = BuildApReq(tgt, now, usec, authConfounder, reqBody);

        var w = new AsnWriter(AsnEncodingRules.DER);
        using (w.PushSequence(new Asn1Tag(TagClass.Application, Krb5Constants.TgsReq))) // TGS-REQ [APPLICATION 12]
        using (w.PushSequence())
        {
            using (w.PushSequence(Ctx(1))) w.WriteInteger(Krb5Constants.Pvno);  // pvno [1]
            using (w.PushSequence(Ctx(2))) w.WriteInteger(Krb5Constants.TgsReq); // msg-type [2]

            using (w.PushSequence(Ctx(3)))                                       // padata [3] SEQUENCE OF
            using (w.PushSequence())
            using (w.PushSequence())                                            // PA-DATA
            {
                using (w.PushSequence(Ctx(1))) w.WriteInteger(Krb5Constants.PaTgsReq); // padata-type [1] = PA-TGS-REQ
                using (w.PushSequence(Ctx(2))) w.WriteOctetString(apReq);        // padata-value [2] = AP-REQ
            }

            using (w.PushSequence(Ctx(4))) w.WriteEncodedValue(reqBody);         // req-body [4] (same bytes checksummed)
        }

        return w.Encode();
    }

    // KDC-REQ-BODY ::= SEQUENCE { kdc-options[0], realm[2], sname[3], till[5], nonce[7], etype[8] }
    private static byte[] EncodeKdcReqBody(string realm, string[] snameComponents, DateTimeOffset till, uint nonce, int etype)
    {
        var w = new AsnWriter(AsnEncodingRules.DER);
        using (w.PushSequence())
        {
            using (w.PushSequence(Ctx(0))) w.WriteBitString(Krb5Constants.KdcOptionsTgs); // kdc-options [0]
            using (w.PushSequence(Ctx(2))) w.WriteEncodedValue(Der.GeneralString(realm)); // realm [2]
            using (w.PushSequence(Ctx(3))) WriteSrvName(w, snameComponents);              // sname [3]
            using (w.PushSequence(Ctx(5))) w.WriteGeneralizedTime(till, omitFractionalSeconds: true); // till [5]
            using (w.PushSequence(Ctx(7))) w.WriteInteger(nonce);                         // nonce [7]
            using (w.PushSequence(Ctx(8)))                                                // etype [8]
            using (w.PushSequence())
            {
                w.WriteInteger(etype);
            }
        }

        return w.Encode();
    }

    // AP-REQ ::= [APPLICATION 14] SEQUENCE { pvno[0], msg-type[1], ap-options[2], ticket[3], authenticator[4] }
    private static byte[] BuildApReq(Tgt tgt, DateTimeOffset now, int usec, byte[] authConfounder, byte[] reqBody)
    {
        byte[] authenticator = BuildAuthenticator(tgt, now, usec, reqBody);
        byte[] encAuth = Krb5Crypto.Encrypt(tgt.SessionKey, 7, authenticator, authConfounder); // key usage 7

        var w = new AsnWriter(AsnEncodingRules.DER);
        using (w.PushSequence(new Asn1Tag(TagClass.Application, Krb5Constants.ApReq)))
        using (w.PushSequence())
        {
            using (w.PushSequence(Ctx(0))) w.WriteInteger(Krb5Constants.Pvno);  // pvno [0]
            using (w.PushSequence(Ctx(1))) w.WriteInteger(Krb5Constants.ApReq); // msg-type [1] = 14
            using (w.PushSequence(Ctx(2))) w.WriteBitString(new byte[4]);        // ap-options [2] (empty)
            using (w.PushSequence(Ctx(3))) w.WriteEncodedValue(tgt.Ticket);      // ticket [3] (the TGT)
            using (w.PushSequence(Ctx(4)))                                       // authenticator [4] EncryptedData
            using (w.PushSequence())
            {
                using (w.PushSequence(Ctx(0))) w.WriteInteger(Krb5Constants.Rc4Hmac); // etype [0]
                using (w.PushSequence(Ctx(2))) w.WriteOctetString(encAuth);      // cipher [2]
            }
        }

        return w.Encode();
    }

    // Authenticator ::= [APPLICATION 2] SEQUENCE { authenticator-vno[0], crealm[1], cname[2], cksum[3], cusec[4], ctime[5] }
    // The cksum is a keyed HMAC-MD5 over the KDC-REQ-BODY (key usage 6) — required by the Heimdal/Samba KDC.
    private static byte[] BuildAuthenticator(Tgt tgt, DateTimeOffset now, int usec, byte[] reqBody)
    {
        byte[] cksum = Krb5Crypto.Rc4HmacChecksum(tgt.SessionKey, 6, reqBody);

        var w = new AsnWriter(AsnEncodingRules.DER);
        using (w.PushSequence(new Asn1Tag(TagClass.Application, Krb5Constants.Authenticator)))
        using (w.PushSequence())
        {
            using (w.PushSequence(Ctx(0))) w.WriteInteger(Krb5Constants.Pvno);  // authenticator-vno [0]
            using (w.PushSequence(Ctx(1))) w.WriteEncodedValue(Der.GeneralString(tgt.Realm)); // crealm [1]
            using (w.PushSequence(Ctx(2))) WritePrincipalName(w, tgt.User);      // cname [2]
            using (w.PushSequence(Ctx(3)))                                       // cksum [3] Checksum
            using (w.PushSequence())
            {
                using (w.PushSequence(Ctx(0))) w.WriteInteger(Krb5Constants.Rc4HmacChecksumType); // cksumtype [0]
                using (w.PushSequence(Ctx(1))) w.WriteOctetString(cksum);        // checksum [1]
            }

            using (w.PushSequence(Ctx(4))) w.WriteInteger(usec);                 // cusec [4]
            using (w.PushSequence(Ctx(5))) w.WriteGeneralizedTime(now, omitFractionalSeconds: true); // ctime [5]
        }

        return w.Encode();
    }

    // PrincipalName NT-PRINCIPAL, single component (the client name).
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

    // PrincipalName NT-SRV-INST, SPN components (e.g. ["MSSQLSvc", "db.lab.local:1433"]).
    private static void WriteSrvName(AsnWriter w, string[] components)
    {
        using (w.PushSequence())
        {
            using (w.PushSequence(Ctx(0))) w.WriteInteger(Krb5Constants.NtSrvInst);
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
