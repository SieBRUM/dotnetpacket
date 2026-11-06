using System.Formats.Asn1;

namespace DotNetPacket.Protocols.Krb5;

/// <summary>
/// Builds a Kerberos AS-REQ (RFC 4120 5.4.1). Two shapes:
/// <list type="bullet">
/// <item><see cref="Build"/> — no encrypted pre-auth (GetNPUsers / AS-REP roasting): only a
/// PA-PAC-REQUEST pa-data; the KDC answers AS-REP (roastable) or KRB-ERROR (pre-auth required).</item>
/// <item><see cref="BuildPreauth"/> — with a PA-ENC-TIMESTAMP (the normal getTGT path): an
/// encrypted timestamp proving knowledge of the client key, so the KDC returns a usable TGT.</item>
/// </list>
/// All context tags are EXPLICIT, as Kerberos uses.
/// </summary>
public static class AsReq
{
    private static Asn1Tag Ctx(int n) => new(TagClass.ContextSpecific, n, isConstructed: true);

    private static readonly int[] DefaultEtypes = { Krb5Constants.Rc4Hmac };

    /// <summary>Encodes a no-pre-auth AS-REQ (only PA-PAC-REQUEST).</summary>
    public static byte[] Build(string realm, string user, uint nonce, DateTimeOffset till, int[]? etypes = null, bool requestPac = true)
    {
        return Encode(realm, user, nonce, till, etypes ?? DefaultEtypes, w =>
        {
            WritePaData(w, Krb5Constants.PaPacRequest, EncodePacRequest(requestPac));
        });
    }

    /// <summary>
    /// Encodes an AS-REQ carrying a PA-ENC-TIMESTAMP (encrypted with <paramref name="clientKey"/>,
    /// key usage 1) plus PA-PAC-REQUEST. <paramref name="now"/>/<paramref name="usec"/> are the
    /// timestamp; <paramref name="confounder"/> is the RC4 confounder (fixed for deterministic tests).
    /// </summary>
    public static byte[] BuildPreauth(
        string realm, string user, byte[] clientKey, uint nonce, DateTimeOffset till,
        DateTimeOffset now, int usec, byte[] confounder, int etype = Krb5Constants.Rc4Hmac, bool requestPac = true)
    {
        byte[] tsEnc = EncodePaEncTsEnc(now, usec);
        byte[] encrypted = Krb5Crypto.Encrypt(clientKey, 1, tsEnc, confounder); // key usage 1
        byte[] encData = EncodeEncryptedData(etype, encrypted);

        return Encode(realm, user, nonce, till, new[] { etype }, w =>
        {
            WritePaData(w, Krb5Constants.PaEncTimestamp, encData);     // PA-ENC-TIMESTAMP [0]
            WritePaData(w, Krb5Constants.PaPacRequest, EncodePacRequest(requestPac)); // PA-PAC-REQUEST [1]
        });
    }

    // Shared AS-REQ / KDC-REQ-BODY skeleton; writePadata emits the PA-DATA entries.
    private static byte[] Encode(string realm, string user, uint nonce, DateTimeOffset till, int[] etypes, Action<AsnWriter> writePadata)
    {
        realm = realm.ToUpperInvariant();
        var w = new AsnWriter(AsnEncodingRules.DER);
        using (w.PushSequence(new Asn1Tag(TagClass.Application, Krb5Constants.AsReq))) // AS-REQ [APPLICATION 10]
        using (w.PushSequence())                                                       // KDC-REQ SEQUENCE
        {
            using (w.PushSequence(Ctx(1))) w.WriteInteger(Krb5Constants.Pvno);          // pvno [1]
            using (w.PushSequence(Ctx(2))) w.WriteInteger(Krb5Constants.AsReq);         // msg-type [2]

            using (w.PushSequence(Ctx(3)))                                              // padata [3] SEQUENCE OF
            using (w.PushSequence())
            {
                writePadata(w);
            }

            using (w.PushSequence(Ctx(4)))                                              // req-body [4]
            using (w.PushSequence())
            {
                using (w.PushSequence(Ctx(0))) w.WriteBitString(Krb5Constants.KdcOptionsForwardableRenewableProxiable); // kdc-options [0]
                using (w.PushSequence(Ctx(1))) WritePrincipalName(w, new[] { user });    // cname [1]
                using (w.PushSequence(Ctx(2))) w.WriteEncodedValue(Der.GeneralString(realm)); // realm [2]
                using (w.PushSequence(Ctx(3))) WritePrincipalName(w, new[] { "krbtgt", realm }); // sname [3]
                using (w.PushSequence(Ctx(5))) w.WriteGeneralizedTime(till, omitFractionalSeconds: true); // till [5]
                using (w.PushSequence(Ctx(6))) w.WriteGeneralizedTime(till, omitFractionalSeconds: true); // rtime [6]
                using (w.PushSequence(Ctx(7))) w.WriteInteger(nonce);                    // nonce [7]
                using (w.PushSequence(Ctx(8)))                                           // etype [8] SEQUENCE OF Int32
                using (w.PushSequence())
                {
                    foreach (int etype in etypes)
                    {
                        w.WriteInteger(etype);
                    }
                }
            }
        }

        return w.Encode();
    }

    // PA-DATA ::= SEQUENCE { padata-type [1] Int32, padata-value [2] OCTET STRING }
    private static void WritePaData(AsnWriter w, int type, byte[] value)
    {
        using (w.PushSequence())
        {
            using (w.PushSequence(Ctx(1))) w.WriteInteger(type);
            using (w.PushSequence(Ctx(2))) w.WriteOctetString(value);
        }
    }

    // PrincipalName ::= SEQUENCE { name-type [0] Int32, name-string [1] SEQUENCE OF GeneralString }
    private static void WritePrincipalName(AsnWriter w, string[] components)
    {
        using (w.PushSequence())
        {
            using (w.PushSequence(Ctx(0))) w.WriteInteger(Krb5Constants.NtPrincipal);
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

    // KERB-PA-PAC-REQUEST ::= SEQUENCE { include-pac [0] BOOLEAN }
    private static byte[] EncodePacRequest(bool includePac)
    {
        var w = new AsnWriter(AsnEncodingRules.DER);
        using (w.PushSequence())
        {
            using (w.PushSequence(Ctx(0))) w.WriteBoolean(includePac);
        }

        return w.Encode();
    }

    // PA-ENC-TS-ENC ::= SEQUENCE { patimestamp [0] KerberosTime, pausec [1] Microseconds OPTIONAL }
    private static byte[] EncodePaEncTsEnc(DateTimeOffset now, int usec)
    {
        var w = new AsnWriter(AsnEncodingRules.DER);
        using (w.PushSequence())
        {
            using (w.PushSequence(Ctx(0))) w.WriteGeneralizedTime(now, omitFractionalSeconds: true);
            using (w.PushSequence(Ctx(1))) w.WriteInteger(usec);
        }

        return w.Encode();
    }

    // EncryptedData ::= SEQUENCE { etype [0] Int32, kvno [1] UInt32 OPTIONAL, cipher [2] OCTET STRING }
    private static byte[] EncodeEncryptedData(int etype, byte[] cipher)
    {
        var w = new AsnWriter(AsnEncodingRules.DER);
        using (w.PushSequence())
        {
            using (w.PushSequence(Ctx(0))) w.WriteInteger(etype);
            using (w.PushSequence(Ctx(2))) w.WriteOctetString(cipher);
        }

        return w.Encode();
    }
}
