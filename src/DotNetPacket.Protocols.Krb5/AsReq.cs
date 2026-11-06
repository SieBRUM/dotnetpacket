using System.Formats.Asn1;

namespace DotNetPacket.Protocols.Krb5;

/// <summary>
/// Builds a Kerberos AS-REQ (RFC 4120 5.4.1) with no encrypted pre-auth — the request impacket's
/// <c>GetNPUsers.py</c> sends to roast an account that has "do not require pre-authentication"
/// set. It carries only a PA-PAC-REQUEST pa-data; the KDC answers with an AS-REP (roastable) or a
/// KRB-ERROR (pre-auth required / unknown / etc.). All context tags are EXPLICIT, as Kerberos uses.
/// </summary>
public static class AsReq
{
    private static Asn1Tag Ctx(int n) => new(TagClass.ContextSpecific, n, isConstructed: true);

    private static readonly int[] DefaultEtypes = { Krb5Constants.Rc4Hmac };

    /// <summary>
    /// Encodes an AS-REQ for <paramref name="user"/>@<paramref name="realm"/>. <paramref name="till"/>
    /// is the ticket expiry (impacket uses now+1 day); <paramref name="nonce"/> a random 31-bit value.
    /// <paramref name="etypes"/> defaults to RC4-HMAC (what GetNPUsers tries first).
    /// </summary>
    public static byte[] Build(string realm, string user, uint nonce, DateTimeOffset till, int[]? etypes = null, bool requestPac = true)
    {
        realm = realm.ToUpperInvariant();
        etypes ??= DefaultEtypes;

        var w = new AsnWriter(AsnEncodingRules.DER);
        using (w.PushSequence(new Asn1Tag(TagClass.Application, Krb5Constants.AsReq))) // AS-REQ [APPLICATION 10]
        using (w.PushSequence())                                                       // KDC-REQ SEQUENCE
        {
            using (w.PushSequence(Ctx(1))) w.WriteInteger(Krb5Constants.Pvno);          // pvno [1]
            using (w.PushSequence(Ctx(2))) w.WriteInteger(Krb5Constants.AsReq);         // msg-type [2]

            // padata [3] SEQUENCE OF PA-DATA — a single PA-PAC-REQUEST.
            using (w.PushSequence(Ctx(3)))
            using (w.PushSequence())
            {
                using (w.PushSequence())                                                // PA-DATA
                {
                    using (w.PushSequence(Ctx(1))) w.WriteInteger(Krb5Constants.PaPacRequest); // padata-type [1]
                    using (w.PushSequence(Ctx(2))) w.WriteOctetString(EncodePacRequest(requestPac)); // padata-value [2]
                }
            }

            // req-body [4] KDC-REQ-BODY
            using (w.PushSequence(Ctx(4)))
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

    // PrincipalName ::= SEQUENCE { name-type [0] Int32, name-string [1] SEQUENCE OF GeneralString }
    private static void WritePrincipalName(AsnWriter w, string[] components)
    {
        using (w.PushSequence())
        {
            using (w.PushSequence(Ctx(0))) w.WriteInteger(Krb5Constants.NtPrincipal); // name-type [0]
            using (w.PushSequence(Ctx(1)))                                            // name-string [1]
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
}
