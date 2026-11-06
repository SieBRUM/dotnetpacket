using System.Formats.Asn1;

namespace DotNetPacket.Core.Tests;

/// <summary>
/// Hand-encodes a minimal, SYNTHETIC Kerberos AS-REP for parser round-trip tests only. This is
/// NOT captured traffic — the Samba lab KDC won't emit a pre-auth-less AS-REP, so there is no real
/// one to pin. It produces just enough of the structure (pvno, msg-type, enc-part) for the parser.
/// </summary>
internal static class SyntheticAsRep
{
    private static Asn1Tag Ctx(int n) => new(TagClass.ContextSpecific, n, isConstructed: true);

    public static byte[] Build(string crealm, string cname, int etype, byte[] cipher)
    {
        var w = new AsnWriter(AsnEncodingRules.DER);
        using (w.PushSequence(new Asn1Tag(TagClass.Application, 11))) // AS-REP [APPLICATION 11]
        using (w.PushSequence())
        {
            using (w.PushSequence(Ctx(0))) w.WriteInteger(5);  // pvno [0]
            using (w.PushSequence(Ctx(1))) w.WriteInteger(11); // msg-type [1]
            using (w.PushSequence(Ctx(6)))                     // enc-part [6] EncryptedData
            using (w.PushSequence())
            {
                using (w.PushSequence(Ctx(0))) w.WriteInteger(etype);  // etype [0]
                using (w.PushSequence(Ctx(2))) w.WriteOctetString(cipher); // cipher [2]
            }
        }

        _ = crealm;
        _ = cname;
        return w.Encode();
    }
}
