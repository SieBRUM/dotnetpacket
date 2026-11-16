using System.Formats.Asn1;
using System.Text;

namespace DotNetPacket.Protocols.Krb5;

/// <summary>One ETYPE-INFO2-ENTRY (RFC 4120 5.2.7.5): an etype the KDC supports plus its salt.</summary>
public sealed record EtypeInfo2Entry(int Etype, byte[]? Salt, byte[]? S2kParams)
{
    /// <summary>The PBKDF2 iteration count from s2kparams (4-byte big-endian), or the RFC 3962 default.</summary>
    public int Iterations => S2kParams is { Length: 4 }
        ? (S2kParams[0] << 24) | (S2kParams[1] << 16) | (S2kParams[2] << 8) | S2kParams[3]
        : AesCtsCrypto.DefaultIterations;

    /// <summary>The salt as text, or the empty string when the KDC omitted it.</summary>
    public string SaltText => Salt is null ? string.Empty : Encoding.UTF8.GetString(Salt);
}

/// <summary>
/// Parses PA-ETYPE-INFO2 — the pa-data the KDC returns in a KDC_ERR_PREAUTH_REQUIRED error (and in the
/// AS-REP) listing each supported etype and, for the AES/DES profiles, the authoritative string-to-key
/// salt. impacket reads this to compute the right AES key; so do we. Mirrors
/// <c>impacket.krb5.kerberosv5</c>'s handling of <c>ETYPE_INFO2</c>.
/// </summary>
public static class EtypeInfo2
{
    private static Asn1Tag Ctx(int n) => new(TagClass.ContextSpecific, n, isConstructed: true);

    /// <summary>
    /// Parses the KRB-ERROR e-data (a DER-encoded METHOD-DATA ::= SEQUENCE OF PA-DATA) and returns the
    /// ETYPE-INFO2 entries, or an empty list if none is present.
    /// </summary>
    public static IReadOnlyList<EtypeInfo2Entry> Parse(byte[] eData)
    {
        var entries = new List<EtypeInfo2Entry>();
        if (eData.Length == 0)
        {
            return entries;
        }

        AsnReader methodData = new AsnReader(eData, AsnEncodingRules.DER).ReadSequence();
        while (methodData.HasData)
        {
            AsnReader pa = methodData.ReadSequence();     // PA-DATA ::= SEQUENCE { padata-type [1], padata-value [2] }
            int type = 0;
            byte[] value = Array.Empty<byte>();
            while (pa.HasData)
            {
                Asn1Tag t = pa.PeekTag();
                if (t.HasSameClassAndValue(Ctx(1)))
                {
                    type = (int)pa.ReadSequence(Ctx(1)).ReadInteger();
                }
                else if (t.HasSameClassAndValue(Ctx(2)))
                {
                    value = pa.ReadSequence(Ctx(2)).ReadOctetString();
                }
                else
                {
                    pa.ReadEncodedValue();
                }
            }

            if (type == Krb5Constants.PaEtypeInfo2)
            {
                entries.AddRange(ParseEntries(value));
            }
        }

        return entries;
    }

    // ETYPE-INFO2 ::= SEQUENCE SIZE (1..MAX) OF ETYPE-INFO2-ENTRY
    private static IEnumerable<EtypeInfo2Entry> ParseEntries(byte[] etypeInfo2)
    {
        var list = new List<EtypeInfo2Entry>();
        AsnReader seq = new AsnReader(etypeInfo2, AsnEncodingRules.DER).ReadSequence();
        while (seq.HasData)
        {
            AsnReader entry = seq.ReadSequence(); // ETYPE-INFO2-ENTRY
            int etype = 0;
            byte[]? salt = null;
            byte[]? s2k = null;
            while (entry.HasData)
            {
                Asn1Tag t = entry.PeekTag();
                if (t.HasSameClassAndValue(Ctx(0)))
                {
                    etype = (int)entry.ReadSequence(Ctx(0)).ReadInteger();
                }
                else if (t.HasSameClassAndValue(Ctx(1)))
                {
                    // salt [1] KerberosString (GeneralString) — keep the raw content octets.
                    salt = ReadStringContent(entry.ReadSequence(Ctx(1)));
                }
                else if (t.HasSameClassAndValue(Ctx(2)))
                {
                    s2k = entry.ReadSequence(Ctx(2)).ReadOctetString();
                }
                else
                {
                    entry.ReadEncodedValue();
                }
            }

            list.Add(new EtypeInfo2Entry(etype, salt, s2k));
        }

        return list;
    }

    // Reads a DER string primitive (GeneralString/IA5String/UTF8String) and returns its content octets.
    private static byte[] ReadStringContent(AsnReader reader)
    {
        byte[] tlv = reader.ReadEncodedValue().ToArray();
        int i = 1; // skip the tag byte
        int len = tlv[i++];
        if ((len & 0x80) != 0)
        {
            int n = len & 0x7F;
            len = 0;
            for (int k = 0; k < n; k++)
            {
                len = (len << 8) | tlv[i++];
            }
        }

        return tlv[i..(i + len)];
    }
}
