using System.Formats.Asn1;

namespace DotNetPacket.Protocols.Krb5;

/// <summary>
/// The decrypted AS-REP/TGS-REP enc-part (EncKDCRepPart, RFC 4120 5.4.2) — the fields we need from
/// a TGT: the session key and the ticket end time. Wrapped as [APPLICATION 25] (EncASRepPart) or
/// [APPLICATION 26] (EncTGSRepPart); both are tried. sname is left to the caller (the requested
/// SPN) to avoid GeneralString reading.
/// </summary>
public sealed record EncKdcRepPart(int SessionKeyEtype, byte[] SessionKey, DateTimeOffset? EndTime)
{
    private static Asn1Tag Ctx(int n) => new(TagClass.ContextSpecific, n, isConstructed: true);

    public static EncKdcRepPart Parse(byte[] plaintext)
    {
        var top = new AsnReader(plaintext, AsnEncodingRules.DER);
        Asn1Tag appTag = top.PeekTag();
        int app = appTag.TagValue; // 25 = EncASRepPart, 26 = EncTGSRepPart
        AsnReader body = top.ReadSequence(new Asn1Tag(TagClass.Application, app)).ReadSequence();

        int keyEtype = 0;
        byte[] key = Array.Empty<byte>();
        DateTimeOffset? endTime = null;

        while (body.HasData)
        {
            Asn1Tag t = body.PeekTag();
            if (t.TagClass == TagClass.ContextSpecific && t.TagValue == 0)
            {
                AsnReader enc = body.ReadSequence(Ctx(0)).ReadSequence(); // EncryptionKey
                while (enc.HasData)
                {
                    Asn1Tag kt = enc.PeekTag();
                    if (kt.TagValue == 0 && kt.TagClass == TagClass.ContextSpecific)
                    {
                        keyEtype = (int)enc.ReadSequence(Ctx(0)).ReadInteger();
                    }
                    else if (kt.TagValue == 1 && kt.TagClass == TagClass.ContextSpecific)
                    {
                        key = enc.ReadSequence(Ctx(1)).ReadOctetString();
                    }
                    else
                    {
                        enc.ReadEncodedValue();
                    }
                }
            }
            else if (t.TagClass == TagClass.ContextSpecific && t.TagValue == 7)
            {
                endTime = body.ReadSequence(Ctx(7)).ReadGeneralizedTime();
            }
            else
            {
                body.ReadEncodedValue();
            }
        }

        return new EncKdcRepPart(keyEtype, key, endTime);
    }
}
