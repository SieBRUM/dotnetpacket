using System.Formats.Asn1;

namespace DotNetPacket.Protocols.Krb5;

/// <summary>
/// The decrypted AS-REP/TGS-REP enc-part (EncKDCRepPart, RFC 4120 5.4.2) — the fields we need from
/// a TGT: the session key and the ticket end time. Wrapped as [APPLICATION 25] (EncASRepPart) or
/// [APPLICATION 26] (EncTGSRepPart); both are tried. sname is left to the caller (the requested
/// SPN) to avoid GeneralString reading.
/// </summary>
public sealed record EncKdcRepPart(
    int SessionKeyEtype, byte[] SessionKey, DateTimeOffset? EndTime,
    byte[] Flags, DateTimeOffset? AuthTime, DateTimeOffset? StartTime, DateTimeOffset? RenewTill)
{
    private static Asn1Tag Ctx(int n) => new(TagClass.ContextSpecific, n, isConstructed: true);

    // EncKDCRepPart ::= { key[0], last-req[1], nonce[2], key-expiration[3], flags[4],
    //                     authtime[5], starttime[6], endtime[7], renew-till[8], srealm[9], sname[10], caddr[11] }
    public static EncKdcRepPart Parse(byte[] plaintext)
    {
        var top = new AsnReader(plaintext, AsnEncodingRules.DER);
        Asn1Tag appTag = top.PeekTag();
        int app = appTag.TagValue; // 25 = EncASRepPart, 26 = EncTGSRepPart
        AsnReader body = top.ReadSequence(new Asn1Tag(TagClass.Application, app)).ReadSequence();

        int keyEtype = 0;
        byte[] key = Array.Empty<byte>();
        byte[] flags = new byte[4];
        DateTimeOffset? authTime = null, startTime = null, endTime = null, renewTill = null;

        while (body.HasData)
        {
            Asn1Tag t = body.PeekTag();
            if (t.TagClass != TagClass.ContextSpecific)
            {
                body.ReadEncodedValue();
                continue;
            }

            switch (t.TagValue)
            {
                case 0:
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

                    break;
                case 4:
                    flags = body.ReadSequence(Ctx(4)).ReadBitString(out _);
                    break;
                case 5:
                    authTime = body.ReadSequence(Ctx(5)).ReadGeneralizedTime();
                    break;
                case 6:
                    startTime = body.ReadSequence(Ctx(6)).ReadGeneralizedTime();
                    break;
                case 7:
                    endTime = body.ReadSequence(Ctx(7)).ReadGeneralizedTime();
                    break;
                case 8:
                    renewTill = body.ReadSequence(Ctx(8)).ReadGeneralizedTime();
                    break;
                default:
                    body.ReadEncodedValue();
                    break;
            }
        }

        return new EncKdcRepPart(keyEtype, key, endTime, flags, authTime, startTime, renewTill);
    }
}
