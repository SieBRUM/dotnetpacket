using System.Formats.Asn1;

namespace DotNetPacket.Protocols.Krb5;

/// <summary>
/// Decodes a Kerberos <c>Ticket</c> ([APPLICATION 1]) far enough to recover the PAC: decrypt the
/// enc-part under the service's long-term key (key usage 2, KRB_KU_TICKET), then walk the
/// EncTicketPart's authorization-data for the AD-WIN2K-PAC element (ad-type 128), unwrapping the
/// AD-IF-RELEVANT (ad-type 1) container it sits inside. This is how getPac / describeTicket reach the
/// PAC a ticket carries. Decode-only, lab-first.
/// </summary>
public static class KerberosTicket
{
    private const int TicketApp = 1;
    private const int EncTicketPartApp = 3;
    private const int TicketEncPartUsage = 2;      // [MS-KILE] / RFC 4120: ticket enc-part key usage
    private const int AdIfRelevant = 1;
    private const int AdWin2kPac = 128;

    private static Asn1Tag Ctx(int n) => new(TagClass.ContextSpecific, n, isConstructed: true);

    /// <summary>Decrypts a ticket's PAC with the service key and returns the raw PAC blob (or null).</summary>
    public static byte[]? DecryptPac(byte[] ticketDer, byte[] serviceKey, int keyEtype)
    {
        (int etype, byte[] cipher) = ExtractEncPart(ticketDer);
        int useEtype = etype != 0 ? etype : keyEtype;
        byte[] encTicketPart = Krb5Cipher.Decrypt(useEtype, serviceKey, TicketEncPartUsage, cipher);
        return ExtractPac(encTicketPart);
    }

    /// <summary>Parses Ticket ([APPLICATION 1]) → enc-part [3] EncryptedData → (etype, cipher).</summary>
    public static (int Etype, byte[] Cipher) ExtractEncPart(byte[] ticketDer)
    {
        // Ticket ::= [APPLICATION 1] SEQUENCE { tkt-vno [0], realm [1], sname [2], enc-part [3] }
        AsnReader body = new AsnReader(ticketDer, AsnEncodingRules.DER)
            .ReadSequence(new Asn1Tag(TagClass.Application, TicketApp))
            .ReadSequence();

        while (body.HasData)
        {
            Asn1Tag t = body.PeekTag();
            if (t.TagClass == TagClass.ContextSpecific && t.TagValue == 3)
            {
                AsnReader enc = body.ReadSequence(Ctx(3)).ReadSequence(); // EncryptedData
                int etype = 0;
                byte[] cipher = Array.Empty<byte>();
                while (enc.HasData)
                {
                    Asn1Tag et = enc.PeekTag();
                    if (et.TagValue == 0)
                    {
                        etype = (int)enc.ReadSequence(Ctx(0)).ReadInteger();
                    }
                    else if (et.TagValue == 2)
                    {
                        cipher = enc.ReadSequence(Ctx(2)).ReadOctetString();
                    }
                    else
                    {
                        enc.ReadEncodedValue(); // kvno [1] etc.
                    }
                }

                return (etype, cipher);
            }

            body.ReadEncodedValue();
        }

        throw new InvalidOperationException("Ticket has no enc-part [3].");
    }

    /// <summary>Walks EncTicketPart ([APPLICATION 3]) authorization-data [10] for the AD-WIN2K-PAC blob.</summary>
    public static byte[]? ExtractPac(byte[] encTicketPart)
    {
        // EncTicketPart ::= [APPLICATION 3] SEQUENCE { … authorization-data [10] AuthorizationData OPTIONAL }
        AsnReader body = new AsnReader(encTicketPart, AsnEncodingRules.DER)
            .ReadSequence(new Asn1Tag(TagClass.Application, EncTicketPartApp))
            .ReadSequence();

        while (body.HasData)
        {
            Asn1Tag t = body.PeekTag();
            if (t.TagClass == TagClass.ContextSpecific && t.TagValue == 10)
            {
                AsnReader adSeq = body.ReadSequence(Ctx(10)).ReadSequence();
                return FindPac(adSeq);
            }

            body.ReadEncodedValue();
        }

        return null;
    }

    /// <summary>Scans an AuthorizationData SEQUENCE OF for AD-WIN2K-PAC, recursing into AD-IF-RELEVANT.</summary>
    private static byte[]? FindPac(AsnReader adSeq)
    {
        while (adSeq.HasData)
        {
            AsnReader ad = adSeq.ReadSequence(); // AuthorizationData element
            int adType = 0;
            byte[] adData = Array.Empty<byte>();
            while (ad.HasData)
            {
                Asn1Tag t = ad.PeekTag();
                if (t.TagValue == 0)
                {
                    adType = (int)ad.ReadSequence(Ctx(0)).ReadInteger();
                }
                else if (t.TagValue == 1)
                {
                    adData = ad.ReadSequence(Ctx(1)).ReadOctetString();
                }
                else
                {
                    ad.ReadEncodedValue();
                }
            }

            if (adType == AdWin2kPac)
            {
                return adData;
            }

            if (adType == AdIfRelevant)
            {
                // AD-IF-RELEVANT wraps a nested AuthorizationData SEQUENCE OF.
                byte[]? nested = FindPac(new AsnReader(adData, AsnEncodingRules.DER).ReadSequence());
                if (nested is not null)
                {
                    return nested;
                }
            }
        }

        return null;
    }
}
