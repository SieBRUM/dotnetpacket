using System.Formats.Asn1;
using System.Numerics;

namespace DotNetPacket.Protocols.Krb5;

/// <summary>
/// Parses a TGS-REP (RFC 4120 5.4.2). Exposes both what a Kerberoast needs (the service ticket's
/// enc-part, encrypted under the service account's long-term key) and what Kerberos *authentication*
/// needs: the full encoded service <b>ticket</b> and the TGS-REP's own <b>enc-part</b> (encrypted
/// under the TGT session key, key usage 8), which yields the service session key. A KRB-ERROR reply
/// is surfaced via <see cref="ErrorCode"/>.
/// </summary>
public sealed class TgsRep
{
    public bool IsTgsRep { get; private init; }

    public int ErrorCode { get; private init; }

    /// <summary>The service ticket's enc-part etype (the roast material's etype).</summary>
    public int TicketEtype { get; private init; }

    /// <summary>The service ticket's enc-part cipher (the roast material).</summary>
    public byte[] TicketCipher { get; private init; } = Array.Empty<byte>();

    /// <summary>The full encoded service <c>Ticket</c> ([APPLICATION 1]), to embed in an AP-REQ.</summary>
    public byte[] Ticket { get; private init; } = Array.Empty<byte>();

    /// <summary>The TGS-REP enc-part etype (encrypted under the TGT session key).</summary>
    public int EncPartEtype { get; private init; }

    /// <summary>The TGS-REP enc-part cipher; decrypt with the TGT session key (usage 8) to get the service session key.</summary>
    public byte[] EncPartCipher { get; private init; } = Array.Empty<byte>();

    private static Asn1Tag Ctx(int n) => new(TagClass.ContextSpecific, n, isConstructed: true);

    public static TgsRep Parse(byte[] message)
    {
        var top = new AsnReader(message, AsnEncodingRules.DER);
        Asn1Tag tag = top.PeekTag();

        if (tag.TagClass == TagClass.Application && tag.TagValue == Krb5Constants.KrbError)
        {
            return new TgsRep { IsTgsRep = false, ErrorCode = ParseKrbErrorCode(top) };
        }

        if (tag.TagClass != TagClass.Application || tag.TagValue != Krb5Constants.TgsRep)
        {
            throw new InvalidDataException($"Unexpected Kerberos reply tag {tag.TagClass}/{tag.TagValue}.");
        }

        AsnReader body = top.ReadSequence(new Asn1Tag(TagClass.Application, Krb5Constants.TgsRep)).ReadSequence();

        byte[] ticketBytes = Array.Empty<byte>();
        int ticketEtype = 0;
        byte[] ticketCipher = Array.Empty<byte>();
        int encEtype = 0;
        byte[] encCipher = Array.Empty<byte>();

        while (body.HasData)
        {
            Asn1Tag t = body.PeekTag();
            if (t.TagClass == TagClass.ContextSpecific && t.TagValue == 5)
            {
                // ticket [5] -> Ticket [APPLICATION 1]. Keep the raw encoded ticket for the AP-REQ.
                AsnReader t5 = body.ReadSequence(Ctx(5));
                ticketBytes = t5.ReadEncodedValue().ToArray();
                (ticketEtype, ticketCipher) = ReadTicketEncPart(ticketBytes);
            }
            else if (t.TagClass == TagClass.ContextSpecific && t.TagValue == 6)
            {
                // enc-part [6] -> EncryptedData { etype[0], cipher[2] }.
                (encEtype, encCipher) = ReadEncryptedData(body.ReadSequence(Ctx(6)).ReadSequence());
            }
            else
            {
                body.ReadEncodedValue();
            }
        }

        if (ticketBytes.Length == 0)
        {
            throw new InvalidDataException("TGS-REP without a ticket.");
        }

        return new TgsRep
        {
            IsTgsRep = true,
            Ticket = ticketBytes,
            TicketEtype = ticketEtype,
            TicketCipher = ticketCipher,
            EncPartEtype = encEtype,
            EncPartCipher = encCipher,
        };
    }

    private static (int Etype, byte[] Cipher) ReadTicketEncPart(byte[] ticketEncoded)
    {
        AsnReader ticket = new AsnReader(ticketEncoded, AsnEncodingRules.DER)
            .ReadSequence(new Asn1Tag(TagClass.Application, 1)).ReadSequence();
        while (ticket.HasData)
        {
            Asn1Tag t = ticket.PeekTag();
            if (t.TagClass == TagClass.ContextSpecific && t.TagValue == 3)
            {
                return ReadEncryptedData(ticket.ReadSequence(Ctx(3)).ReadSequence());
            }

            ticket.ReadEncodedValue();
        }

        throw new InvalidDataException("Service ticket without an enc-part.");
    }

    private static (int Etype, byte[] Cipher) ReadEncryptedData(AsnReader enc)
    {
        int etype = 0;
        byte[] cipher = Array.Empty<byte>();
        while (enc.HasData)
        {
            Asn1Tag et = enc.PeekTag();
            if (et.TagValue == 0 && et.TagClass == TagClass.ContextSpecific)
            {
                etype = (int)enc.ReadSequence(Ctx(0)).ReadInteger();
            }
            else if (et.TagValue == 2 && et.TagClass == TagClass.ContextSpecific)
            {
                cipher = enc.ReadSequence(Ctx(2)).ReadOctetString();
            }
            else
            {
                enc.ReadEncodedValue();
            }
        }

        return (etype, cipher);
    }

    private static int ParseKrbErrorCode(AsnReader top)
    {
        AsnReader body = top.ReadSequence(new Asn1Tag(TagClass.Application, Krb5Constants.KrbError)).ReadSequence();
        while (body.HasData)
        {
            Asn1Tag t = body.PeekTag();
            if (t.TagClass == TagClass.ContextSpecific && t.TagValue == 6)
            {
                BigInteger code = body.ReadSequence(Ctx(6)).ReadInteger();
                return (int)code;
            }

            body.ReadEncodedValue();
        }

        throw new InvalidDataException("KRB-ERROR without an error-code.");
    }
}
