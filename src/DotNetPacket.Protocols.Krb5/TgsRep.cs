using System.Formats.Asn1;
using System.Numerics;

namespace DotNetPacket.Protocols.Krb5;

/// <summary>
/// Parses a TGS-REP (RFC 4120 5.4.2) and pulls out the <b>service ticket</b>'s enc-part — the
/// material a Kerberoast cracks (it is encrypted with the service account's long-term key). The
/// TGS-REP's own enc-part (the new session key) is not needed and is skipped. A KRB-ERROR reply is
/// surfaced via <see cref="ErrorCode"/>.
/// </summary>
public sealed class TgsRep
{
    public bool IsTgsRep { get; private init; }

    public int ErrorCode { get; private init; }

    public int TicketEtype { get; private init; }

    public byte[] TicketCipher { get; private init; } = Array.Empty<byte>();

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
        while (body.HasData)
        {
            Asn1Tag t = body.PeekTag();
            if (t.TagClass == TagClass.ContextSpecific && t.TagValue == 5)
            {
                // ticket [5] -> Ticket [APPLICATION 1] SEQUENCE { tkt-vno[0], realm[1], sname[2], enc-part[3] }
                AsnReader ticket = body.ReadSequence(Ctx(5))
                    .ReadSequence(new Asn1Tag(TagClass.Application, 1)).ReadSequence();
                (int etype, byte[] cipher) = ReadTicketEncPart(ticket);
                return new TgsRep { IsTgsRep = true, TicketEtype = etype, TicketCipher = cipher };
            }

            body.ReadEncodedValue();
        }

        throw new InvalidDataException("TGS-REP without a ticket.");
    }

    private static (int Etype, byte[] Cipher) ReadTicketEncPart(AsnReader ticket)
    {
        while (ticket.HasData)
        {
            Asn1Tag t = ticket.PeekTag();
            if (t.TagClass == TagClass.ContextSpecific && t.TagValue == 3)
            {
                AsnReader enc = ticket.ReadSequence(Ctx(3)).ReadSequence(); // EncryptedData
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

            ticket.ReadEncodedValue();
        }

        throw new InvalidDataException("Service ticket without an enc-part.");
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
