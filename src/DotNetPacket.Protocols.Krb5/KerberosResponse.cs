using System.Formats.Asn1;
using System.Numerics;

namespace DotNetPacket.Protocols.Krb5;

/// <summary>Parsed AS exchange reply: either an AS-REP (roastable) or a KRB-ERROR.</summary>
public sealed class KerberosResponse
{
    /// <summary>True if the KDC returned an AS-REP (the account did not require pre-auth).</summary>
    public bool IsAsRep { get; private init; }

    /// <summary>KRB-ERROR error-code, when <see cref="IsAsRep"/> is false.</summary>
    public int ErrorCode { get; private init; }

    /// <summary>AS-REP enc-part encryption type, when <see cref="IsAsRep"/> is true.</summary>
    public int EncPartEtype { get; private init; }

    /// <summary>AS-REP enc-part ciphertext (the material that becomes the AS-REP-roast hash).</summary>
    public byte[] EncPartCipher { get; private init; } = Array.Empty<byte>();

    private static Asn1Tag Ctx(int n) => new(TagClass.ContextSpecific, n, isConstructed: true);

    /// <summary>Parses a raw KDC reply (one DER message) as an AS-REP or a KRB-ERROR.</summary>
    public static KerberosResponse Parse(byte[] message)
    {
        var top = new AsnReader(message, AsnEncodingRules.DER);
        Asn1Tag tag = top.PeekTag();

        if (tag.TagClass == TagClass.Application && tag.TagValue == Krb5Constants.KrbError)
        {
            return new KerberosResponse { IsAsRep = false, ErrorCode = ParseKrbError(top) };
        }

        if (tag.TagClass == TagClass.Application && tag.TagValue == Krb5Constants.AsRep)
        {
            (int etype, byte[] cipher) = ParseAsRep(top);
            return new KerberosResponse { IsAsRep = true, EncPartEtype = etype, EncPartCipher = cipher };
        }

        throw new InvalidDataException($"Unexpected Kerberos reply tag {tag.TagClass}/{tag.TagValue}.");
    }

    // KRB-ERROR ::= [APPLICATION 30] SEQUENCE { ... error-code [6] Int32 ... }
    private static int ParseKrbError(AsnReader top)
    {
        AsnReader body = top.ReadSequence(new Asn1Tag(TagClass.Application, Krb5Constants.KrbError)).ReadSequence();
        while (body.HasData)
        {
            Asn1Tag t = body.PeekTag();
            if (t.TagClass == TagClass.ContextSpecific && t.TagValue == 6)
            {
                return (int)ReadExplicitInteger(body, Ctx(6));
            }

            body.ReadEncodedValue();
        }

        throw new InvalidDataException("KRB-ERROR without an error-code.");
    }

    // AS-REP ::= [APPLICATION 11] SEQUENCE { ... enc-part [6] EncryptedData }
    // EncryptedData ::= SEQUENCE { etype [0] Int32, kvno [1] UInt32 OPTIONAL, cipher [2] OCTET STRING }
    private static (int Etype, byte[] Cipher) ParseAsRep(AsnReader top)
    {
        AsnReader body = top.ReadSequence(new Asn1Tag(TagClass.Application, Krb5Constants.AsRep)).ReadSequence();
        while (body.HasData)
        {
            Asn1Tag t = body.PeekTag();
            if (t.TagClass == TagClass.ContextSpecific && t.TagValue == 6)
            {
                AsnReader enc = body.ReadSequence(Ctx(6)).ReadSequence(); // EncryptedData
                int etype = 0;
                byte[] cipher = Array.Empty<byte>();
                while (enc.HasData)
                {
                    Asn1Tag et = enc.PeekTag();
                    if (et.TagValue == 0 && et.TagClass == TagClass.ContextSpecific)
                    {
                        etype = (int)ReadExplicitInteger(enc, Ctx(0));
                    }
                    else if (et.TagValue == 2 && et.TagClass == TagClass.ContextSpecific)
                    {
                        cipher = enc.ReadSequence(Ctx(2)).ReadOctetString();
                    }
                    else
                    {
                        enc.ReadEncodedValue(); // kvno [1] or anything else
                    }
                }

                return (etype, cipher);
            }

            body.ReadEncodedValue();
        }

        throw new InvalidDataException("AS-REP without an enc-part.");
    }

    private static BigInteger ReadExplicitInteger(AsnReader reader, Asn1Tag ctx) =>
        reader.ReadSequence(ctx).ReadInteger();
}
