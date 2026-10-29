using System.Formats.Asn1;

namespace NetPacket.Protocols.Ntlm;

/// <summary>
/// Minimal SPNEGO / GSS-API wrapping (RFC 4178) for carrying NTLM tokens inside
/// SMB2 SESSION_SETUP, built on the BCL's ASN.1 DER encoder. Only the two shapes a
/// client sends/receives for NTLM are handled: the initial GSS-wrapped
/// <c>NegTokenInit</c> and the subsequent <c>NegTokenResp</c>.
/// </summary>
public static class Spnego
{
    private const string SpnegoOid = "1.3.6.1.5.5.2";
    private const string NtlmSspOid = "1.3.6.1.4.1.311.2.2.10";

    private static readonly Asn1Tag Context0 = new(TagClass.ContextSpecific, 0);
    private static readonly Asn1Tag Context1 = new(TagClass.ContextSpecific, 1);
    private static readonly Asn1Tag Context2 = new(TagClass.ContextSpecific, 2);
    private static readonly Asn1Tag Context3 = new(TagClass.ContextSpecific, 3);
    private static readonly Asn1Tag Application0 = new(TagClass.Application, 0);

    /// <summary>
    /// The DER-encoded <c>MechTypeList</c> (<c>SEQUENCE OF MechType</c>) offering NTLMSSP.
    /// The SPNEGO mechListMIC is computed over exactly these bytes, so the same
    /// constant is embedded in the initial token and signed for the response.
    /// </summary>
    public static readonly byte[] NtlmMechListDer = BuildMechList();

    private static byte[] BuildMechList()
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            writer.WriteObjectIdentifier(NtlmSspOid);
        }

        return writer.Encode();
    }

    /// <summary>Wraps an NTLM NEGOTIATE (Type 1) as a GSS-API <c>NegTokenInit</c> offering NTLMSSP.</summary>
    public static byte[] WrapInitialToken(byte[] ntlmNegotiate)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence(Application0))
        {
            writer.WriteObjectIdentifier(SpnegoOid);
            using (writer.PushSequence(Context0))          // negTokenInit [0]
            using (writer.PushSequence())                  // NegTokenInit SEQUENCE
            {
                using (writer.PushSequence(Context0))      // mechTypes [0]
                {
                    writer.WriteEncodedValue(NtlmMechListDer); // SEQUENCE OF MechType
                }

                using (writer.PushSequence(Context2))      // mechToken [2]
                {
                    writer.WriteOctetString(ntlmNegotiate);
                }
            }
        }

        return writer.Encode();
    }

    /// <summary>
    /// Wraps an NTLM AUTHENTICATE (Type 3) as a <c>NegTokenResp</c>, optionally with a
    /// SPNEGO <c>mechListMIC</c> — which a real client (and a strict server) requires.
    /// </summary>
    public static byte[] WrapResponseToken(byte[] ntlmAuthenticate, byte[]? mechListMic = null)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence(Context1))              // negTokenResp [1]
        using (writer.PushSequence())                      // NegTokenResp SEQUENCE
        {
            using (writer.PushSequence(Context2))          // responseToken [2]
            {
                writer.WriteOctetString(ntlmAuthenticate);
            }

            if (mechListMic is not null)
            {
                using (writer.PushSequence(Context3))      // mechListMIC [3]
                {
                    writer.WriteOctetString(mechListMic);
                }
            }
        }

        return writer.Encode();
    }

    /// <summary>
    /// Extracts the NTLM token (CHALLENGE / Type 2) from a server's SPNEGO
    /// <c>NegTokenResp</c> (or a GSS-wrapped token, as a fallback).
    /// </summary>
    public static byte[] ExtractResponseToken(byte[] spnego)
    {
        var reader = new AsnReader(spnego, AsnEncodingRules.DER);
        Asn1Tag tag = reader.PeekTag();

        AsnReader negTokenResp;
        if (tag.HasSameClassAndValue(Application0))
        {
            // GSS-API wrapped: OID then the negotiation token.
            AsnReader gss = reader.ReadSequence(Application0);
            gss.ReadObjectIdentifier();
            Asn1Tag inner = gss.PeekTag();
            negTokenResp = gss.ReadSequence(inner.HasSameClassAndValue(Context0) ? Context0 : Context1);
        }
        else
        {
            negTokenResp = reader.ReadSequence(Context1);
        }

        AsnReader sequence = negTokenResp.ReadSequence();
        byte[]? responseToken = null;
        while (sequence.HasData)
        {
            Asn1Tag field = sequence.PeekTag();
            if (field.HasSameClassAndValue(Context2))
            {
                AsnReader tokenReader = sequence.ReadSequence(Context2);
                responseToken = tokenReader.ReadOctetString();
            }
            else
            {
                sequence.ReadEncodedValue(); // skip negState / supportedMech / mechListMIC
            }
        }

        return responseToken
               ?? throw new InvalidDataException("SPNEGO response did not contain a responseToken.");
    }
}
