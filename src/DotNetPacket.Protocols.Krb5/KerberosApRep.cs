using System.Formats.Asn1;

namespace DotNetPacket.Protocols.Krb5;

/// <summary>The acceptor's mutual-auth subkey, recovered from an AP-REP: the SMB/GSS session key under AES.</summary>
public sealed record KerberosSubkey(int Etype, byte[] Key);

/// <summary>
/// Parses the Kerberos AP-REP the service returns when mutual authentication is requested, and
/// recovers the acceptor subkey from its EncAPRepPart. Per [MS-KILE] 3.1.1.2 and RFC 4121, when AES
/// is used the AP-REP subkey differs from the ticket session key and is the one used as the GSS/SMB
/// session key — so SMB signing must key on it. Ported from impacket's <c>smb3.kerberosLogin</c>
/// mutual-auth branch (<c>EncAPRepPart['subkey']</c>, key usage 12).
/// </summary>
public static class KerberosApRep
{
    // Mechanism OID 1.2.840.113554.1.2.2 (KRB5), DER-encoded — the inner GSS mech.
    private static readonly byte[] Krb5MechOid = { 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x12, 0x01, 0x02, 0x02 };

    private static Asn1Tag Ctx(int n) => new(TagClass.ContextSpecific, n, isConstructed: true);

    private const int ApRepApp = 15;        // AP-REP ::= [APPLICATION 15]
    private const int EncApRepPartApp = 27;  // EncAPRepPart ::= [APPLICATION 27]
    private const int ApRepEncPartUsage = 12; // KU_AP_REP_ENCPART

    /// <summary>
    /// Given the SPNEGO responseToken from a Kerberos SESSION_SETUP response (a GSS-API AP-REP token)
    /// and the ticket <paramref name="sessionKey"/>/<paramref name="sessionKeyEtype"/>, decrypts the
    /// EncAPRepPart (key usage 12) and returns its subkey, or null if the token carries no AP-REP/subkey.
    /// </summary>
    public static KerberosSubkey? ExtractSubkey(byte[] responseToken, byte[] sessionKey, int sessionKeyEtype)
    {
        byte[]? apRep = UnwrapGssApRep(responseToken);
        if (apRep is null)
        {
            return null;
        }

        // AP-REP ::= [APPLICATION 15] SEQUENCE { pvno [0], msg-type [1], enc-part [2] EncryptedData }
        AsnReader body = new AsnReader(apRep, AsnEncodingRules.DER)
            .ReadSequence(new Asn1Tag(TagClass.Application, ApRepApp))
            .ReadSequence();

        byte[] cipher = Array.Empty<byte>();
        while (body.HasData)
        {
            Asn1Tag t = body.PeekTag();
            if (t.HasSameClassAndValue(Ctx(2)))
            {
                AsnReader enc = body.ReadSequence(Ctx(2)).ReadSequence(); // EncryptedData
                while (enc.HasData)
                {
                    Asn1Tag et = enc.PeekTag();
                    if (et.HasSameClassAndValue(Ctx(2)))
                    {
                        cipher = enc.ReadSequence(Ctx(2)).ReadOctetString();
                    }
                    else
                    {
                        enc.ReadEncodedValue(); // etype [0] / kvno [1]
                    }
                }
            }
            else
            {
                body.ReadEncodedValue();
            }
        }

        if (cipher.Length == 0)
        {
            return null;
        }

        byte[] plain = Krb5Cipher.Decrypt(sessionKeyEtype, sessionKey, ApRepEncPartUsage, cipher);
        return ParseSubkey(plain);
    }

    // EncAPRepPart ::= [APPLICATION 27] SEQUENCE { ctime [0], cusec [1], subkey [2] EncryptionKey OPTIONAL, ... }
    private static KerberosSubkey? ParseSubkey(byte[] encApRepPart)
    {
        AsnReader body = new AsnReader(encApRepPart, AsnEncodingRules.DER)
            .ReadSequence(new Asn1Tag(TagClass.Application, EncApRepPartApp))
            .ReadSequence();

        while (body.HasData)
        {
            Asn1Tag t = body.PeekTag();
            if (t.HasSameClassAndValue(Ctx(2)))
            {
                // EncryptionKey ::= SEQUENCE { keytype [0] Int32, keyvalue [1] OCTET STRING }
                AsnReader key = body.ReadSequence(Ctx(2)).ReadSequence();
                int keytype = 0;
                byte[] keyvalue = Array.Empty<byte>();
                while (key.HasData)
                {
                    Asn1Tag kt = key.PeekTag();
                    if (kt.HasSameClassAndValue(Ctx(0)))
                    {
                        keytype = (int)key.ReadSequence(Ctx(0)).ReadInteger();
                    }
                    else if (kt.HasSameClassAndValue(Ctx(1)))
                    {
                        keyvalue = key.ReadSequence(Ctx(1)).ReadOctetString();
                    }
                    else
                    {
                        key.ReadEncodedValue();
                    }
                }

                return keyvalue.Length == 0 ? null : new KerberosSubkey(keytype, keyvalue);
            }

            body.ReadEncodedValue();
        }

        return null;
    }

    // Strips the GSS-API InitialContextToken framing ([APPLICATION 0] { krb5-OID, TOK_ID 0x0002, AP-REP }).
    private static byte[]? UnwrapGssApRep(byte[] token)
    {
        if (token.Length < 2 || token[0] != 0x60)
        {
            // Some stacks hand back a bare AP-REP already.
            return token.Length > 0 && token[0] == (0x40 | 0x20 | ApRepApp) ? token : null;
        }

        int i = 1;
        i += DerLengthBytes(token, i, out _); // skip the APPLICATION 0 length
        if (i + Krb5MechOid.Length + 2 > token.Length)
        {
            return null;
        }

        // Expect the KRB5 mech OID then TOK_ID 0x02 0x00 (AP-REP).
        for (int k = 0; k < Krb5MechOid.Length; k++)
        {
            if (token[i + k] != Krb5MechOid[k])
            {
                return null;
            }
        }

        i += Krb5MechOid.Length;
        if (token[i] != 0x02 || token[i + 1] != 0x00)
        {
            return null;
        }

        i += 2;
        return token[i..];
    }

    private static int DerLengthBytes(byte[] buf, int offset, out int length)
    {
        int b = buf[offset];
        if ((b & 0x80) == 0)
        {
            length = b;
            return 1;
        }

        int n = b & 0x7F;
        length = 0;
        for (int k = 1; k <= n; k++)
        {
            length = (length << 8) | buf[offset + k];
        }

        return 1 + n;
    }
}
