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

    /// <summary>The result of processing a DCE-style AP-REP: the acceptor subkey and the ALTER_CONTEXT response token.</summary>
    public sealed record DceApRep(KerberosSubkey Subkey, int SequenceNumber, byte[] AltContextApRep);

    /// <summary>
    /// Processes the AP-REP from a DCE-style Kerberos DCERPC BIND_ACK (impacket's
    /// <c>getKerberosType3</c>): decrypts EncAPRepPart (usage 12) to recover the acceptor subkey and
    /// sequence number, then builds the third-leg AP-REP to send in the ALTER_CONTEXT — a re-encoded
    /// EncAPRepPart (subkey removed, ctime/cusec refreshed, same seq-number) re-encrypted under the
    /// ticket session key. Returns a bare (non-GSS-framed) AP-REP, as the response token.
    /// </summary>
    public static DceApRep ProcessDceApRep(byte[] responseToken, byte[] sessionKey, int sessionKeyEtype)
    {
        byte[] apRep = UnwrapGssApRep(responseToken) ?? responseToken;

        AsnReader body = new AsnReader(apRep, AsnEncodingRules.DER)
            .ReadSequence(new Asn1Tag(TagClass.Application, ApRepApp))
            .ReadSequence();

        byte[] cipher = Array.Empty<byte>();
        while (body.HasData)
        {
            if (body.PeekTag().HasSameClassAndValue(Ctx(2)))
            {
                AsnReader enc = body.ReadSequence(Ctx(2)).ReadSequence();
                while (enc.HasData)
                {
                    if (enc.PeekTag().HasSameClassAndValue(Ctx(2)))
                    {
                        cipher = enc.ReadSequence(Ctx(2)).ReadOctetString();
                    }
                    else
                    {
                        enc.ReadEncodedValue();
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
            throw new InvalidDataException("DCE AP-REP carries no enc-part.");
        }

        byte[] plain = Krb5Cipher.Decrypt(sessionKeyEtype, sessionKey, ApRepEncPartUsage, cipher);
        KerberosSubkey subkey = ParseSubkey(plain) ?? throw new InvalidDataException("DCE AP-REP has no subkey.");
        int seq = ParseSeqNumber(plain);

        byte[] newEncPart = BuildEncApRepPart(DateTimeOffset.UtcNow, seq);
        byte[] reEncrypted = Krb5Cipher.Encrypt(sessionKeyEtype, sessionKey, ApRepEncPartUsage, newEncPart);
        byte[] altApRep = BuildApRep(sessionKeyEtype, reEncrypted);
        return new DceApRep(subkey, seq, altApRep);
    }

    private static Asn1Tag App(int n) => new(TagClass.Application, n, isConstructed: true);

    // EncAPRepPart ::= [APPLICATION 27] SEQUENCE { ctime [0], cusec [1], seq-number [3] } (no subkey for the DCE reply).
    private static byte[] BuildEncApRepPart(DateTimeOffset now, int seq)
    {
        var w = new AsnWriter(AsnEncodingRules.DER);
        using (w.PushSequence(App(EncApRepPartApp)))
        using (w.PushSequence())
        {
            using (w.PushSequence(Ctx(0))) w.WriteGeneralizedTime(now, omitFractionalSeconds: true);
            using (w.PushSequence(Ctx(1))) w.WriteInteger(now.Microsecond);
            using (w.PushSequence(Ctx(3))) w.WriteInteger(seq);
        }

        return w.Encode();
    }

    // AP-REP ::= [APPLICATION 15] SEQUENCE { pvno [0]=5, msg-type [1]=15, enc-part [2] EncryptedData }
    private static byte[] BuildApRep(int etype, byte[] encryptedPart)
    {
        var w = new AsnWriter(AsnEncodingRules.DER);
        using (w.PushSequence(App(ApRepApp)))
        using (w.PushSequence())
        {
            using (w.PushSequence(Ctx(0))) w.WriteInteger(5);   // pvno
            using (w.PushSequence(Ctx(1))) w.WriteInteger(15);  // msg-type = AP-REP
            using (w.PushSequence(Ctx(2)))                      // enc-part EncryptedData
            using (w.PushSequence())
            {
                using (w.PushSequence(Ctx(0))) w.WriteInteger(etype);
                using (w.PushSequence(Ctx(2))) w.WriteOctetString(encryptedPart);
            }
        }

        return w.Encode();
    }

    // EncAPRepPart seq-number [3].
    private static int ParseSeqNumber(byte[] encApRepPart)
    {
        AsnReader b = new AsnReader(encApRepPart, AsnEncodingRules.DER)
            .ReadSequence(App(EncApRepPartApp))
            .ReadSequence();
        while (b.HasData)
        {
            if (b.PeekTag().HasSameClassAndValue(Ctx(3)))
            {
                return (int)b.ReadSequence(Ctx(3)).ReadInteger();
            }

            b.ReadEncodedValue();
        }

        return 0;
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
