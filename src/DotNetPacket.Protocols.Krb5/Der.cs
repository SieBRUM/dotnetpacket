using System.Text;

namespace DotNetPacket.Protocols.Krb5;

/// <summary>
/// Tiny DER helpers for the one Kerberos type <see cref="System.Formats.Asn1.AsnWriter"/> cannot
/// emit directly: GeneralString (tag 0x1B), which RFC 4120 uses for KerberosString / Realm.
/// The result is fed to <c>AsnWriter.WriteEncodedValue</c>.
/// </summary>
internal static class Der
{
    public const byte GeneralStringTag = 0x1B;

    /// <summary>Encodes an ASCII string as a DER GeneralString TLV.</summary>
    public static byte[] GeneralString(string value) => Tlv(GeneralStringTag, Encoding.ASCII.GetBytes(value));

    private static byte[] Tlv(byte tag, byte[] content)
    {
        byte[] len = Length(content.Length);
        var tlv = new byte[1 + len.Length + content.Length];
        tlv[0] = tag;
        Array.Copy(len, 0, tlv, 1, len.Length);
        Array.Copy(content, 0, tlv, 1 + len.Length, content.Length);
        return tlv;
    }

    private static byte[] Length(int n)
    {
        if (n < 0x80)
        {
            return new[] { (byte)n };
        }

        var bytes = new List<byte>();
        int v = n;
        while (v > 0)
        {
            bytes.Insert(0, (byte)(v & 0xFF));
            v >>= 8;
        }

        bytes.Insert(0, (byte)(0x80 | bytes.Count));
        return bytes.ToArray();
    }
}
