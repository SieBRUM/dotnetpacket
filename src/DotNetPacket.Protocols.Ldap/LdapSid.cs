namespace DotNetPacket.Protocols.Ldap;

/// <summary>
/// Windows SID (MS-DTYP 2.4.2) binary ↔ canonical "S-1-5-..." string conversion. Used when
/// parsing/building security descriptors (nTSecurityDescriptor, msDS-GroupMSAMembership). Port of
/// the SID handling in impacket's <c>ldaptypes.LDAP_SID</c> / badsuccessor.py.
/// </summary>
public static class LdapSid
{
    /// <summary>Formats a binary SID as its canonical "S-R-A-S1-S2-..." string (empty if malformed).</summary>
    public static string ToCanonical(byte[] sid)
    {
        if (sid.Length < 8)
        {
            return string.Empty;
        }

        int revision = sid[0];
        int subCount = sid[1];
        long authority = 0;
        for (int i = 2; i < 8; i++)
        {
            authority = (authority << 8) | sid[i]; // IdentifierAuthority is big-endian
        }

        var parts = new List<string>();
        for (int i = 0; i < subCount; i++)
        {
            int off = 8 + (i * 4);
            if (off + 4 > sid.Length)
            {
                break;
            }

            uint sub = (uint)(sid[off] | (sid[off + 1] << 8) | (sid[off + 2] << 16) | (sid[off + 3] << 24)); // LE
            parts.Add(sub.ToString());
        }

        return parts.Count == 0 ? $"S-{revision}-{authority}" : $"S-{revision}-{authority}-{string.Join('-', parts)}";
    }

    /// <summary>Encodes a canonical "S-1-5-..." SID string to its binary form.</summary>
    public static byte[] FromCanonical(string sid)
    {
        string[] p = sid.Split('-');
        // p[0]="S", p[1]=revision, p[2]=authority, p[3..]=sub-authorities
        byte revision = byte.Parse(p[1]);
        long authority = long.Parse(p[2]);
        int subCount = p.Length - 3;

        var bytes = new byte[8 + (subCount * 4)];
        bytes[0] = revision;
        bytes[1] = (byte)subCount;
        for (int i = 0; i < 6; i++)
        {
            bytes[2 + i] = (byte)((authority >> (8 * (5 - i))) & 0xFF); // big-endian
        }

        for (int i = 0; i < subCount; i++)
        {
            uint sub = uint.Parse(p[3 + i]);
            int off = 8 + (i * 4);
            bytes[off] = (byte)(sub & 0xFF);
            bytes[off + 1] = (byte)((sub >> 8) & 0xFF);
            bytes[off + 2] = (byte)((sub >> 16) & 0xFF);
            bytes[off + 3] = (byte)((sub >> 24) & 0xFF);
        }

        return bytes;
    }
}
