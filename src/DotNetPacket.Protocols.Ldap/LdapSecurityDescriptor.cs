using DotNetPacket.Core;

namespace DotNetPacket.Protocols.Ldap;

/// <summary>One parsed DACL ACE: its type, access mask, optional object-type GUID, and trustee SID.</summary>
public sealed record LdapAce(byte AceType, uint Mask, Guid? ObjectType, string Sid);

/// <summary>
/// A parsed Windows security descriptor (MS-DTYP 2.4.6 SR_SECURITY_DESCRIPTOR): owner SID and the
/// DACL's ACEs. Port of the parsing in impacket's <c>ldaptypes</c>, used by badsuccessor to analyse
/// OU permissions (nTSecurityDescriptor) and to build the dMSA's msDS-GroupMSAMembership SD.
/// </summary>
public sealed class LdapSecurityDescriptor
{
    public const byte AccessAllowedAceType = 0x00;
    public const byte AccessAllowedObjectAceType = 0x05;

    public string OwnerSid { get; private init; } = string.Empty;

    public IReadOnlyList<LdapAce> DaclAces { get; private init; } = Array.Empty<LdapAce>();

    public static LdapSecurityDescriptor Parse(byte[] data)
    {
        var r = new ByteReader(data, ByteOrder.Little);
        r.ReadByte();                 // Revision
        r.ReadByte();                 // Sbz1
        r.ReadUInt16();               // Control
        uint ownerOffset = r.ReadUInt32();
        r.ReadUInt32();               // GroupSid offset
        r.ReadUInt32();               // Sacl offset
        uint daclOffset = r.ReadUInt32();

        string owner = string.Empty;
        if (ownerOffset != 0 && ownerOffset < data.Length)
        {
            owner = LdapSid.ToCanonical(data[(int)ownerOffset..]);
        }

        var aces = new List<LdapAce>();
        if (daclOffset != 0 && daclOffset + 8 <= data.Length)
        {
            var d = new ByteReader(data, ByteOrder.Little) { Position = (int)daclOffset };
            d.ReadByte();             // AclRevision
            d.ReadByte();             // Sbz1
            d.ReadUInt16();           // AclSize
            ushort aceCount = d.ReadUInt16();
            d.ReadUInt16();           // Sbz2

            for (int i = 0; i < aceCount; i++)
            {
                int aceStart = d.Position;
                byte aceType = d.ReadByte();
                d.ReadByte();         // AceFlags
                ushort aceSize = d.ReadUInt16();
                uint mask = d.ReadUInt32();

                Guid? objectType = null;
                if (aceType == AccessAllowedObjectAceType)
                {
                    uint objectFlags = d.ReadUInt32();
                    if ((objectFlags & 0x1) != 0) // ACE_OBJECT_TYPE_PRESENT
                    {
                        objectType = new Guid(d.ReadBytes(16));
                    }

                    if ((objectFlags & 0x2) != 0) // ACE_INHERITED_OBJECT_TYPE_PRESENT
                    {
                        d.ReadBytes(16);
                    }
                }

                string sid = LdapSid.ToCanonical(d.ReadBytes(aceStart + aceSize - d.Position));
                aces.Add(new LdapAce(aceType, mask, objectType, sid));
                d.Position = aceStart + aceSize; // next ACE (robust against trailing bytes)
            }
        }

        return new LdapSecurityDescriptor { OwnerSid = owner, DaclAces = aces };
    }

    /// <summary>
    /// Builds the msDS-GroupMSAMembership / nTSecurityDescriptor bytes badsuccessor sets on the dMSA:
    /// owner = the principal, DACL with two ACCESS_ALLOWED ACEs for that SID (0x000F01FF and
    /// GenericAll 0x10000000). Self-relative, Control 0x8004. Matches impacket's build.
    /// </summary>
    public static byte[] BuildGroupMsaMembership(string principalSid)
    {
        byte[] sid = LdapSid.FromCanonical(principalSid);

        // Two ACCESS_ALLOWED_ACEs: header(4) + Mask(4) + Sid.
        byte[] ace1 = BuildAllowAce(0x000F01FF, sid);
        byte[] ace2 = BuildAllowAce(0x10000000, sid);
        int aclSize = 8 + ace1.Length + ace2.Length; // ACL header is 8 bytes

        // Self-relative layout matching impacket: header(20) + DACL(at 20) + OwnerSid(after the DACL).
        const int daclOffset = 20;
        int ownerOffset = daclOffset + aclSize;

        var w = new ByteWriter(ByteOrder.Little);
        w.WriteByte(1);                       // Revision
        w.WriteByte(0);                       // Sbz1
        w.WriteUInt16(0x8004);                // Control: SE_DACL_PRESENT | SE_SELF_RELATIVE
        w.WriteUInt32((uint)ownerOffset);     // OffsetOwner
        w.WriteUInt32(0);                     // OffsetGroup
        w.WriteUInt32(0);                     // OffsetSacl
        w.WriteUInt32(daclOffset);            // OffsetDacl
        // ACL
        w.WriteByte(4);                       // AclRevision (ADS)
        w.WriteByte(0);                       // Sbz1
        w.WriteUInt16((ushort)aclSize);       // AclSize
        w.WriteUInt16(2);                     // AceCount
        w.WriteUInt16(0);                     // Sbz2
        w.WriteBytes(ace1);
        w.WriteBytes(ace2);
        w.WriteBytes(sid);                    // OwnerSid (after the DACL)
        return w.ToArray();
    }

    private static byte[] BuildAllowAce(uint mask, byte[] sid)
    {
        ushort size = (ushort)(8 + sid.Length); // AceType(1)+Flags(1)+Size(2)+Mask(4)+Sid
        var w = new ByteWriter(ByteOrder.Little);
        w.WriteByte(AccessAllowedAceType);
        w.WriteByte(0);                        // AceFlags
        w.WriteUInt16(size);
        w.WriteUInt32(mask);
        w.WriteBytes(sid);
        return w.ToArray();
    }
}
