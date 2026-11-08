using DotNetPacket.Core;

namespace DotNetPacket.Protocols.Ldap;

/// <summary>
/// A round-trippable self-relative security descriptor (MS-DTYP 2.4.6 SR_SECURITY_DESCRIPTOR). Port
/// of impacket's <c>ldaptypes.SR_SECURITY_DESCRIPTOR</c>, used by dacledit to read a target's
/// nTSecurityDescriptor, edit its DACL, and push it back. <see cref="GetData"/> reproduces impacket's
/// <c>getData()</c> byte-for-byte: the self-relative body is laid out in the order Sacl, Dacl, Owner,
/// Group with offsets recomputed, and absent parts get offset 0.
///
/// In dacledit's flow the directory is queried with the LDAP_SERVER_SD_FLAGS control set to
/// DACL_SECURITY_INFORMATION (0x04), so the server returns a DACL-only descriptor (owner/group/sacl
/// offsets 0); the owner/group/sacl passthrough here is for faithfulness when they are present.
/// </summary>
public sealed class NtSecurityDescriptor
{
    private const int HeaderLength = 20;

    public byte Revision { get; set; } = 1;

    public byte Sbz1 { get; set; }

    public ushort Control { get; set; } = 0x8004; // SE_DACL_PRESENT | SE_SELF_RELATIVE

    /// <summary>Owner SID bytes (empty when the descriptor carries no owner).</summary>
    public byte[] OwnerSid { get; set; } = Array.Empty<byte>();

    /// <summary>Group SID bytes (empty when absent).</summary>
    public byte[] GroupSid { get; set; } = Array.Empty<byte>();

    /// <summary>SACL (null when absent); re-serialized like the DACL.</summary>
    public NtAcl? Sacl { get; set; }

    /// <summary>DACL (null when the descriptor has no DACL present).</summary>
    public NtAcl? Dacl { get; set; }

    public static NtSecurityDescriptor Parse(byte[] data)
    {
        var r = new ByteReader(data, ByteOrder.Little);
        var sd = new NtSecurityDescriptor
        {
            Revision = r.ReadByte(),
            Sbz1 = r.ReadByte(),
            Control = r.ReadUInt16(),
        };
        uint offOwner = r.ReadUInt32();
        uint offGroup = r.ReadUInt32();
        uint offSacl = r.ReadUInt32();
        uint offDacl = r.ReadUInt32();

        if (offOwner != 0)
        {
            sd.OwnerSid = SliceSid(data, (int)offOwner);
        }

        if (offGroup != 0)
        {
            sd.GroupSid = SliceSid(data, (int)offGroup);
        }

        if (offSacl != 0)
        {
            sd.Sacl = NtAcl.Parse(data, (int)offSacl);
        }

        if (offDacl != 0)
        {
            sd.Dacl = NtAcl.Parse(data, (int)offDacl);
        }

        return sd;
    }

    public byte[] GetData()
    {
        byte[] sacl = Sacl?.Serialize() ?? Array.Empty<byte>();
        byte[] dacl = Dacl?.Serialize() ?? Array.Empty<byte>();

        // Self-relative body order, matching impacket getData(): Sacl, Dacl, Owner, Group.
        int cursor = HeaderLength;
        uint offSacl = 0, offDacl = 0, offOwner = 0, offGroup = 0;
        if (Sacl is not null)
        {
            offSacl = (uint)cursor;
            cursor += sacl.Length;
        }

        if (Dacl is not null)
        {
            offDacl = (uint)cursor;
            cursor += dacl.Length;
        }

        if (OwnerSid.Length > 0)
        {
            offOwner = (uint)cursor;
            cursor += OwnerSid.Length;
        }

        if (GroupSid.Length > 0)
        {
            offGroup = (uint)cursor;
        }

        var w = new ByteWriter(ByteOrder.Little);
        w.WriteByte(Revision);
        w.WriteByte(Sbz1);
        w.WriteUInt16(Control);
        w.WriteUInt32(offOwner);
        w.WriteUInt32(offGroup);
        w.WriteUInt32(offSacl);
        w.WriteUInt32(offDacl);
        w.WriteBytes(sacl);
        w.WriteBytes(dacl);
        w.WriteBytes(OwnerSid);
        w.WriteBytes(GroupSid);
        return w.ToArray();
    }

    private static byte[] SliceSid(byte[] data, int offset)
    {
        int subCount = data[offset + 1];
        int len = 8 + (4 * subCount);
        return data[offset..(offset + len)];
    }
}
