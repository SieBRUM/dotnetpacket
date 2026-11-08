using DotNetPacket.Core;

namespace DotNetPacket.Protocols.Ldap;

/// <summary>
/// An ACL (MS-DTYP 2.4.5) — the ordered list of ACEs that makes up a DACL (or SACL). Port of
/// impacket's <c>ldaptypes.ACL</c>. <see cref="Serialize"/> recomputes AceCount and AclSize from the
/// ACE list exactly as impacket's <c>getData()</c> does, so an edited DACL round-trips faithfully.
/// </summary>
public sealed class NtAcl
{
    public byte AclRevision { get; set; } = 4; // ACL_REVISION_DS (AD objects)

    public byte Sbz1 { get; set; }

    public ushort Sbz2 { get; set; }

    public List<NtAce> Aces { get; } = new();

    public static NtAcl Parse(byte[] data, int offset)
    {
        var r = new ByteReader(data, ByteOrder.Little) { Position = offset };
        var acl = new NtAcl
        {
            AclRevision = r.ReadByte(),
            Sbz1 = r.ReadByte(),
        };
        r.ReadUInt16();                  // AclSize (recomputed on serialize)
        ushort aceCount = r.ReadUInt16();
        acl.Sbz2 = r.ReadUInt16();

        for (int i = 0; i < aceCount; i++)
        {
            acl.Aces.Add(NtAce.Parse(r));
        }

        return acl;
    }

    public byte[] Serialize()
    {
        var aceBlock = new ByteWriter(ByteOrder.Little);
        foreach (NtAce ace in Aces)
        {
            aceBlock.WriteBytes(ace.Serialize());
        }

        byte[] aces = aceBlock.ToArray();
        var w = new ByteWriter(ByteOrder.Little);
        w.WriteByte(AclRevision);
        w.WriteByte(Sbz1);
        w.WriteUInt16((ushort)(aces.Length + 8)); // AclSize includes the 8-byte header
        w.WriteUInt16((ushort)Aces.Count);
        w.WriteUInt16(Sbz2);
        w.WriteBytes(aces);
        return w.ToArray();
    }
}
