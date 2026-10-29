using System.Text;
using NetPacket.Core;

namespace NetPacket.Protocols.Smb;

/// <summary>
/// SMB2 TREE_CONNECT request (MS-SMB2 2.2.9). Connects to a share by UNC path
/// (e.g. <c>\\server\share</c>). Port of impacket's <c>smb3structs.SMB2TreeConnect</c>.
/// </summary>
public sealed class Smb2TreeConnectRequest : NetStructure
{
    public override ByteOrder ByteOrder => ByteOrder.Little;

    public ushort Flags { get; set; }

    /// <summary>The share UNC path, e.g. <c>\\127.0.0.1\public</c>.</summary>
    public string Path { get; set; } = string.Empty;

    public override void PackInto(ByteWriter writer)
    {
        byte[] path = Encoding.Unicode.GetBytes(Path);
        writer.WriteUInt16(9);                                // StructureSize (fixed 8, +1 convention)
        writer.WriteUInt16(Flags);
        writer.WriteUInt16((ushort)(Smb2Header.Size + 8));    // PathOffset (from header start)
        writer.WriteUInt16((ushort)path.Length);              // PathLength
        writer.WriteBytes(path);
    }
}

/// <summary>SMB2 TREE_CONNECT response (MS-SMB2 2.2.10). The TreeId is in the SMB2 header.</summary>
public sealed class Smb2TreeConnectResponse : NetStructure
{
    public override ByteOrder ByteOrder => ByteOrder.Little;

    public Smb2ShareType ShareType { get; private set; }

    public Smb2ShareFlags ShareFlags { get; private set; }

    public Smb2ShareCapabilities Capabilities { get; private set; }

    /// <summary>The access the server grants the caller on this share (an ACCESS_MASK).</summary>
    public uint MaximalAccess { get; private set; }

    public override void Unpack(ByteReader reader)
    {
        reader.Position += Smb2Header.Size; // skip the SMB2 header

        reader.ReadUInt16(); // StructureSize
        ShareType = (Smb2ShareType)reader.ReadByte();
        reader.ReadByte(); // Reserved
        ShareFlags = (Smb2ShareFlags)reader.ReadUInt32();
        Capabilities = (Smb2ShareCapabilities)reader.ReadUInt32();
        MaximalAccess = reader.ReadUInt32();
    }
}
