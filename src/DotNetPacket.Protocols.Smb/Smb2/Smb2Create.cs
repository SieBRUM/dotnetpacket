using System.Text;
using DotNetPacket.Core;

namespace DotNetPacket.Protocols.Smb;

/// <summary>
/// SMB2 CREATE request (MS-SMB2 2.2.13): open or create a file/directory on a
/// connected tree. Port of impacket's <c>smb3structs.SMB2Create</c>. Create
/// contexts are not sent (a realism gap — Windows sends DHnQ/MxAc/QFid/etc.).
/// </summary>
public sealed class Smb2CreateRequest : NetStructure
{
    public override ByteOrder ByteOrder => ByteOrder.Little;

    public Smb2OplockLevel OplockLevel { get; set; } = Smb2OplockLevel.None;

    public Smb2ImpersonationLevel ImpersonationLevel { get; set; } = Smb2ImpersonationLevel.Impersonation;

    public Smb2AccessMask DesiredAccess { get; set; } = Smb2AccessMask.FileGenericRead;

    public Smb2FileAttributes FileAttributes { get; set; } = Smb2FileAttributes.None;

    public Smb2ShareAccess ShareAccess { get; set; } = Smb2ShareAccess.All;

    public Smb2CreateDisposition CreateDisposition { get; set; } = Smb2CreateDisposition.Open;

    public Smb2CreateOptions CreateOptions { get; set; } = Smb2CreateOptions.NonDirectoryFile;

    /// <summary>Share-relative path, no leading backslash (e.g. <c>readme.txt</c> or <c>dir\file.txt</c>).</summary>
    public string Path { get; set; } = string.Empty;

    public override void PackInto(ByteWriter writer)
    {
        byte[] name = Encoding.Unicode.GetBytes(Path);

        writer.WriteUInt16(57);                                 // StructureSize (fixed 56, +1)
        writer.WriteByte(0);                                    // SecurityFlags
        writer.WriteByte((byte)OplockLevel);
        writer.WriteUInt32((uint)ImpersonationLevel);
        writer.WriteUInt64(0);                                  // SmbCreateFlags
        writer.WriteUInt64(0);                                  // Reserved
        writer.WriteUInt32((uint)DesiredAccess);
        writer.WriteUInt32((uint)FileAttributes);
        writer.WriteUInt32((uint)ShareAccess);
        writer.WriteUInt32((uint)CreateDisposition);
        writer.WriteUInt32((uint)CreateOptions);
        writer.WriteUInt16((ushort)(Smb2Header.Size + 56));     // NameOffset
        writer.WriteUInt16((ushort)name.Length);                // NameLength
        writer.WriteUInt32(0);                                  // CreateContextsOffset
        writer.WriteUInt32(0);                                  // CreateContextsLength
        writer.WriteBytes(name.Length > 0 ? name : new byte[] { 0 }); // buffer (>=1 byte)
    }
}

/// <summary>SMB2 CREATE response (MS-SMB2 2.2.14). The 16-byte FileId is the open handle.</summary>
public sealed class Smb2CreateResponse : NetStructure
{
    public override ByteOrder ByteOrder => ByteOrder.Little;

    public uint CreateAction { get; private set; }

    public ulong EndOfFile { get; private set; }

    public Smb2FileAttributes FileAttributes { get; private set; }

    public byte[] FileId { get; private set; } = new byte[16];

    public override void Unpack(ByteReader reader)
    {
        reader.Position += Smb2Header.Size; // skip the SMB2 header

        reader.ReadUInt16(); // StructureSize
        reader.ReadByte();   // OplockLevel
        reader.ReadByte();   // Flags
        CreateAction = reader.ReadUInt32();
        reader.ReadUInt64(); // CreationTime
        reader.ReadUInt64(); // LastAccessTime
        reader.ReadUInt64(); // LastWriteTime
        reader.ReadUInt64(); // ChangeTime
        reader.ReadUInt64(); // AllocationSize
        EndOfFile = reader.ReadUInt64();
        FileAttributes = (Smb2FileAttributes)reader.ReadUInt32();
        reader.ReadUInt32(); // Reserved2
        FileId = reader.ReadBytes(16);
    }
}
