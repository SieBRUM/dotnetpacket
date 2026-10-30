using DotNetPacket.Core;

namespace DotNetPacket.Protocols.Smb;

/// <summary>
/// SMB2 SESSION_SETUP request (MS-SMB2 2.2.5). Carries a GSS/SPNEGO security blob
/// (which wraps the NTLM token). Port of impacket's
/// <c>smb3structs.SMB2SessionSetup</c>.
/// </summary>
public sealed class Smb2SessionSetupRequest : NetStructure
{
    public override ByteOrder ByteOrder => ByteOrder.Little;

    public byte Flags { get; set; }

    public Smb2SecurityMode SecurityMode { get; set; } = Smb2SecurityMode.SigningEnabled;

    /// <summary>A Windows client advertises DFS here.</summary>
    public Smb2Capabilities Capabilities { get; set; } = Smb2Capabilities.Dfs;

    public ulong PreviousSessionId { get; set; }

    /// <summary>The GSS/SPNEGO token (wrapping the NTLM NEGOTIATE or AUTHENTICATE).</summary>
    public byte[] SecurityBuffer { get; set; } = Array.Empty<byte>();

    public override void PackInto(ByteWriter writer)
    {
        writer.WriteUInt16(25);                 // StructureSize (fixed part is 24, +1 convention)
        writer.WriteByte(Flags);
        writer.WriteByte((byte)SecurityMode);
        writer.WriteUInt32((uint)Capabilities);
        writer.WriteUInt32(0);                  // Channel
        writer.WriteUInt16((ushort)(Smb2Header.Size + 24)); // SecurityBufferOffset (from header start)
        writer.WriteUInt16((ushort)SecurityBuffer.Length);  // SecurityBufferLength
        writer.WriteUInt64(PreviousSessionId);
        writer.WriteBytes(SecurityBuffer);
    }
}

/// <summary>SMB2 SESSION_SETUP response (MS-SMB2 2.2.6). Parses the returned SPNEGO blob.</summary>
public sealed class Smb2SessionSetupResponse : NetStructure
{
    public override ByteOrder ByteOrder => ByteOrder.Little;

    public ushort SessionFlags { get; private set; }

    /// <summary>The GSS/SPNEGO token (wrapping the NTLM CHALLENGE, or empty on success).</summary>
    public byte[] SecurityBuffer { get; private set; } = Array.Empty<byte>();

    public override void Unpack(ByteReader reader)
    {
        reader.Position += Smb2Header.Size; // skip the SMB2 header

        reader.ReadUInt16(); // StructureSize
        SessionFlags = reader.ReadUInt16();
        ushort securityBufferOffset = reader.ReadUInt16();
        ushort securityBufferLength = reader.ReadUInt16();

        if (securityBufferLength > 0)
        {
            reader.Position = securityBufferOffset; // offset from the SMB2 header start
            SecurityBuffer = reader.ReadBytes(securityBufferLength);
        }
    }
}
