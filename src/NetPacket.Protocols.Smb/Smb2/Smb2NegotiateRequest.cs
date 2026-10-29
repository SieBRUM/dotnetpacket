using System.Security.Cryptography;
using NetPacket.Core;

namespace NetPacket.Protocols.Smb;

/// <summary>
/// SMB2 NEGOTIATE request (MS-SMB2 2.2.3). Port of impacket's
/// <c>smb3structs.SMB2Negotiate</c>, but with defaults chosen to resemble a real
/// modern Windows client rather than tool defaults — see <c>docs/REALISM.md</c>.
/// </summary>
/// <remarks>
/// Uses the manual-override pattern because the dialect list, the 8-byte
/// alignment, and the SMB 3.1.1 negotiate contexts cross-reference each other
/// (<c>NegotiateContextOffset</c> is relative to the start of the SMB2 header, so
/// this request is packed assuming a <see cref="Smb2Header.Size"/>-byte header
/// precedes it, which is always the case).
/// </remarks>
public sealed class Smb2NegotiateRequest : NetStructure
{
    public override ByteOrder ByteOrder => ByteOrder.Little;

    public Smb2SecurityMode SecurityMode { get; set; } = Smb2SecurityMode.SigningEnabled;

    /// <summary>Advertised like a Windows 10/11 workstation. Only sent for SMB 3.x dialects.</summary>
    public Smb2Capabilities Capabilities { get; set; } =
        Smb2Capabilities.Dfs | Smb2Capabilities.Leasing | Smb2Capabilities.LargeMtu |
        Smb2Capabilities.MultiChannel | Smb2Capabilities.DirectoryLeasing | Smb2Capabilities.Encryption;

    /// <summary>
    /// Real clients use a stable per-machine GUID; this defaults to random bytes
    /// per connection. Set it to a fixed value for sustained realism.
    /// </summary>
    public byte[] ClientGuid { get; set; } = RandomNumberGenerator.GetBytes(16);

    /// <summary>Dialects offered, in the order a current Windows client offers them.</summary>
    public IList<Smb2Dialect> Dialects { get; set; } = new List<Smb2Dialect>
    {
        Smb2Dialect.Smb202,
        Smb2Dialect.Smb210,
        Smb2Dialect.Smb300,
        Smb2Dialect.Smb302,
        Smb2Dialect.Smb311,
    };

    // --- SMB 3.1.1 negotiate-context inputs (only emitted when 3.1.1 is offered) ---

    public ushort[] PreauthHashAlgorithms { get; set; } = { Smb2HashAlgorithm.Sha512 };

    public byte[] PreauthSalt { get; set; } = RandomNumberGenerator.GetBytes(32);

    public ushort[] Ciphers { get; set; } = { Smb2Cipher.Aes128Gcm, Smb2Cipher.Aes128Ccm };

    private bool Offers311 => Dialects.Contains(Smb2Dialect.Smb311);

    private bool OffersSmb3 =>
        Dialects.Contains(Smb2Dialect.Smb300) ||
        Dialects.Contains(Smb2Dialect.Smb302) ||
        Offers311;

    public override void PackInto(ByteWriter writer)
    {
        int dialectBytes = Dialects.Count * 2;
        uint contextOffset = Offers311
            ? (uint)Align8(Smb2Header.Size + 36 + dialectBytes)
            : 0u;
        ushort contextCount = Offers311 ? (ushort)2 : (ushort)0;

        // Fixed 36-byte part.
        writer.WriteUInt16(36);                                 // StructureSize
        writer.WriteUInt16((ushort)Dialects.Count);             // DialectCount
        writer.WriteUInt16((ushort)SecurityMode);               // SecurityMode
        writer.WriteUInt16(0);                                  // Reserved
        writer.WriteUInt32(OffersSmb3 ? (uint)Capabilities : 0); // Capabilities (3.x only)
        writer.WriteBytes(NormalizeGuid());                     // ClientGuid (16)
        writer.WriteUInt32(contextOffset);                      // NegotiateContextOffset
        writer.WriteUInt16(contextCount);                       // NegotiateContextCount
        writer.WriteUInt16(0);                                  // Reserved2

        // Dialect array.
        foreach (Smb2Dialect dialect in Dialects)
        {
            writer.WriteUInt16((ushort)dialect);
        }

        if (!Offers311)
        {
            return;
        }

        // Negotiate contexts, each 8-byte aligned from the start of the SMB2 header.
        AlignTo8(writer);
        WritePreauthIntegrityContext(writer);
        AlignTo8(writer);
        WriteEncryptionContext(writer);
    }

    private void WritePreauthIntegrityContext(ByteWriter writer)
    {
        var data = new ByteWriter(ByteOrder.Little);
        data.WriteUInt16((ushort)PreauthHashAlgorithms.Length); // HashAlgorithmCount
        data.WriteUInt16((ushort)PreauthSalt.Length);           // SaltLength
        foreach (ushort algorithm in PreauthHashAlgorithms)
        {
            data.WriteUInt16(algorithm);
        }

        data.WriteBytes(PreauthSalt);

        WriteContext(writer, Smb2NegotiateContextType.PreauthIntegrityCapabilities, data.ToArray());
    }

    private void WriteEncryptionContext(ByteWriter writer)
    {
        var data = new ByteWriter(ByteOrder.Little);
        data.WriteUInt16((ushort)Ciphers.Length); // CipherCount
        foreach (ushort cipher in Ciphers)
        {
            data.WriteUInt16(cipher);
        }

        WriteContext(writer, Smb2NegotiateContextType.EncryptionCapabilities, data.ToArray());
    }

    private static void WriteContext(ByteWriter writer, Smb2NegotiateContextType type, byte[] data)
    {
        writer.WriteUInt16((ushort)type);
        writer.WriteUInt16((ushort)data.Length);
        writer.WriteUInt32(0); // Reserved
        writer.WriteBytes(data);
    }

    // Pad the writer so that the next byte sits on an 8-byte boundary relative to
    // the SMB2 header (which precedes this body).
    private static void AlignTo8(ByteWriter writer)
    {
        int absolute = Smb2Header.Size + writer.Length;
        int padding = Align8(absolute) - absolute;
        for (int i = 0; i < padding; i++)
        {
            writer.WriteByte(0);
        }
    }

    private byte[] NormalizeGuid()
    {
        if (ClientGuid.Length == 16)
        {
            return ClientGuid;
        }

        var guid = new byte[16];
        Array.Copy(ClientGuid, guid, Math.Min(ClientGuid.Length, 16));
        return guid;
    }

    private static int Align8(int value) => (value + 7) & ~7;
}
