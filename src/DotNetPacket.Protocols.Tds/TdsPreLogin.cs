using DotNetPacket.Core;

namespace DotNetPacket.Protocols.Tds;

/// <summary>TDS packet types (MS-TDS 2.2.3.1.1) and PRELOGIN encryption values.</summary>
public static class TdsConstants
{
    public const byte PreLogin = 0x12;
    public const byte Login7 = 0x10;
    public const byte Sspi = 0x11;

    /// <summary>Status flag: this is the last packet of the message (EOM).</summary>
    public const byte StatusEom = 0x01;

    // PRELOGIN ENCRYPTION option values (MS-TDS 2.2.6.5).
    public const byte EncryptOff = 0;      // encryption available but off
    public const byte EncryptOn = 1;       // encryption on
    public const byte EncryptNotSupported = 2;
    public const byte EncryptRequired = 3; // server requires encryption

    // PRELOGIN option tokens.
    public const byte TokenVersion = 0x00;
    public const byte TokenEncryption = 0x01;
    public const byte TokenInstance = 0x02;
    public const byte TokenThreadId = 0x03;
    public const byte TokenEnd = 0xFF;

    public static string DescribeEncryption(byte enc) => enc switch
    {
        EncryptOff => "ENCRYPT_OFF (available, not used)",
        EncryptOn => "ENCRYPT_ON (in use)",
        EncryptNotSupported => "ENCRYPT_NOT_SUP (server has no encryption)",
        EncryptRequired => "ENCRYPT_REQ (server requires encryption)",
        _ => $"unknown ({enc})",
    };
}

/// <summary>Parsed PRELOGIN response: the server's encryption option and version bytes.</summary>
public sealed record TdsPreLoginResponse(byte Encryption, byte[] Version)
{
    /// <summary>Formats the 6-byte VERSION as major.minor.build (MS-TDS 2.2.6.5).</summary>
    public string VersionString => Version.Length >= 4
        ? $"{Version[0]}.{Version[1]}.{(Version[2] << 8) | Version[3]}"
        : string.Empty;
}

/// <summary>
/// The TDS PRELOGIN message (MS-TDS 2.2.6.5): an option table (token + 16-bit BE offset/length each,
/// terminated by 0xFF) followed by the option data. Port of impacket's <c>tds.TDS_PRELOGIN</c>, used
/// by checkMSSQLStatus to read the server's encryption posture. All multi-byte header fields are
/// big-endian.
/// </summary>
public static class TdsPreLogin
{
    /// <summary>The MSSQL client version impacket advertises (8.0.0x155).</summary>
    public static readonly byte[] ClientVersion = { 0x08, 0x00, 0x01, 0x55, 0x00, 0x00 };

    /// <summary>
    /// Builds a PRELOGIN payload with VERSION, ENCRYPTION, INSTANCE ("MSSQLServer\0") and THREADID,
    /// computing the option-table offsets. Matches impacket's <c>preLogin</c> request.
    /// </summary>
    public static byte[] Build(byte encryption, uint threadId, byte[]? version = null, string instance = "MSSQLServer")
    {
        version ??= ClientVersion;
        byte[] instanceBytes = System.Text.Encoding.ASCII.GetBytes(instance + "\0");

        // Option table: 4 descriptors (5 bytes each) + the 0xFF terminator = 21 bytes.
        const int tableSize = (4 * 5) + 1;
        int versionOffset = tableSize;
        int encryptionOffset = versionOffset + version.Length;
        int instanceOffset = encryptionOffset + 1;
        int threadIdOffset = instanceOffset + instanceBytes.Length;

        var w = new ByteWriter(ByteOrder.Big);
        void Option(byte token, int offset, int length)
        {
            w.WriteByte(token);
            w.WriteUInt16((ushort)offset);
            w.WriteUInt16((ushort)length);
        }

        Option(TdsConstants.TokenVersion, versionOffset, version.Length);
        Option(TdsConstants.TokenEncryption, encryptionOffset, 1);
        Option(TdsConstants.TokenInstance, instanceOffset, instanceBytes.Length);
        Option(TdsConstants.TokenThreadId, threadIdOffset, 4);
        w.WriteByte(TdsConstants.TokenEnd);

        w.WriteBytes(version);
        w.WriteByte(encryption);
        w.WriteBytes(instanceBytes);
        w.WriteUInt32(threadId, ByteOrder.Little); // ThreadID — impacket packs it little-endian
        return w.ToArray();
    }

    /// <summary>
    /// Parses a PRELOGIN payload (request or response), walking the option table to extract the
    /// ENCRYPTION byte and the VERSION bytes.
    /// </summary>
    public static TdsPreLoginResponse Parse(byte[] payload)
    {
        byte encryption = TdsConstants.EncryptNotSupported;
        byte[] version = Array.Empty<byte>();

        var r = new ByteReader(payload, ByteOrder.Big);
        while (r.Remaining >= 1)
        {
            byte token = r.ReadByte();
            if (token == TdsConstants.TokenEnd)
            {
                break;
            }

            ushort offset = r.ReadUInt16();
            ushort length = r.ReadUInt16();
            if (offset + length > payload.Length)
            {
                continue;
            }

            if (token == TdsConstants.TokenEncryption && length >= 1)
            {
                encryption = payload[offset];
            }
            else if (token == TdsConstants.TokenVersion)
            {
                version = payload[offset..(offset + length)];
            }
        }

        return new TdsPreLoginResponse(encryption, version);
    }
}
