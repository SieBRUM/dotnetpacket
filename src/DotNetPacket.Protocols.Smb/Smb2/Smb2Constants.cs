namespace DotNetPacket.Protocols.Smb;

/// <summary>SMB2/3 command codes (MS-SMB2 2.2.1.1). Port of impacket <c>smb3structs</c> command constants.</summary>
public enum Smb2Command : ushort
{
    Negotiate = 0x0000,
    SessionSetup = 0x0001,
    Logoff = 0x0002,
    TreeConnect = 0x0003,
    TreeDisconnect = 0x0004,
    Create = 0x0005,
    Close = 0x0006,
    Flush = 0x0007,
    Read = 0x0008,
    Write = 0x0009,
    Lock = 0x000A,
    Ioctl = 0x000B,
    Cancel = 0x000C,
    Echo = 0x000D,
    QueryDirectory = 0x000E,
    ChangeNotify = 0x000F,
    QueryInfo = 0x0010,
    SetInfo = 0x0011,
    OplockBreak = 0x0012,
}

/// <summary>SMB2/3 dialect revisions (MS-SMB2 2.2.3).</summary>
public enum Smb2Dialect : ushort
{
    Smb202 = 0x0202,
    Smb210 = 0x0210,
    Smb300 = 0x0300,
    Smb302 = 0x0302,
    Smb311 = 0x0311,
}

/// <summary>SMB2 negotiate security mode (MS-SMB2 2.2.3).</summary>
[Flags]
public enum Smb2SecurityMode : ushort
{
    SigningEnabled = 0x0001,
    SigningRequired = 0x0002,
}

/// <summary>SMB2 global capability flags (MS-SMB2 2.2.3).</summary>
[Flags]
public enum Smb2Capabilities : uint
{
    None = 0x00000000,
    Dfs = 0x00000001,
    Leasing = 0x00000002,
    LargeMtu = 0x00000004,
    MultiChannel = 0x00000008,
    PersistentHandles = 0x00000010,
    DirectoryLeasing = 0x00000020,
    Encryption = 0x00000040,
}

/// <summary>SMB2 negotiate context types (MS-SMB2 2.2.3.1).</summary>
public enum Smb2NegotiateContextType : ushort
{
    PreauthIntegrityCapabilities = 0x0001,
    EncryptionCapabilities = 0x0002,
    CompressionCapabilities = 0x0003,
    NetnameNegotiateContextId = 0x0005,
    SigningCapabilities = 0x0008,
}

/// <summary>Preauth-integrity hash algorithm ids (MS-SMB2 2.2.3.1.1).</summary>
public static class Smb2HashAlgorithm
{
    public const ushort Sha512 = 0x0001;
}

/// <summary>Compression algorithm ids (MS-SMB2 2.2.3.1.3).</summary>
public static class Smb2CompressionAlgorithm
{
    public const ushort None = 0x0000;
    public const ushort Lznt1 = 0x0001;
    public const ushort Lz77 = 0x0002;
    public const ushort Lz77Huffman = 0x0003;
    public const ushort PatternV1 = 0x0004;

    public static string Describe(ushort algorithm) => algorithm switch
    {
        None => "NONE",
        Lznt1 => "LZNT1",
        Lz77 => "LZ77",
        Lz77Huffman => "LZ77+Huffman",
        PatternV1 => "Pattern_V1",
        _ => $"0x{algorithm:x4}",
    };
}

/// <summary>SMB2_COMPRESSION_CAPABILITIES Flags (MS-SMB2 2.2.3.1.3).</summary>
[Flags]
public enum Smb2CompressionFlags : uint
{
    None = 0x00000000,
    Chained = 0x00000001,
}

/// <summary>Signing algorithm ids (MS-SMB2 2.2.3.1.7).</summary>
public static class Smb2SigningAlgorithm
{
    public const ushort HmacSha256 = 0x0000;
    public const ushort AesCmac = 0x0001;
    public const ushort AesGmac = 0x0002;

    public static string Describe(ushort algorithm) => algorithm switch
    {
        HmacSha256 => "HMAC-SHA256",
        AesCmac => "AES-128-CMAC",
        AesGmac => "AES-128-GMAC",
        _ => $"0x{algorithm:x4}",
    };
}

/// <summary>Encryption cipher ids (MS-SMB2 2.2.3.1.2).</summary>
public static class Smb2Cipher
{
    public const ushort Aes128Ccm = 0x0001;
    public const ushort Aes128Gcm = 0x0002;
    public const ushort Aes256Ccm = 0x0003;
    public const ushort Aes256Gcm = 0x0004;

    public static string Describe(ushort cipher) => cipher switch
    {
        0 => "none",
        Aes128Ccm => "AES-128-CCM",
        Aes128Gcm => "AES-128-GCM",
        Aes256Ccm => "AES-256-CCM",
        Aes256Gcm => "AES-256-GCM",
        _ => $"0x{cipher:x4}",
    };
}

/// <summary>The handful of NTSTATUS codes the session-setup handshake cares about.</summary>
public static class NtStatus
{
    public const uint Success = 0x00000000;
    public const uint Pending = 0x00000103;
    public const uint BufferOverflow = 0x80000005;
    public const uint NoMoreFiles = 0x80000006;
    public const uint MoreProcessingRequired = 0xC0000016;
    public const uint LogonFailure = 0xC000006D;
    public const uint AccessDenied = 0xC0000022;

    public static string Describe(uint status) => status switch
    {
        Success => "STATUS_SUCCESS",
        Pending => "STATUS_PENDING",
        BufferOverflow => "STATUS_BUFFER_OVERFLOW",
        MoreProcessingRequired => "STATUS_MORE_PROCESSING_REQUIRED",
        LogonFailure => "STATUS_LOGON_FAILURE",
        AccessDenied => "STATUS_ACCESS_DENIED",
        _ => $"0x{status:X8}",
    };
}
