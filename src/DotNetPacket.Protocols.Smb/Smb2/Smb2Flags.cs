namespace DotNetPacket.Protocols.Smb;

/// <summary>SMB2 packet header flags (MS-SMB2 2.2.1.2).</summary>
[Flags]
public enum Smb2HeaderFlags : uint
{
    None = 0x00000000,
    ServerToRedir = 0x00000001,   // response
    AsyncCommand = 0x00000002,
    RelatedOperations = 0x00000004,
    Signed = 0x00000008,
    PriorityMask = 0x00000070,
    DfsOperations = 0x10000000,
    ReplayOperation = 0x20000000,
}

/// <summary>SESSION_SETUP response session flags (MS-SMB2 2.2.6).</summary>
[Flags]
public enum Smb2SessionFlags : ushort
{
    None = 0x0000,
    IsGuest = 0x0001,
    IsNull = 0x0002,
    EncryptData = 0x0004,
}

/// <summary>SESSION_SETUP request flags (MS-SMB2 2.2.5).</summary>
[Flags]
public enum Smb2SessionSetupFlags : byte
{
    None = 0x00,
    Binding = 0x01,
}

/// <summary>TREE_CONNECT response share type (MS-SMB2 2.2.10).</summary>
public enum Smb2ShareType : byte
{
    Disk = 0x01,
    Pipe = 0x02,
    Print = 0x03,
}

/// <summary>TREE_CONNECT response share flags (MS-SMB2 2.2.10).</summary>
[Flags]
public enum Smb2ShareFlags : uint
{
    ManualCaching = 0x00000000,
    AutoCaching = 0x00000010,
    VdoCaching = 0x00000020,
    NoCaching = 0x00000030,
    Dfs = 0x00000001,
    DfsRoot = 0x00000002,
    RestrictExclusiveOpens = 0x00000100,
    ForceSharedDelete = 0x00000200,
    AllowNamespaceCaching = 0x00000400,
    AccessBasedDirectoryEnum = 0x00000800,
    ForceLevel2Oplock = 0x00001000,
    EnableHashV1 = 0x00002000,
    EnableHashV2 = 0x00004000,
    EncryptData = 0x00008000,
    IdentityRemoting = 0x00040000,
    Compress = 0x00100000,
}

/// <summary>TREE_CONNECT response share capabilities (MS-SMB2 2.2.10).</summary>
[Flags]
public enum Smb2ShareCapabilities : uint
{
    None = 0x00000000,
    Dfs = 0x00000008,
    ContinuousAvailability = 0x00000010,
    Scaleout = 0x00000020,
    Cluster = 0x00000040,
    Asymmetric = 0x00000080,
    RedirectToOwner = 0x00000100,
}
