namespace NetPacket.Protocols.Smb;

/// <summary>SMB2 CREATE requested oplock level (MS-SMB2 2.2.13).</summary>
public enum Smb2OplockLevel : byte
{
    None = 0x00,
    II = 0x01,
    Exclusive = 0x08,
    Batch = 0x09,
    Lease = 0xFF,
}

/// <summary>SMB2 CREATE impersonation level (MS-SMB2 2.2.13).</summary>
public enum Smb2ImpersonationLevel : uint
{
    Anonymous = 0x00000000,
    Identification = 0x00000001,
    Impersonation = 0x00000002,
    Delegate = 0x00000003,
}

/// <summary>SMB2 CREATE share access (MS-SMB2 2.2.13).</summary>
[Flags]
public enum Smb2ShareAccess : uint
{
    None = 0x00000000,
    Read = 0x00000001,
    Write = 0x00000002,
    Delete = 0x00000004,
    All = Read | Write | Delete,
}

/// <summary>SMB2 CREATE disposition (MS-SMB2 2.2.13).</summary>
public enum Smb2CreateDisposition : uint
{
    Supersede = 0x00000000,
    Open = 0x00000001,
    Create = 0x00000002,
    OpenIf = 0x00000003,
    Overwrite = 0x00000004,
    OverwriteIf = 0x00000005,
}

/// <summary>SMB2 CREATE options (MS-SMB2 2.2.13).</summary>
[Flags]
public enum Smb2CreateOptions : uint
{
    None = 0x00000000,
    DirectoryFile = 0x00000001,
    WriteThrough = 0x00000002,
    SequentialOnly = 0x00000004,
    NoIntermediateBuffering = 0x00000008,
    SynchronousIoAlert = 0x00000010,
    SynchronousIoNonAlert = 0x00000020,
    NonDirectoryFile = 0x00000040,
    CompleteIfOplocked = 0x00000100,
    NoEaKnowledge = 0x00000200,
    RandomAccess = 0x00000800,
    DeleteOnClose = 0x00001000,
    OpenByFileId = 0x00002000,
    OpenForBackupIntent = 0x00004000,
    NoCompression = 0x00008000,
    OpenReparsePoint = 0x00200000,
    OpenNoRecall = 0x00400000,
}

/// <summary>File access mask bits (MS-DTYP 2.4.3 / MS-SMB2 2.2.13.1).</summary>
[Flags]
public enum Smb2AccessMask : uint
{
    FileReadData = 0x00000001,
    FileWriteData = 0x00000002,
    FileAppendData = 0x00000004,
    FileReadEa = 0x00000008,
    FileWriteEa = 0x00000010,
    FileExecute = 0x00000020,
    FileDeleteChild = 0x00000040,
    FileReadAttributes = 0x00000080,
    FileWriteAttributes = 0x00000100,
    Delete = 0x00010000,
    ReadControl = 0x00020000,
    WriteDac = 0x00040000,
    WriteOwner = 0x00080000,
    Synchronize = 0x00100000,
    AccessSystemSecurity = 0x01000000,
    MaximumAllowed = 0x02000000,
    GenericAll = 0x10000000,
    GenericExecute = 0x20000000,
    GenericWrite = 0x40000000,
    GenericRead = 0x80000000,

    /// <summary>FILE_GENERIC_READ expanded (what a real client sends to read a file).</summary>
    FileGenericRead = FileReadData | FileReadEa | FileReadAttributes | ReadControl | Synchronize,
}

/// <summary>File attributes (MS-FSCC 2.6).</summary>
[Flags]
public enum Smb2FileAttributes : uint
{
    None = 0x00000000,
    ReadOnly = 0x00000001,
    Hidden = 0x00000002,
    System = 0x00000004,
    Directory = 0x00000010,
    Archive = 0x00000020,
    Normal = 0x00000080,
    Temporary = 0x00000100,
    SparseFile = 0x00000200,
    ReparsePoint = 0x00000400,
    Compressed = 0x00000800,
    Offline = 0x00001000,
    NotContentIndexed = 0x00002000,
    Encrypted = 0x00004000,
}
