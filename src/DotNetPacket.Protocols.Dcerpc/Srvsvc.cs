namespace DotNetPacket.Protocols.Dcerpc;

/// <summary>SMB share types (MS-SRVS 2.2.2.4, STYPE_*). The high byte carries special/temporary flags.</summary>
public enum ShareType : uint
{
    DiskTree = 0x00000000,
    PrintQueue = 0x00000001,
    Device = 0x00000002,
    Ipc = 0x00000003,
}

/// <summary>A SHARE_INFO_1 entry (MS-SRVS 2.2.4.23): name, type, and remark.</summary>
public sealed record ShareInfo1(string Name, uint RawType, string Remark)
{
    public ShareType Type => (ShareType)(RawType & 0x0FFFFFFF);

    public bool IsSpecial => (RawType & 0x80000000) != 0;
}

/// <summary>A SERVER_INFO_101 record (MS-SRVS 2.2.4.41): platform, name, OS version, server type.</summary>
public sealed record ServerInfo101(
    uint PlatformId,
    string Name,
    uint VersionMajor,
    uint VersionMinor,
    uint Type,
    string Comment);

/// <summary>
/// SERVER_INFO_102 (MS-SRVS 2.2.4.41) — the level-101 fields plus the server's tunable
/// announce/session settings: concurrent user limit, auto-disconnect timeout, hidden flag,
/// announce interval + delta, client-license count, and the user directory path.
/// </summary>
public sealed record ServerInfo102(
    uint PlatformId,
    string Name,
    uint VersionMajor,
    uint VersionMinor,
    uint Type,
    string Comment,
    uint Users,
    uint Disc,
    uint Hidden,
    uint Announce,
    uint AnnDelta,
    uint Licenses,
    string UserPath);

/// <summary>
/// Minimal srvsvc client (MS-SRVS). Port of the parts of impacket's
/// <c>dcerpc.v5.srvs</c> needed for recon — share enumeration and server info.
/// The pipe must already be bound to the srvsvc interface.
/// </summary>
public static class Srvsvc
{
    private const ushort OpnumNetrShareEnum = 15;
    private const ushort OpnumNetrServerGetInfo = 21;

    /// <summary>NetrServerGetInfo level 101 (MS-SRVS 3.1.4.17): server name, OS version, and type.</summary>
    public static ServerInfo101 NetrServerGetInfo(DcerpcPipe pipe)
    {
        var ndr = new NdrWriter();
        ndr.WriteUniqueString(null); // ServerName [in,string,unique]
        ndr.WriteUInt32(101);        // Level
        byte[] stub = pipe.Call(OpnumNetrServerGetInfo, ndr.ToArray());
        return ParseServerInfo101(stub);
    }

    /// <summary>Parses a NetrServerGetInfo level-101 response stub (exposed for tests and offline analysis).</summary>
    public static ServerInfo101 ParseServerInfo101(byte[] stub)
    {
        var reader = new NdrReader(stub);
        reader.ReadUInt32();                 // union discriminant (Level == 101)
        uint infoReferent = reader.ReadReferent();
        if (infoReferent == 0)
        {
            return new ServerInfo101(0, string.Empty, 0, 0, 0, string.Empty);
        }

        uint platformId = reader.ReadUInt32();
        uint nameReferent = reader.ReadReferent();
        uint versionMajor = reader.ReadUInt32();
        uint versionMinor = reader.ReadUInt32();
        uint type = reader.ReadUInt32();
        uint commentReferent = reader.ReadReferent();

        string name = nameReferent != 0 ? reader.ReadConformantVaryingString() : string.Empty;
        string comment = commentReferent != 0 ? reader.ReadConformantVaryingString() : string.Empty;

        return new ServerInfo101(platformId, name, versionMajor, versionMinor, type, comment);
    }

    /// <summary>
    /// NetrServerGetInfo level 102 (MS-SRVS 3.1.4.17): the level-101 fields plus the server's
    /// announce/session tunables (user limit, auto-disconnect, hidden flag, announce interval,
    /// license count, user path). Port of impacket's <c>hNetrServerGetInfo</c> at level 102.
    /// </summary>
    public static ServerInfo102 NetrServerGetInfo102(DcerpcPipe pipe)
    {
        var ndr = new NdrWriter();
        ndr.WriteUniqueString(null); // ServerName [in,string,unique]
        ndr.WriteUInt32(102);        // Level
        byte[] stub = pipe.Call(OpnumNetrServerGetInfo, ndr.ToArray());
        return ParseServerInfo102(stub);
    }

    /// <summary>
    /// Parses a NetrServerGetInfo level-102 response stub: union tag (102) + a SERVER_INFO_102
    /// referent (platform id; name referent; version major/minor; type; comment referent; the six
    /// ULONG tunables; userpath referent), then the deferred name/comment/userpath buffers in
    /// field order. Exposed for tests / offline analysis.
    /// </summary>
    public static ServerInfo102 ParseServerInfo102(byte[] stub)
    {
        var reader = new NdrReader(stub);
        reader.ReadUInt32();                 // union discriminant (Level == 102)
        uint infoReferent = reader.ReadReferent();
        if (infoReferent == 0)
        {
            return new ServerInfo102(0, string.Empty, 0, 0, 0, string.Empty, 0, 0, 0, 0, 0, 0, string.Empty);
        }

        uint platformId = reader.ReadUInt32();
        uint nameReferent = reader.ReadReferent();
        uint versionMajor = reader.ReadUInt32();
        uint versionMinor = reader.ReadUInt32();
        uint type = reader.ReadUInt32();
        uint commentReferent = reader.ReadReferent();
        uint users = reader.ReadUInt32();
        uint disc = reader.ReadUInt32();
        uint hidden = reader.ReadUInt32();
        uint announce = reader.ReadUInt32();
        uint annDelta = reader.ReadUInt32();
        uint licenses = reader.ReadUInt32();
        uint userPathReferent = reader.ReadReferent();

        // Deferred conformant-varying buffers, in field order.
        string name = nameReferent != 0 ? reader.ReadConformantVaryingString() : string.Empty;
        string comment = commentReferent != 0 ? reader.ReadConformantVaryingString() : string.Empty;
        string userPath = userPathReferent != 0 ? reader.ReadConformantVaryingString() : string.Empty;

        return new ServerInfo102(
            platformId, name, versionMajor, versionMinor, type, comment,
            users, disc, hidden, announce, annDelta, licenses, userPath);
    }

    /// <summary>
    /// NetrShareEnum level 1 (MS-SRVS 3.1.4.8): enumerate the server's shares with
    /// name, type, and remark.
    /// </summary>
    public static IReadOnlyList<ShareInfo1> NetrShareEnum(DcerpcPipe pipe)
    {
        byte[] responseStub = pipe.Call(OpnumNetrShareEnum, BuildRequest());
        return ParseResponse(responseStub);
    }

    private static byte[] BuildRequest()
    {
        var ndr = new NdrWriter();
        ndr.WriteReferent(present: false);                 // ServerName (NULL => local)
        ndr.WriteUInt32(1);                                // InfoStruct.Level
        ndr.WriteUInt32(1);                                // SHARE_ENUM_UNION switch
        ndr.WriteReferent(present: true);                  // Level1 container pointer
        ndr.WriteUInt32(0);                                // container.EntriesRead
        ndr.WriteReferent(present: false);                 // container.Buffer (NULL)
        ndr.WriteUInt32(0xFFFFFFFF);                       // PreferedMaximumLength
        ndr.WriteReferent(present: false);                 // ResumeHandle (NULL)
        return ndr.ToArray();
    }

    /// <summary>Parses a NetrShareEnum level-1 response stub (exposed for tests and offline analysis).</summary>
    public static IReadOnlyList<ShareInfo1> ParseResponse(byte[] stub)
    {
        var reader = new NdrReader(stub);

        reader.ReadUInt32();                 // InfoStruct.Level
        reader.ReadUInt32();                 // SHARE_ENUM_UNION switch
        reader.ReadReferent();               // Level1 container pointer
        uint entriesRead = reader.ReadUInt32();
        uint bufferReferent = reader.ReadReferent();

        var shares = new List<ShareInfo1>();
        if (bufferReferent == 0 || entriesRead == 0)
        {
            return shares;
        }

        reader.ReadUInt32(); // conformant array MaxCount

        // First pass: the array elements (embedded pointers are referents only here).
        var nameRefs = new uint[entriesRead];
        var types = new uint[entriesRead];
        var remarkRefs = new uint[entriesRead];
        for (int i = 0; i < entriesRead; i++)
        {
            nameRefs[i] = reader.ReadReferent();
            types[i] = reader.ReadUInt32();
            remarkRefs[i] = reader.ReadReferent();
        }

        // Second pass: the deferred strings, in element order (name then remark).
        for (int i = 0; i < entriesRead; i++)
        {
            string name = nameRefs[i] != 0 ? reader.ReadConformantVaryingString() : string.Empty;
            string remark = remarkRefs[i] != 0 ? reader.ReadConformantVaryingString() : string.Empty;
            shares.Add(new ShareInfo1(name, types[i], remark));
        }

        return shares;
    }
}
