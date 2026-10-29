namespace NetPacket.Protocols.Dcerpc;

/// <summary>A WKSTA_INFO_100 record (MS-WKST 2.2.5.1): platform, names, and OS version.</summary>
public sealed record WkstaInfo100(
    uint PlatformId,
    string ComputerName,
    string LanGroup,
    uint VersionMajor,
    uint VersionMinor);

/// <summary>
/// Minimal wkssvc client (MS-WKST). Port of the share of impacket's
/// <c>dcerpc.v5.wkst</c> used for workstation enumeration — a common "who is this
/// host" recon call (computer name, domain/workgroup, OS version). The pipe must
/// already be bound to the wkssvc interface.
/// </summary>
public static class Wkssvc
{
    private const ushort OpnumNetrWkstaGetInfo = 0;

    /// <summary>NetrWkstaGetInfo level 100 (MS-WKST 3.2.4.1): host, domain, and OS version.</summary>
    public static WkstaInfo100 NetrWkstaGetInfo(DcerpcPipe pipe)
    {
        var ndr = new NdrWriter();
        ndr.WriteUniqueString(null); // ServerName [in,string,unique]
        ndr.WriteUInt32(100);        // Level
        byte[] stub = pipe.Call(OpnumNetrWkstaGetInfo, ndr.ToArray());
        return ParseWkstaInfo100(stub);
    }

    /// <summary>Parses a NetrWkstaGetInfo level-100 response stub (exposed for tests and offline analysis).</summary>
    public static WkstaInfo100 ParseWkstaInfo100(byte[] stub)
    {
        var reader = new NdrReader(stub);
        reader.ReadUInt32();                 // union discriminant (Level == 100)
        uint infoReferent = reader.ReadReferent();
        if (infoReferent == 0)
        {
            return new WkstaInfo100(0, string.Empty, string.Empty, 0, 0);
        }

        uint platformId = reader.ReadUInt32();
        uint nameReferent = reader.ReadReferent();
        uint groupReferent = reader.ReadReferent();
        uint versionMajor = reader.ReadUInt32();
        uint versionMinor = reader.ReadUInt32();

        string computerName = nameReferent != 0 ? reader.ReadConformantVaryingString() : string.Empty;
        string lanGroup = groupReferent != 0 ? reader.ReadConformantVaryingString() : string.Empty;

        return new WkstaInfo100(platformId, computerName, lanGroup, versionMajor, versionMinor);
    }
}
