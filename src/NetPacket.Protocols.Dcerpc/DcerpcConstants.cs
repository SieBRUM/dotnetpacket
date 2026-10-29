namespace NetPacket.Protocols.Dcerpc;

/// <summary>DCERPC PDU types (DCE 1.1 / MS-RPCE 2.2.2.3).</summary>
public enum DcerpcPduType : byte
{
    Request = 0,
    Response = 2,
    Fault = 3,
    Bind = 11,
    BindAck = 12,
    BindNak = 13,
    AlterContext = 14,
    AlterContextResp = 15,
    Auth3 = 16,
}

/// <summary>DCERPC PFC (fragment) flags (DCE 1.1).</summary>
[Flags]
public enum DcerpcPfcFlags : byte
{
    FirstFragment = 0x01,
    LastFragment = 0x02,
    PendingCancel = 0x04,
    Concurrent = 0x08,
    DidNotExecute = 0x20,
    Maybe = 0x40,
    ObjectUuid = 0x80,
}

/// <summary>Well-known DCERPC identifiers and defaults.</summary>
public static class Dcerpc
{
    /// <summary>Little-endian / ASCII / IEEE data representation (MS-RPCE 2.2.2.3).</summary>
    public static readonly byte[] LittleEndianDataRepresentation = { 0x10, 0x00, 0x00, 0x00 };

    public const ushort DefaultMaxFrag = 4280;

    /// <summary>The NDR (version 2.0) transfer syntax UUID.</summary>
    public static readonly Guid NdrTransferSyntax = new("8a885d04-1ceb-11c9-9fe8-08002b104860");
    public const ushort NdrVersionMajor = 2;
    public const ushort NdrVersionMinor = 0;
}

/// <summary>A DCERPC interface: its abstract-syntax UUID, version, and default named pipe.</summary>
public sealed record DcerpcInterface(string Name, Guid Uuid, ushort VersionMajor, ushort VersionMinor, string Pipe)
{
    // A few read-only / enumeration interfaces available on a typical server.
    public static readonly DcerpcInterface Srvsvc =
        new("srvsvc", new Guid("4b324fc8-1670-01d3-1278-5a47bf6ee188"), 3, 0, "srvsvc");

    public static readonly DcerpcInterface Wkssvc =
        new("wkssvc", new Guid("6bffd098-a112-3610-9833-46c3f87e345a"), 1, 0, "wkssvc");

    public static readonly DcerpcInterface Lsarpc =
        new("lsarpc", new Guid("12345778-1234-abcd-ef00-0123456789ab"), 0, 0, "lsarpc");

    public static readonly DcerpcInterface Samr =
        new("samr", new Guid("12345778-1234-abcd-ef00-0123456789ac"), 1, 0, "samr");

    public static readonly DcerpcInterface Svcctl =
        new("svcctl", new Guid("367abb81-9844-35f1-ad32-98f038001003"), 2, 0, "svcctl");

    public static readonly IReadOnlyList<DcerpcInterface> WellKnown =
        new[] { Srvsvc, Wkssvc, Lsarpc, Samr, Svcctl };

    public static DcerpcInterface? ByName(string name)
    {
        foreach (DcerpcInterface iface in WellKnown)
        {
            if (string.Equals(iface.Name, name, StringComparison.OrdinalIgnoreCase))
            {
                return iface;
            }
        }

        return null;
    }
}
