using NetPacket.Protocols.Dcerpc;
using Xunit;

namespace NetPacket.Core.Tests;

public class HostInfoParseTests
{
    // These exercise the parsers' NDR shape (level union -> struct with deferred
    // string pointers) using synthetic stubs; live values are validated by the
    // rpc-hostinfo example against a server.

    [Fact]
    public void Wkssvc_NetrWkstaGetInfo_Parses()
    {
        var ndr = new NdrWriter();
        ndr.WriteUInt32(100);         // union discriminant
        ndr.WriteReferent(true);      // info pointer
        ndr.WriteUInt32(500);         // platform_id
        ndr.WriteReferent(true);      // computername ptr
        ndr.WriteReferent(true);      // langroup ptr
        ndr.WriteUInt32(10);          // ver_major
        ndr.WriteUInt32(0);           // ver_minor
        ndr.WriteConformantVaryingString("LABSRV");
        ndr.WriteConformantVaryingString("WORKGROUP");
        ndr.WriteUInt32(0);           // return code

        WkstaInfo100 info = Wkssvc.ParseWkstaInfo100(ndr.ToArray());

        Assert.Equal("LABSRV", info.ComputerName);
        Assert.Equal("WORKGROUP", info.LanGroup);
        Assert.Equal(10u, info.VersionMajor);
        Assert.Equal(500u, info.PlatformId);
    }

    [Fact]
    public void Srvsvc_NetrServerGetInfo_Parses()
    {
        var ndr = new NdrWriter();
        ndr.WriteUInt32(101);         // union discriminant
        ndr.WriteReferent(true);      // info pointer
        ndr.WriteUInt32(500);         // platform_id
        ndr.WriteReferent(true);      // name ptr
        ndr.WriteUInt32(6);           // ver_major
        ndr.WriteUInt32(1);           // ver_minor
        ndr.WriteUInt32(0x00000003);  // type
        ndr.WriteReferent(true);      // comment ptr
        ndr.WriteConformantVaryingString("LABSRV");
        ndr.WriteConformantVaryingString("NetPacket Lab");
        ndr.WriteUInt32(0);           // return code

        ServerInfo101 info = Srvsvc.ParseServerInfo101(ndr.ToArray());

        Assert.Equal("LABSRV", info.Name);
        Assert.Equal(6u, info.VersionMajor);
        Assert.Equal(1u, info.VersionMinor);
        Assert.Equal("NetPacket Lab", info.Comment);
        Assert.Equal(0x00000003u, info.Type);
    }
}
