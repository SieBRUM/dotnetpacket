using DotNetPacket.Protocols.Dcerpc;
using Xunit;

namespace DotNetPacket.Core.Tests;

public class SamrDomainGeneralTests
{
    // Verbatim SamrQueryInformationDomain (opnum 8) DomainGeneralInformation (level 2) response
    // stub captured against a Samba AD DC: Buffer referent + union tag 2, a
    // SAMPR_DOMAIN_GENERAL_INFORMATION (ForceLogoff = the "never" sentinel; three
    // RPC_UNICODE_STRING headers for Oem/DomainName/ReplicaSource; DomainModifiedCount=1;
    // ServerState=0; ServerRole=3 (Primary); UAS=0; UserCount=4; GroupCount=12; AliasCount=5),
    // then the deferred name buffers (Oem = "Provisioned by SAMBA 4.19.5-Ubuntu", DomainName =
    // "LAB", ReplicaSource empty), then NTSTATUS 0.
    private const string DomainGeneralResp =
        "0000020002000000000000000000008044004400040002000600060008000200" +
        "000000000c0002000100000000000000000000000300000000000000040000000c00000005000000" +
        "220000000000000022000000500072006f00760069007300690" +
        "06f006e00650064002000620079002000530041004d0042004100200034002e00310039002e00350" +
        "02d005500620075006e00740075" +
        "0003000000000000000300000" +
        "04c0041004200000000000000000000000000000000000000";

    [Fact]
    public void ParseDomainGeneral_ReadsCountsRoleAndNames()
    {
        var info = Samr.ParseDomainGeneral(Convert.FromHexString(DomainGeneralResp));

        Assert.True(info.Success);
        Assert.Equal("LAB", info.DomainName);
        Assert.Equal("Provisioned by SAMBA 4.19.5-Ubuntu", info.OemInformation);
        Assert.Equal(string.Empty, info.ReplicaSourceNodeName);
        Assert.Equal(3u, info.ServerRole);
        Assert.Equal("Primary", info.ServerRoleText);
        Assert.False(info.UasCompatibilityRequired);
        Assert.Equal(4u, info.UserCount);
        Assert.Equal(12u, info.GroupCount);
        Assert.Equal(5u, info.AliasCount);
    }
}
