using DotNetPacket.Protocols.Dcerpc;
using Xunit;

namespace DotNetPacket.Core.Tests;

public class LsaDnsDomainTests
{
    // Response stub of a real lsarpc LsarQueryInformationPolicy2 (PolicyDnsDomainInformation,
    // level 12) call captured against a Samba AD DC: union referent + tag 12, three
    // RPC_UNICODE_STRING headers (Name/DnsDomain/DnsForest), a 16-byte DomainGuid, an
    // RPC_SID pointer, then the deferred name buffers and the SID. NetBIOS "LAB",
    // DNS/forest "lab.local". The live rpc-lsa example drives the call; this pins the parser.
    private const string DnsDomainStub =
        "000002000c00000006000800040002001200140008000200120014000c000200" +
        "abff8ee8b66f3e47be23db13a2b3f19910000200" +
        "0400000000000000030000004c00410042000000" +
        "0a00000000000000090000006c00610062002e006c006f00630061006c000000" +
        "0a00000000000000090000006c00610062002e006c006f00630061006c000000" +
        "0400000001040000000000051500000085c2e0c4ea6e4421377b88db" +
        "00000000";

    [Fact]
    public void ParseDnsDomain_ReadsNamesGuidAndSid()
    {
        LsaDnsDomain d = Lsarpc.ParseDnsDomain(Convert.FromHexString(DnsDomainStub));

        Assert.Equal(0u, d.Status);
        Assert.Equal("LAB", d.NetbiosName);
        Assert.Equal("lab.local", d.DnsDomainName);
        Assert.Equal("lab.local", d.DnsForestName);
        Assert.Equal("e88effab-6fb6-473e-be23-db13a2b3f199", d.DomainGuid);
        Assert.StartsWith("S-1-5-21-", d.Sid);
    }
}
