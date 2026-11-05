using DotNetPacket.Protocols.Dcerpc;
using Xunit;

namespace DotNetPacket.Core.Tests;

public class LsarPrimaryDomainTests
{
    // Verbatim LsarQueryInformationPolicy (opnum 7) PolicyPrimaryDomainInformation (class 3)
    // response stub captured against a Samba AD DC: union referent + tag 3, an
    // LSAPR_POLICY_PRIMARY_DOM_INFO (DomainName "LAB" RPC_UNICODE_STRING + the primary-domain SID
    // S-1-5-21-3303064197-558132970-3683154743), then NTSTATUS 0. Structurally identical to the
    // account-domain class, so Lsarpc.ParseAccountDomain reads it.
    private const string PrimaryDomainResp =
        "000002000300000006000800040002000800020004000000000000000300000" +
        "04c0041004200000004000000010400000000000515000000" +
        "85c2e0c4ea6e4421377b88db00000000";

    [Fact]
    public void ParseAccountDomain_ReadsPrimaryDomainNameAndSid()
    {
        var info = Lsarpc.ParseAccountDomain(Convert.FromHexString(PrimaryDomainResp));

        Assert.True(info.Success);
        Assert.Equal("LAB", info.Name);
        Assert.Equal("S-1-5-21-3303064197-558132970-3683154743", info.Sid);
    }
}
