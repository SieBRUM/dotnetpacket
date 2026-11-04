using DotNetPacket.Protocols.Dcerpc;
using Xunit;

namespace DotNetPacket.Core.Tests;

public class SamrAliasMembersTests
{
    // Verbatim SamrGetMembersInAlias (opnum 33) response stub captured against a Samba AD DC for
    // the BUILTIN\Administrators alias (RID 544): a SAMPR_PSID_ARRAY_OUT with Count=3 and a
    // referenced conformant SAMPR_SID_INFORMATION array (three SID-pointer referents
    // 0x00020004/8/c), then the three deferred RPC_SIDs — Domain Admins (…-512), Enterprise
    // Admins (…-519), Administrator (…-500) in the LAB domain — then NTSTATUS 0.
    private const string AliasMembersResp =
        "03000000000002000300000004000200080002000c000200" +
        "0500000001050000000000051500000085c2e0c4ea6e4421377b88db00020000" +
        "0500000001050000000000051500000085c2e0c4ea6e4421377b88db07020000" +
        "0500000001050000000000051500000085c2e0c4ea6e4421377b88dbf4010000" +
        "00000000";

    [Fact]
    public void ParseMembersInAlias_ReadsEveryMemberSidAndStatus()
    {
        (var members, uint status) = Samr.ParseMembersInAlias(Convert.FromHexString(AliasMembersResp));

        Assert.Equal(0u, status);
        Assert.Equal(3, members.Count);

        Assert.Equal("S-1-5-21-3303064197-558132970-3683154743-512", members[0].ToString());
        Assert.Equal("S-1-5-21-3303064197-558132970-3683154743-519", members[1].ToString());
        Assert.Equal("S-1-5-21-3303064197-558132970-3683154743-500", members[2].ToString());
    }
}
