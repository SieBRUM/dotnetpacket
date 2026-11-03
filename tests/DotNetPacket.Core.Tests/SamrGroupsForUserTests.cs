using DotNetPacket.Protocols.Dcerpc;
using Xunit;

namespace DotNetPacket.Core.Tests;

public class SamrGroupsForUserTests
{
    // Verbatim SamrGetGroupsForUser (opnum 39) response stub captured against a Samba AD DC for
    // the built-in Administrator: SAMPR_GET_GROUPS_BUFFER referent, MembershipCount=5, array
    // referent + conformant MaxCount=5, then five GROUP_MEMBERSHIP {RID, Attributes=0x7} rows
    // (513/512/519/518/520), then NTSTATUS 0. Pins the parser.
    private const string GroupsResp =
        "000002000500000004000200050000000102000007000000000200000700000007020000070000000602000007000000080200000700000000000000";

    [Fact]
    public void ParseGroupsForUser_ReadsMembershipRows()
    {
        var groups = Samr.ParseGroupsForUser(Convert.FromHexString(GroupsResp));

        Assert.Equal(5, groups.Count);
        Assert.Equal(new uint[] { 513, 512, 519, 518, 520 }, groups.Select(g => g.Rid).ToArray());
        Assert.All(groups, g => Assert.Equal(0x7u, g.Attributes));

        Assert.Equal("Domain Users", groups[0].GroupName);
        Assert.Equal("Domain Admins", groups[1].GroupName);
        Assert.Equal("Enterprise Admins", groups[2].GroupName);
        Assert.Contains("ENABLED", groups[0].AttributesText);
        Assert.Contains("MANDATORY", groups[0].AttributesText);
    }

    [Fact]
    public void GroupName_FallsBackToRidForUnknown()
    {
        Assert.Equal("RID 1105", new SamrGroupMembership(1105, 7).GroupName);
    }
}
