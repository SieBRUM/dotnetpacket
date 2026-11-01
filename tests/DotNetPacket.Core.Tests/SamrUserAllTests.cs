using DotNetPacket.Protocols.Dcerpc;
using Xunit;

namespace DotNetPacket.Core.Tests;

public class SamrUserAllTests
{
    // Verbatim SamrQueryInformationUser2 (class 21, SAMPR_USER_ALL_INFORMATION) response stub
    // captured against a Samba AD DC for the built-in Administrator (RID 500): Buffer referent +
    // union tag 21, six OLD_LARGE_INTEGER timestamps, ten RPC_UNICODE_STRING headers, two
    // RPC_SHORT_BLOB + PrivateData + security-descriptor headers, the scalar ids/counters and
    // LogonHours header, then the deferred UserName / AdminComment buffers. Pins the parser.
    private const string UserAllStub =
        "000002001500bdbd00000000000000000000000000000000187f622a8068dd01ffffffffffffff7f183fcc544969dd0118ffbb1f8189dd011a001a00040002000000000008000200000000000c0002000000000010000200000000001400020000000000180002006c006c001c0002000000000020000200000000002400020000000000000000000000000000000000000000000000000000000000000000000000000000000000f40100000102000010000000ffffff08a8000000280002000000000000000000000000000d000000000000000d000000410064006d0069006e006900730074007200610074006f007200abab0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003600000000000000360000004200750069006c0074002d0069006e0020006100630063006f0075006e007400200066006f0072002000610064006d0069006e006900730074006500720069006e0067002000740068006500200063006f006d00700075007400650072002f0064006f006d00610069006e00000000000000000000000000000000000000000000000000ec0400000000000015000000ffffffffffffffffffffffffffffffffffffffffffbfbfbf00000000";

    [Fact]
    public void ParseUserAll_ReadsNamesFlagsAndScalars()
    {
        SamrUserAll d = Samr.ParseUserAll(Convert.FromHexString(UserAllStub));

        Assert.Equal("Administrator", d.UserName);
        Assert.Equal(string.Empty, d.FullName);
        Assert.Equal("Built-in account for administering the computer/domain", d.AdminComment);
        Assert.Equal(500u, d.UserId);
        Assert.Equal(513u, d.PrimaryGroupId);
        Assert.Equal(0x10u, d.UserAccountControl);
        Assert.Equal(0u, d.BadPasswordCount);
        Assert.Equal(0u, d.LogonCount);
        Assert.Contains("NORMAL_ACCOUNT", d.AccountFlagsText);
    }

    [Fact]
    public void FileTimeToUtc_HandlesSentinels()
    {
        Assert.Null(Samr.FileTimeToUtc(0));
        Assert.Null(Samr.FileTimeToUtc(long.MaxValue)); // "never" (0x7FFFFFFFFFFFFFFF)
        Assert.NotNull(Samr.FileTimeToUtc(0x01dd68802a627f18L));
    }
}
