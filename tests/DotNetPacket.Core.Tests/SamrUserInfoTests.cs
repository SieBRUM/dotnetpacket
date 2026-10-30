using DotNetPacket.Protocols.Dcerpc;
using Xunit;

namespace DotNetPacket.Core.Tests;

public class SamrUserInfoTests
{
    // Synthetic SAMPR_USER_GENERAL_INFORMATION (level 1): UserName set, other
    // strings empty-but-allocated, PrimaryGroupId 513 — mirrors Samba's labuser.
    // Real bytes validated by the rpc-enumusers example.
    [Fact]
    public void ParseUserGeneral_DecodesFields()
    {
        var ndr = new NdrWriter();
        ndr.WriteReferent(true);          // Buffer pointer
        ndr.WriteUInt32(1);               // union discriminant (level 1)

        ndr.WriteUnicodeStringHeader("labuser"); // UserName
        ndr.WriteUInt16(0); ndr.WriteUInt16(0); ndr.WriteReferent(true); // FullName (empty, allocated)
        ndr.WriteUInt32(513);             // PrimaryGroupId
        ndr.WriteUInt16(0); ndr.WriteUInt16(0); ndr.WriteReferent(true); // AdminComment (empty)
        ndr.WriteUInt16(0); ndr.WriteUInt16(0); ndr.WriteReferent(true); // UserComment (empty)

        ndr.WriteUnicodeStringBuffer("labuser"); // UserName buffer
        ndr.WriteUnicodeStringBuffer(string.Empty); // FullName
        ndr.WriteUnicodeStringBuffer(string.Empty); // AdminComment
        ndr.WriteUnicodeStringBuffer(string.Empty); // UserComment

        ndr.WriteUInt32(0);               // return status

        SamrUserGeneral info = Samr.ParseUserGeneral(ndr.ToArray());

        Assert.Equal("labuser", info.UserName);
        Assert.Equal(513u, info.PrimaryGroupId);
        Assert.Equal(string.Empty, info.FullName);
        Assert.Equal(string.Empty, info.AdminComment);
    }
}
