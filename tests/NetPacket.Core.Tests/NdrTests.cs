using NetPacket.Protocols.Dcerpc;
using Xunit;

namespace NetPacket.Core.Tests;

public class NdrTests
{
    [Fact]
    public void ConformantVaryingString_RoundTrips()
    {
        var writer = new NdrWriter();
        writer.WriteConformantVaryingString("public");
        byte[] bytes = writer.ToArray();

        // MaxCount / Offset / ActualCount headers (count includes the NUL terminator).
        Assert.Equal(7u, BitConverter.ToUInt32(bytes, 0));
        Assert.Equal(0u, BitConverter.ToUInt32(bytes, 4));
        Assert.Equal(7u, BitConverter.ToUInt32(bytes, 8));

        var reader = new NdrReader(bytes);
        Assert.Equal("public", reader.ReadConformantVaryingString());
    }

    [Fact]
    public void Writer_AlignsUInt32()
    {
        var writer = new NdrWriter();
        writer.WriteUInt16(0x0102); // 2 bytes
        writer.WriteUInt32(0x03040506); // must align to offset 4
        byte[] bytes = writer.ToArray();

        Assert.Equal(8, bytes.Length);                       // 2 + 2 pad + 4
        Assert.Equal(0x03040506u, BitConverter.ToUInt32(bytes, 4));
    }

    [Fact]
    public void Referent_NullVsPresent()
    {
        var writer = new NdrWriter();
        writer.WriteReferent(false);
        writer.WriteReferent(true);
        byte[] bytes = writer.ToArray();

        Assert.Equal(0u, BitConverter.ToUInt32(bytes, 0));
        Assert.Equal(NdrWriter.NonNullReferent, BitConverter.ToUInt32(bytes, 4));
    }
}

public class SrvsvcParseTests
{
    // A synthetic SHARE_INFO_1 level-1 response stub with two shares, built in NDR
    // deferral order, to exercise the NetrShareEnum parser without a live server.
    [Fact]
    public void NetrShareEnum_ParsesContainer()
    {
        var ndr = new NdrWriter();
        ndr.WriteUInt32(1);                 // Level
        ndr.WriteUInt32(1);                 // union switch
        ndr.WriteReferent(true);            // container pointer
        ndr.WriteUInt32(2);                 // EntriesRead
        ndr.WriteReferent(true);            // Buffer pointer
        ndr.WriteUInt32(2);                 // array MaxCount
        // elements: (nameRef, type, remarkRef) x2
        ndr.WriteReferent(true); ndr.WriteUInt32((uint)ShareType.DiskTree); ndr.WriteReferent(true);
        ndr.WriteReferent(true); ndr.WriteUInt32(0x80000003); ndr.WriteReferent(true); // IPC + special
        // deferred strings in element order: name, remark, name, remark
        ndr.WriteConformantVaryingString("public");
        ndr.WriteConformantVaryingString("the public share");
        ndr.WriteConformantVaryingString("IPC$");
        ndr.WriteConformantVaryingString("Remote IPC");
        ndr.WriteUInt32(2);                 // TotalEntries
        ndr.WriteReferent(false);           // ResumeHandle
        ndr.WriteUInt32(0);                 // return value

        IReadOnlyList<ShareInfo1> shares = Srvsvc.ParseResponse(ndr.ToArray());

        Assert.Equal(2, shares.Count);
        Assert.Equal("public", shares[0].Name);
        Assert.Equal(ShareType.DiskTree, shares[0].Type);
        Assert.Equal("the public share", shares[0].Remark);
        Assert.Equal("IPC$", shares[1].Name);
        Assert.Equal(ShareType.Ipc, shares[1].Type);
        Assert.True(shares[1].IsSpecial);
    }
}
