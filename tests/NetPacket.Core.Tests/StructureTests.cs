using NetPacket.Core;
using NetPacket.Protocols.Ntlm;
using NetPacket.Protocols.Smb;
using Xunit;

namespace NetPacket.Core.Tests;

public class SmbHeaderTests
{
    [Fact]
    public void Packs_To_32_Bytes_With_Signature()
    {
        var header = new SmbHeader { Command = 0x72, Mid = 1 };
        byte[] bytes = header.Pack();

        Assert.Equal(32, bytes.Length);
        Assert.Equal(new byte[] { 0xFF, (byte)'S', (byte)'M', (byte)'B' }, bytes[..4]);
        Assert.Equal((byte)0x72, bytes[4]);
    }

    [Fact]
    public void RoundTrips()
    {
        var original = new SmbHeader
        {
            Command = 0x72,
            Status = 0,
            Flags = 0x18,
            Flags2 = 0xC853,
            Tid = 0x1234,
            Uid = 0x5678,
            Mid = 0x9ABC,
        };

        var restored = new SmbHeader();
        restored.Unpack(original.Pack());

        Assert.Equal(original.Command, restored.Command);
        Assert.Equal(original.Flags, restored.Flags);
        Assert.Equal(original.Flags2, restored.Flags2);
        Assert.Equal(original.Tid, restored.Tid);
        Assert.Equal(original.Uid, restored.Uid);
        Assert.Equal(original.Mid, restored.Mid);
    }
}

public class NetBiosSessionHeaderTests
{
    [Fact]
    public void Length_Is_BigEndian()
    {
        var header = new NetBiosSessionHeader { MessageType = 0x00, Flags = 0x00, Length = 0x0102 };
        Assert.Equal(new byte[] { 0x00, 0x00, 0x01, 0x02 }, header.Pack());
    }
}

public class NtlmNegotiateTests
{
    [Fact]
    public void RoundTrips_With_Payload()
    {
        var message = new NtlmNegotiate
        {
            NegotiateFlags = 0xE2088297,
            DomainName = "LAB",
            Workstation = "HOST01",
        };

        var restored = new NtlmNegotiate();
        restored.Unpack(message.Pack());

        Assert.Equal(message.NegotiateFlags, restored.NegotiateFlags);
        Assert.Equal("LAB", restored.DomainName);
        Assert.Equal("HOST01", restored.Workstation);
    }

    [Fact]
    public void Starts_With_Signature_And_Type()
    {
        byte[] bytes = new NtlmNegotiate().Pack();
        Assert.Equal(Ntlm.Signature, bytes[..8]);
        Assert.Equal(new byte[] { 0x01, 0x00, 0x00, 0x00 }, bytes[8..12]); // message type 1, little-endian
    }
}
