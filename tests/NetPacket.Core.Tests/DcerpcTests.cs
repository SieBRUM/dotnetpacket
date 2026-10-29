using NetPacket.Core;
using NetPacket.Protocols.Dcerpc;
using Xunit;

namespace NetPacket.Core.Tests;

public class DcerpcHeaderTests
{
    [Fact]
    public void RoundTrips()
    {
        var header = new DcerpcHeader
        {
            PduType = (byte)DcerpcPduType.Bind,
            FragLength = 72,
            CallId = 1,
        };

        var restored = new DcerpcHeader();
        restored.Unpack(header.Pack());

        Assert.Equal(5, restored.MajorVersion);
        Assert.Equal((byte)DcerpcPduType.Bind, restored.PduType);
        Assert.Equal((ushort)72, restored.FragLength);
        Assert.Equal(1u, restored.CallId);
    }
}

public class DcerpcBindTests
{
    [Fact]
    public void EncodesHeaderInterfaceAndTransferSyntax()
    {
        DcerpcInterface iface = DcerpcInterface.Srvsvc;
        var bind = new DcerpcBind
        {
            InterfaceUuid = iface.Uuid,
            InterfaceVersionMajor = iface.VersionMajor,
            InterfaceVersionMinor = iface.VersionMinor,
            CallId = 1,
        };

        byte[] pdu = bind.Pack();

        Assert.Equal((byte)DcerpcPduType.Bind, pdu[2]);                         // PDU type
        Assert.Equal((ushort)pdu.Length, BitConverter.ToUInt16(pdu, 8));       // FragLength == total length

        // Abstract-syntax UUID: 16-byte header + 16-byte bind preamble (max frags,
        // assoc group, context + transfer-syntax-count headers) = offset 32.
        byte[] uuid = pdu[32..48];
        Assert.Equal(iface.Uuid.ToByteArray(), uuid);

        // NDR transfer syntax UUID follows the interface UUID (16) + version (4).
        byte[] ndr = pdu[52..68];
        Assert.Equal(Dcerpc.NdrTransferSyntax.ToByteArray(), ndr);
    }
}

public class DcerpcBindAckTests
{
    [Fact]
    public void ParsesAcceptance()
    {
        // Build a synthetic BIND_ACK: header + body with sec_addr "\PIPE\srvsvc" and result = acceptance.
        var body = new ByteWriter(ByteOrder.Little);
        body.WriteUInt16(4280); // max xmit
        body.WriteUInt16(4280); // max recv
        body.WriteUInt32(0x1234); // assoc group

        byte[] secAddr = System.Text.Encoding.ASCII.GetBytes("\\PIPE\\srvsvc\0");
        body.WriteUInt16((ushort)secAddr.Length);
        body.WriteBytes(secAddr);

        // pad to 4-byte alignment relative to PDU start (16 header + current body length)
        int pos = 16 + body.Length;
        int pad = (4 - (pos % 4)) % 4;
        for (int i = 0; i < pad; i++)
        {
            body.WriteByte(0);
        }

        body.WriteByte(1); // n_results
        body.WriteByte(0);
        body.WriteUInt16(0);
        body.WriteUInt16((ushort)DcerpcBindAck.ContextResult.Acceptance);
        body.WriteUInt16(0); // reason
        body.WriteBytes(new byte[20]); // transfer syntax

        byte[] bodyBytes = body.ToArray();
        var header = new DcerpcHeader
        {
            PduType = (byte)DcerpcPduType.BindAck,
            FragLength = (ushort)(DcerpcHeader.Size + bodyBytes.Length),
        };

        var pdu = new ByteWriter(ByteOrder.Little);
        pdu.WriteBytes(header.Pack());
        pdu.WriteBytes(bodyBytes);

        DcerpcBindAck ack = DcerpcBindAck.Parse(pdu.ToArray());

        Assert.True(ack.Accepted);
        Assert.Equal("\\PIPE\\srvsvc", ack.SecondaryAddress);
        Assert.Equal(DcerpcBindAck.ContextResult.Acceptance, ack.Result);
    }
}
