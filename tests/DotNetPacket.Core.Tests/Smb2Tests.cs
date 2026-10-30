using DotNetPacket.Core;
using DotNetPacket.Protocols.Smb;
using Xunit;

namespace DotNetPacket.Core.Tests;

public class Smb2HeaderTests
{
    [Fact]
    public void Packs_To_64_Bytes_With_Signature()
    {
        var header = new Smb2Header { Command = (ushort)Smb2Command.Negotiate };
        byte[] bytes = header.Pack();

        Assert.Equal(64, bytes.Length);
        Assert.Equal(new byte[] { 0xFE, (byte)'S', (byte)'M', (byte)'B' }, bytes[..4]);
        Assert.Equal((ushort)64, BitConverter.ToUInt16(bytes, 4)); // StructureSize
    }

    [Fact]
    public void RoundTrips()
    {
        var original = new Smb2Header
        {
            Command = (ushort)Smb2Command.Negotiate,
            CreditRequest = 1,
            MessageId = 0x1122334455667788,
            TreeId = 0xABCD,
            SessionId = 0xDEADBEEF,
        };

        var restored = new Smb2Header();
        restored.Unpack(original.Pack());

        Assert.Equal(original.Command, restored.Command);
        Assert.Equal(original.CreditRequest, restored.CreditRequest);
        Assert.Equal(original.MessageId, restored.MessageId);
        Assert.Equal(original.TreeId, restored.TreeId);
        Assert.Equal(original.SessionId, restored.SessionId);
    }
}

public class Smb2NegotiateRequestTests
{
    [Fact]
    public void FixedPart_HasExpectedShape()
    {
        var request = new Smb2NegotiateRequest(); // default: 5 dialects incl. 3.1.1
        byte[] body = request.Pack();

        Assert.Equal((ushort)36, BitConverter.ToUInt16(body, 0)); // StructureSize
        Assert.Equal((ushort)5, BitConverter.ToUInt16(body, 2));  // DialectCount
        Assert.Equal((ushort)Smb2SecurityMode.SigningEnabled, BitConverter.ToUInt16(body, 4));

        // Capabilities are non-zero because SMB 3.x is offered.
        Assert.NotEqual(0u, BitConverter.ToUInt32(body, 8));
    }

    [Fact]
    public void Offering311_EmitsTwo_EightByteAligned_Contexts()
    {
        var request = new Smb2NegotiateRequest();
        byte[] body = request.Pack();

        uint contextOffset = BitConverter.ToUInt32(body, 28); // NegotiateContextOffset
        ushort contextCount = BitConverter.ToUInt16(body, 32); // NegotiateContextCount

        Assert.Equal((ushort)2, contextCount);

        // Offset is relative to the SMB2 header; for 5 dialects it lands at 112.
        Assert.Equal(112u, contextOffset);
        Assert.Equal(0u, contextOffset % 8); // 8-byte aligned

        // First context (at bodyOffset = contextOffset - headerSize) is Preauth Integrity.
        int firstContextBodyOffset = (int)contextOffset - Smb2Header.Size;
        Assert.Equal(
            (ushort)Smb2NegotiateContextType.PreauthIntegrityCapabilities,
            BitConverter.ToUInt16(body, firstContextBodyOffset));
    }

    [Fact]
    public void WithoutSmb311_NoContexts()
    {
        var request = new Smb2NegotiateRequest
        {
            Dialects = new List<Smb2Dialect> { Smb2Dialect.Smb202, Smb2Dialect.Smb210 },
        };
        byte[] body = request.Pack();

        Assert.Equal((ushort)0, BitConverter.ToUInt16(body, 32)); // NegotiateContextCount
        Assert.Equal(0u, BitConverter.ToUInt32(body, 28));        // NegotiateContextOffset
        // Fixed 36 + two 2-byte dialects, no contexts.
        Assert.Equal(40, body.Length);
    }

    [Fact]
    public void ClientGuid_Is16Bytes()
    {
        byte[] body = new Smb2NegotiateRequest().Pack();
        byte[] guid = body[12..28];
        Assert.Equal(16, guid.Length);
    }
}

public class Smb2NegotiateResponseTests
{
    [Fact]
    public void Parses_FixedFields_And_SecurityBuffer()
    {
        var writer = new ByteWriter(ByteOrder.Little);
        writer.WriteBytes(new byte[Smb2Header.Size]); // header placeholder (parser skips it)

        writer.WriteUInt16(65);                                    // StructureSize
        writer.WriteUInt16((ushort)Smb2SecurityMode.SigningEnabled);
        writer.WriteUInt16((ushort)Smb2Dialect.Smb311);            // DialectRevision
        writer.WriteUInt16(0);                                     // NegotiateContextCount
        writer.WriteBytes(new byte[16]);                           // ServerGuid
        writer.WriteUInt32((uint)Smb2Capabilities.LargeMtu);       // Capabilities
        writer.WriteUInt32(0x100000);                              // MaxTransactSize
        writer.WriteUInt32(0x100000);                              // MaxReadSize
        writer.WriteUInt32(0x100000);                              // MaxWriteSize
        writer.WriteUInt64(0);                                     // SystemTime
        writer.WriteUInt64(0);                                     // ServerStartTime
        writer.WriteUInt16(128);                                   // SecurityBufferOffset
        writer.WriteUInt16(4);                                     // SecurityBufferLength
        writer.WriteUInt32(0);                                     // NegotiateContextOffset
        writer.WriteBytes(new byte[] { 0x60, 0x01, 0x02, 0x03 });  // security buffer at offset 128

        var response = new Smb2NegotiateResponse();
        response.Unpack(writer.ToArray());

        Assert.Equal(Smb2Dialect.Smb311, response.DialectRevision);
        Assert.Equal(Smb2SecurityMode.SigningEnabled, response.SecurityMode);
        Assert.Equal(Smb2Capabilities.LargeMtu, response.Capabilities);
        Assert.Equal((ushort)4, response.SecurityBufferLength);
        Assert.Equal(new byte[] { 0x60, 0x01, 0x02, 0x03 }, response.SecurityBuffer);
    }
}
