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

    // Walk the negotiate-context list out of a packed request body: returns each
    // context's (type, data) in order and asserts every one starts 8-byte aligned
    // relative to the SMB2 header (MS-SMB2 2.2.3.1).
    private static List<(ushort Type, byte[] Data)> WalkContexts(byte[] body)
    {
        uint contextOffset = BitConverter.ToUInt32(body, 28);
        ushort contextCount = BitConverter.ToUInt16(body, 32);
        var contexts = new List<(ushort, byte[])>();

        int pos = (int)contextOffset - Smb2Header.Size;
        for (int i = 0; i < contextCount; i++)
        {
            // Each context header begins 8-byte aligned from the start of the SMB2 header.
            Assert.Equal(0, (Smb2Header.Size + pos) % 8);
            ushort type = BitConverter.ToUInt16(body, pos);
            ushort dataLen = BitConverter.ToUInt16(body, pos + 2);
            byte[] data = body[(pos + 8)..(pos + 8 + dataLen)];
            contexts.Add((type, data));
            pos += 8 + dataLen;
            pos = (pos + 7) & ~7; // skip trailing pad to the next context
        }

        return contexts;
    }

    [Fact]
    public void Offering311_WithoutServerName_EmitsFourContexts_InWindowsOrder()
    {
        var request = new Smb2NegotiateRequest(); // no ServerName -> netname suppressed
        byte[] body = request.Pack();

        uint contextOffset = BitConverter.ToUInt32(body, 28);
        Assert.Equal(112u, contextOffset);      // relative to header, 8-byte aligned (5 dialects)
        Assert.Equal(0u, contextOffset % 8);
        Assert.Equal((ushort)4, BitConverter.ToUInt16(body, 32)); // NegotiateContextCount

        List<(ushort Type, byte[] Data)> ctx = WalkContexts(body);
        Assert.Equal(
            new[]
            {
                (ushort)Smb2NegotiateContextType.PreauthIntegrityCapabilities,
                (ushort)Smb2NegotiateContextType.EncryptionCapabilities,
                (ushort)Smb2NegotiateContextType.CompressionCapabilities,
                (ushort)Smb2NegotiateContextType.SigningCapabilities,
            },
            ctx.Select(c => c.Type).ToArray());
    }

    [Fact]
    public void Offering311_WithServerName_EmitsFiveContexts_WithNetname()
    {
        var request = new Smb2NegotiateRequest { ServerName = "vm.lab.local" };
        byte[] body = request.Pack();

        Assert.Equal((ushort)5, BitConverter.ToUInt16(body, 32));
        List<(ushort Type, byte[] Data)> ctx = WalkContexts(body);
        Assert.Equal(
            new[]
            {
                (ushort)Smb2NegotiateContextType.PreauthIntegrityCapabilities,
                (ushort)Smb2NegotiateContextType.EncryptionCapabilities,
                (ushort)Smb2NegotiateContextType.CompressionCapabilities,
                (ushort)Smb2NegotiateContextType.NetnameNegotiateContextId,
                (ushort)Smb2NegotiateContextType.SigningCapabilities,
            },
            ctx.Select(c => c.Type).ToArray());

        // Netname body is the dialed host as UTF-16LE, no NUL.
        byte[] netname = ctx.Single(c => c.Type == (ushort)Smb2NegotiateContextType.NetnameNegotiateContextId).Data;
        Assert.Equal("vm.lab.local", System.Text.Encoding.Unicode.GetString(netname));
    }

    [Fact]
    public void CompressionContext_HasWindowsDefaultBody()
    {
        var request = new Smb2NegotiateRequest();
        byte[] body = request.Pack();
        byte[] comp = WalkContexts(body)
            .Single(c => c.Type == (ushort)Smb2NegotiateContextType.CompressionCapabilities).Data;

        // CompressionAlgorithmCount(2) Padding(2)=0 Flags(4)=CHAINED then 4 algorithm ids.
        Assert.Equal((ushort)4, BitConverter.ToUInt16(comp, 0));
        Assert.Equal((ushort)0, BitConverter.ToUInt16(comp, 2));
        Assert.Equal((uint)Smb2CompressionFlags.Chained, BitConverter.ToUInt32(comp, 4));
        Assert.Equal(Smb2CompressionAlgorithm.Lznt1, BitConverter.ToUInt16(comp, 8));
        Assert.Equal(Smb2CompressionAlgorithm.Lz77, BitConverter.ToUInt16(comp, 10));
        Assert.Equal(Smb2CompressionAlgorithm.Lz77Huffman, BitConverter.ToUInt16(comp, 12));
        Assert.Equal(Smb2CompressionAlgorithm.PatternV1, BitConverter.ToUInt16(comp, 14));
        Assert.Equal(8 + 4 * 2, comp.Length);
    }

    [Fact]
    public void SigningContext_OffersGmacThenCmac()
    {
        var request = new Smb2NegotiateRequest();
        byte[] body = request.Pack();
        byte[] sign = WalkContexts(body)
            .Single(c => c.Type == (ushort)Smb2NegotiateContextType.SigningCapabilities).Data;

        Assert.Equal((ushort)2, BitConverter.ToUInt16(sign, 0)); // SigningAlgorithmCount
        Assert.Equal(Smb2SigningAlgorithm.AesGmac, BitConverter.ToUInt16(sign, 2));
        Assert.Equal(Smb2SigningAlgorithm.AesCmac, BitConverter.ToUInt16(sign, 4));
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
