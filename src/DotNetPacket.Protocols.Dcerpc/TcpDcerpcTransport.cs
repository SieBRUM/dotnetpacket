using System.Net.Sockets;
using DotNetPacket.Core;

namespace DotNetPacket.Protocols.Dcerpc;

/// <summary>
/// DCERPC directly over TCP (ncacn_ip_tcp): PDUs are written to and read from the
/// socket with no SMB layer, each response framed by the <c>frag_length</c> field of
/// the 16-byte common header. This is the transport used to reach the endpoint
/// mapper on port 135 and interfaces bound to dynamic TCP ports. Port of impacket's
/// <c>dcerpc.v5.transport.TCPTransport</c>.
/// </summary>
public sealed class TcpDcerpcTransport : IDcerpcTransport
{
    private readonly TcpClient _client;
    private readonly NetworkStream _stream;

    public TcpDcerpcTransport(string host, int port = 135)
    {
        _client = new TcpClient();
        _client.Connect(host, port);
        _client.NoDelay = true;
        _stream = _client.GetStream();
    }

    public byte[] Transceive(byte[] pdu)
    {
        Send(pdu);
        return ReadPdu();
    }

    public void Send(byte[] pdu) => _stream.Write(pdu, 0, pdu.Length);

    public void Close()
    {
        _stream.Dispose();
        _client.Dispose();
    }

    /// <summary>Reads exactly one PDU: the 16-byte header, then the rest per frag_length.</summary>
    private byte[] ReadPdu()
    {
        byte[] header = ReadExactly(DcerpcHeader.Size);

        // frag_length is a little-endian ushort at offset 8 of the common header.
        var reader = new ByteReader(header, ByteOrder.Little);
        var parsed = new DcerpcHeader();
        parsed.Unpack(reader);

        int remaining = parsed.FragLength - DcerpcHeader.Size;
        if (remaining < 0)
        {
            throw new InvalidDataException($"DCERPC frag_length {parsed.FragLength} is smaller than the header.");
        }

        byte[] body = ReadExactly(remaining);
        var pdu = new byte[header.Length + body.Length];
        Array.Copy(header, 0, pdu, 0, header.Length);
        Array.Copy(body, 0, pdu, header.Length, body.Length);
        return pdu;
    }

    private byte[] ReadExactly(int count)
    {
        var buffer = new byte[count];
        int offset = 0;
        while (offset < count)
        {
            int read = _stream.Read(buffer, offset, count - offset);
            if (read <= 0)
            {
                throw new IOException("DCERPC TCP connection closed mid-PDU.");
            }

            offset += read;
        }

        return buffer;
    }
}
