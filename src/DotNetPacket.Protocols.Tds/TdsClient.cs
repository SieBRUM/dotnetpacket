using System.Net.Sockets;
using DotNetPacket.Core;
using DotNetPacket.Core.Diagnostics;

namespace DotNetPacket.Protocols.Tds;

/// <summary>
/// A minimal TDS (MS-TDS) client over TCP — the pre-login path only. Port of the framing in
/// impacket's <c>tds.MSSQL</c>: each message is one or more packets, each prefixed by an 8-byte
/// header {Type, Status, Length(BE), SPID(BE), PacketID, Window}. Used by checkMSSQLStatus to read
/// a SQL Server's encryption posture.
/// </summary>
public sealed class TdsClient : IDisposable
{
    private readonly TcpClient _tcp;
    private readonly NetworkStream _stream;

    private TdsClient(TcpClient tcp)
    {
        _tcp = tcp;
        _stream = tcp.GetStream();
    }

    public static TdsClient Connect(string host, int port = 1433, int timeoutMs = 10_000)
    {
        TcpClient tcp = DotNetPacket.Core.Net.ProxyConnector.Connect(host, port, timeoutMs);
        PacketTrace.Event("tds", $"connected to {host}:{port}");
        return new TdsClient(tcp);
    }

    /// <summary>Sends a PRELOGIN and returns the parsed response (encryption posture + version).</summary>
    public TdsPreLoginResponse PreLogin(uint threadId)
    {
        SendPacket(TdsConstants.PreLogin, TdsPreLogin.Build(TdsConstants.EncryptOff, threadId));
        return TdsPreLogin.Parse(ReceivePacket());
    }

    /// <summary>Frames and sends one TDS packet (single-packet message, EOM set).</summary>
    public void SendPacket(byte type, byte[] payload)
    {
        var w = new ByteWriter(ByteOrder.Big);
        w.WriteByte(type);
        w.WriteByte(TdsConstants.StatusEom);
        w.WriteUInt16((ushort)(payload.Length + 8)); // Length incl. the 8-byte header
        w.WriteUInt16(0);                             // SPID
        w.WriteByte(0);                               // PacketID
        w.WriteByte(0);                               // Window
        w.WriteBytes(payload);
        byte[] framed = w.ToArray();
        _stream.Write(framed);
        _stream.Flush();
        PacketTrace.Sent("tds", framed);
    }

    /// <summary>Reads one TDS packet and returns its payload (the 8-byte header stripped).</summary>
    public byte[] ReceivePacket(int timeoutMs = 10_000)
    {
        _stream.ReadTimeout = timeoutMs;
        byte[] header = ReadExact(8);
        int length = (header[2] << 8) | header[3]; // big-endian total length incl. header
        int payloadLength = length - 8;
        byte[] payload = payloadLength <= 0 ? Array.Empty<byte>() : ReadExact(payloadLength);
        PacketTrace.Received("tds", payload);
        return payload;
    }

    private byte[] ReadExact(int count)
    {
        var buffer = new byte[count];
        int read = 0;
        while (read < count)
        {
            int n = _stream.Read(buffer, read, count - read);
            if (n <= 0)
            {
                throw new EndOfStreamException("TDS connection closed mid-packet.");
            }

            read += n;
        }

        return buffer;
    }

    public void Dispose()
    {
        _stream.Dispose();
        _tcp.Dispose();
    }
}
