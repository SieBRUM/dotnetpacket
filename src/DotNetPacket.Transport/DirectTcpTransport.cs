using System.Net.Sockets;

namespace DotNetPacket.Transport;

/// <summary>
/// SMB "Direct TCP" transport (MS-SMB2 2.1): each message on TCP/445 is framed by
/// a 4-byte header — one zero byte followed by a 24-bit big-endian length. The
/// same framing carries NetBIOS session messages on TCP/139.
/// </summary>
public sealed class DirectTcpTransport : IDisposable
{
    private const int MaxMessageLength = 0xFFFFFF; // 24-bit length field

    private readonly TcpClient _client = new();
    private NetworkStream? _stream;

    public void Connect(string host, int port = 445, int timeoutMs = 10_000)
    {
        if (!_client.ConnectAsync(host, port).Wait(timeoutMs))
        {
            throw new TimeoutException($"Timed out connecting to {host}:{port}.");
        }

        _stream = _client.GetStream();
    }

    /// <summary>Frames and sends one message (the SMB2 header + body, without the 4-byte prefix).</summary>
    public void SendMessage(ReadOnlySpan<byte> payload)
    {
        NetworkStream stream = EnsureConnected();
        if (payload.Length > MaxMessageLength)
        {
            throw new ArgumentException($"Message of {payload.Length} bytes exceeds the 24-bit length field.");
        }

        Span<byte> header = stackalloc byte[4];
        header[0] = 0x00;
        header[1] = (byte)((payload.Length >> 16) & 0xFF);
        header[2] = (byte)((payload.Length >> 8) & 0xFF);
        header[3] = (byte)(payload.Length & 0xFF);

        stream.Write(header);
        stream.Write(payload);
        stream.Flush();
    }

    /// <summary>Reads one framed message and returns its payload (without the 4-byte prefix).</summary>
    public byte[] ReceiveMessage(int timeoutMs = 10_000)
    {
        NetworkStream stream = EnsureConnected();
        stream.ReadTimeout = timeoutMs;

        byte[] header = ReadExact(4);
        int length = (header[1] << 16) | (header[2] << 8) | header[3];
        return ReadExact(length);
    }

    private byte[] ReadExact(int count)
    {
        NetworkStream stream = EnsureConnected();
        var buffer = new byte[count];
        int read = 0;
        while (read < count)
        {
            int n = stream.Read(buffer, read, count - read);
            if (n <= 0)
            {
                throw new EndOfStreamException("Connection closed by peer before the full message arrived.");
            }

            read += n;
        }

        return buffer;
    }

    private NetworkStream EnsureConnected() =>
        _stream ?? throw new InvalidOperationException("Transport is not connected; call Connect first.");

    public void Dispose()
    {
        _stream?.Dispose();
        _client.Dispose();
    }
}
