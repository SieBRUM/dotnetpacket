using System.Net.Sockets;

namespace DotNetPacket.Protocols.Krb5;

/// <summary>
/// Minimal Kerberos-over-TCP transport (RFC 4120 7.2.2): each message on TCP/88 is prefixed by a
/// 4-byte big-endian length. One request, one reply. Used to send an AS-REQ to a KDC and read the
/// AS-REP / KRB-ERROR back.
/// </summary>
public static class KerberosTcpClient
{
    /// <summary>Sends <paramref name="request"/> to the KDC at <paramref name="host"/>:<paramref name="port"/> and returns the reply.</summary>
    public static byte[] SendReceive(string host, byte[] request, int port = 88, int timeoutMs = 10_000)
    {
        using var tcp = new TcpClient();
        if (!tcp.ConnectAsync(host, port).Wait(timeoutMs))
        {
            throw new TimeoutException($"Timed out connecting to KDC {host}:{port}.");
        }

        using NetworkStream stream = tcp.GetStream();
        stream.ReadTimeout = timeoutMs;
        stream.WriteTimeout = timeoutMs;

        Span<byte> prefix = stackalloc byte[4];
        prefix[0] = (byte)((request.Length >> 24) & 0xFF);
        prefix[1] = (byte)((request.Length >> 16) & 0xFF);
        prefix[2] = (byte)((request.Length >> 8) & 0xFF);
        prefix[3] = (byte)(request.Length & 0xFF);
        stream.Write(prefix);
        stream.Write(request);
        stream.Flush();

        byte[] lenBytes = ReadExact(stream, 4);
        int length = (lenBytes[0] << 24) | (lenBytes[1] << 16) | (lenBytes[2] << 8) | lenBytes[3];
        return ReadExact(stream, length);
    }

    private static byte[] ReadExact(NetworkStream stream, int count)
    {
        var buffer = new byte[count];
        int read = 0;
        while (read < count)
        {
            int n = stream.Read(buffer, read, count - read);
            if (n <= 0)
            {
                throw new EndOfStreamException("KDC closed the connection mid-message.");
            }

            read += n;
        }

        return buffer;
    }
}
