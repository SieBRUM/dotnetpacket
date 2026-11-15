using System.Net;
using System.Net.Sockets;
using System.Text;

namespace DotNetPacket.Core.Net;

/// <summary>
/// Opens outbound TCP connections, optionally tunnelling them through a SOCKS or HTTP proxy. This is
/// the single choke point every DotNetPacket transport (SMB, LDAP, Kerberos-over-TCP, DCERPC-over-TCP,
/// TDS) connects through, so a <c>-proxy</c> option routes the whole tool — the built-in equivalent of
/// running impacket under <c>proxychains</c>.
///
/// <para>When a proxy is set, the <b>target hostname is handed to the proxy</b> (SOCKS5 domain / SOCKS4a
/// name / HTTP <c>CONNECT host:port</c>) so it resolves on the far side of a pivot — the behaviour AD
/// tooling needs through a SOCKS pivot. With no proxy set (the default), and in a transparent redirector's
/// kernel-capture mode, connections are made straight to the hostname via the system resolver, which the
/// redirector intercepts; no proxy option is required there.</para>
/// </summary>
public static class ProxyConnector
{
    /// <summary>
    /// The process-wide proxy every transport connects through. Null means direct connections. Set once
    /// from the parsed <c>-proxy</c> option before any connection is opened.
    /// </summary>
    public static ProxyEndpoint? Default { get; set; }

    /// <summary>
    /// Connects to <paramref name="host"/>:<paramref name="port"/>, through <see cref="Default"/> if one
    /// is set, otherwise directly. Returns a connected <see cref="TcpClient"/> whose stream carries the
    /// application protocol (the proxy handshake, if any, is already complete).
    /// </summary>
    public static TcpClient Connect(string host, int port, int timeoutMs = 10_000)
        => Connect(Default, host, port, timeoutMs);

    /// <summary>Connects through a specific proxy (or directly when <paramref name="proxy"/> is null).</summary>
    public static TcpClient Connect(ProxyEndpoint? proxy, string host, int port, int timeoutMs = 10_000)
    {
        if (proxy is null)
        {
            var direct = new TcpClient();
            if (!direct.ConnectAsync(host, port).Wait(timeoutMs))
            {
                direct.Dispose();
                throw new TimeoutException($"Timed out connecting to {host}:{port}.");
            }

            return direct;
        }

        TcpClient tcp = proxy.ConnectToProxy(timeoutMs);
        try
        {
            NetworkStream stream = tcp.GetStream();
            stream.ReadTimeout = timeoutMs;
            stream.WriteTimeout = timeoutMs;
            switch (proxy.Scheme)
            {
                case ProxyScheme.Socks5:
                    Socks5Connect(stream, proxy, host, port);
                    break;
                case ProxyScheme.Socks4a:
                    Socks4Connect(stream, host, port, remoteDns: true, proxy.Username);
                    break;
                case ProxyScheme.Socks4:
                    Socks4Connect(stream, host, port, remoteDns: false, proxy.Username);
                    break;
                default:
                    HttpConnect(stream, proxy, host, port);
                    break;
            }

            return tcp;
        }
        catch
        {
            tcp.Dispose();
            throw;
        }
    }

    // --- SOCKS5 (RFC 1928) + username/password auth (RFC 1929) ---
    private static void Socks5Connect(NetworkStream s, ProxyEndpoint proxy, string host, int port)
    {
        bool offerAuth = proxy.Username is not null;
        var greeting = offerAuth
            ? new byte[] { 0x05, 0x02, 0x00, 0x02 }   // no-auth + user/pass
            : new byte[] { 0x05, 0x01, 0x00 };         // no-auth only
        s.Write(greeting, 0, greeting.Length);
        s.Flush();

        byte[] method = ReadExact(s, 2);
        if (method[0] != 0x05)
        {
            throw new IOException("SOCKS5: bad version in method selection.");
        }

        switch (method[1])
        {
            case 0x00:
                break; // no auth
            case 0x02:
                Socks5UserPassAuth(s, proxy.Username ?? string.Empty, proxy.Password ?? string.Empty);
                break;
            case 0xFF:
                throw new IOException("SOCKS5: proxy rejected all offered auth methods.");
            default:
                throw new IOException($"SOCKS5: proxy selected unsupported method 0x{method[1]:X2}.");
        }

        var req = new List<byte> { 0x05, 0x01, 0x00 }; // VER, CMD=CONNECT, RSV
        if (IPAddress.TryParse(host, out IPAddress? ip))
        {
            byte[] addr = ip.GetAddressBytes();
            req.Add(ip.AddressFamily == AddressFamily.InterNetworkV6 ? (byte)0x04 : (byte)0x01);
            req.AddRange(addr);
        }
        else
        {
            byte[] name = Encoding.ASCII.GetBytes(host);
            if (name.Length > 255)
            {
                throw new ArgumentException("SOCKS5: hostname too long.");
            }

            req.Add(0x03);
            req.Add((byte)name.Length);
            req.AddRange(name);
        }

        req.Add((byte)(port >> 8));
        req.Add((byte)(port & 0xFF));
        s.Write(req.ToArray(), 0, req.Count);
        s.Flush();

        byte[] reply = ReadExact(s, 4);
        if (reply[0] != 0x05)
        {
            throw new IOException("SOCKS5: bad reply version.");
        }

        if (reply[1] != 0x00)
        {
            throw new IOException($"SOCKS5: CONNECT failed (reply code 0x{reply[1]:X2}: {Socks5Error(reply[1])}).");
        }

        // Consume BND.ADDR + BND.PORT per the returned address type.
        int toSkip = reply[3] switch
        {
            0x01 => 4 + 2,            // IPv4 + port
            0x04 => 16 + 2,           // IPv6 + port
            0x03 => ReadExact(s, 1)[0] + 2, // length-prefixed domain + port
            _ => throw new IOException($"SOCKS5: unknown bound address type 0x{reply[3]:X2}."),
        };
        ReadExact(s, toSkip);
    }

    private static void Socks5UserPassAuth(NetworkStream s, string user, string pass)
    {
        byte[] u = Encoding.UTF8.GetBytes(user);
        byte[] p = Encoding.UTF8.GetBytes(pass);
        if (u.Length > 255 || p.Length > 255)
        {
            throw new ArgumentException("SOCKS5: username/password too long.");
        }

        var buf = new List<byte> { 0x01, (byte)u.Length };
        buf.AddRange(u);
        buf.Add((byte)p.Length);
        buf.AddRange(p);
        s.Write(buf.ToArray(), 0, buf.Count);
        s.Flush();

        byte[] resp = ReadExact(s, 2);
        if (resp[1] != 0x00)
        {
            throw new IOException("SOCKS5: username/password authentication failed.");
        }
    }

    private static string Socks5Error(byte code) => code switch
    {
        0x01 => "general failure",
        0x02 => "connection not allowed",
        0x03 => "network unreachable",
        0x04 => "host unreachable",
        0x05 => "connection refused",
        0x06 => "TTL expired",
        0x07 => "command not supported",
        0x08 => "address type not supported",
        _ => "unknown",
    };

    // --- SOCKS4 / SOCKS4a (connect by IP, or by name for 4a) ---
    private static void Socks4Connect(NetworkStream s, string host, int port, bool remoteDns, string? userId)
    {
        var req = new List<byte> { 0x04, 0x01, (byte)(port >> 8), (byte)(port & 0xFF) };
        byte[]? nameBytes = null;

        if (!remoteDns || IPAddress.TryParse(host, out _))
        {
            IPAddress v4 = IPAddress.TryParse(host, out IPAddress? parsed) && parsed.AddressFamily == AddressFamily.InterNetwork
                ? parsed
                : Array.Find(Dns.GetHostAddresses(host), a => a.AddressFamily == AddressFamily.InterNetwork)
                  ?? throw new IOException($"SOCKS4: no IPv4 address for '{host}'.");
            req.AddRange(v4.GetAddressBytes());
        }
        else
        {
            // SOCKS4a: dest IP 0.0.0.x (x != 0) signals "resolve the trailing hostname on the far side".
            req.AddRange(new byte[] { 0x00, 0x00, 0x00, 0x01 });
            nameBytes = Encoding.ASCII.GetBytes(host);
        }

        req.AddRange(Encoding.ASCII.GetBytes(userId ?? string.Empty));
        req.Add(0x00); // USERID terminator
        if (nameBytes is not null)
        {
            req.AddRange(nameBytes);
            req.Add(0x00); // hostname terminator
        }

        s.Write(req.ToArray(), 0, req.Count);
        s.Flush();

        byte[] reply = ReadExact(s, 8);
        if (reply[1] != 0x5A)
        {
            throw new IOException($"SOCKS4: request rejected (code 0x{reply[1]:X2}).");
        }
    }

    // --- HTTP CONNECT (optional Basic auth) ---
    private static void HttpConnect(NetworkStream s, ProxyEndpoint proxy, string host, int port)
    {
        var sb = new StringBuilder();
        sb.Append($"CONNECT {host}:{port} HTTP/1.1\r\n");
        sb.Append($"Host: {host}:{port}\r\n");
        if (proxy.Username is not null)
        {
            string token = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{proxy.Username}:{proxy.Password}"));
            sb.Append($"Proxy-Authorization: Basic {token}\r\n");
        }

        sb.Append("Proxy-Connection: Keep-Alive\r\n\r\n");
        byte[] reqBytes = Encoding.ASCII.GetBytes(sb.ToString());
        s.Write(reqBytes, 0, reqBytes.Length);
        s.Flush();

        string statusLine = ReadHttpHeaders(s);
        // Expect: HTTP/1.1 200 Connection established
        string[] parts = statusLine.Split(' ', 3);
        if (parts.Length < 2 || parts[1] != "200")
        {
            throw new IOException($"HTTP proxy CONNECT failed: {statusLine}");
        }
    }

    private static string ReadHttpHeaders(NetworkStream s)
    {
        var all = new StringBuilder();
        int state = 0; // counts \r \n \r \n
        var one = new byte[1];
        string? statusLine = null;
        while (state < 4)
        {
            if (s.Read(one, 0, 1) <= 0)
            {
                throw new IOException("HTTP proxy closed the connection during CONNECT.");
            }

            char c = (char)one[0];
            all.Append(c);
            state = c switch
            {
                '\r' when state is 0 or 2 => state + 1,
                '\n' when state is 1 or 3 => state + 1,
                _ => 0,
            };

            if (statusLine is null && c == '\n')
            {
                statusLine = all.ToString().TrimEnd('\r', '\n');
            }
        }

        return statusLine ?? all.ToString();
    }

    private static byte[] ReadExact(NetworkStream s, int count)
    {
        var buffer = new byte[count];
        int read = 0;
        while (read < count)
        {
            int n = s.Read(buffer, read, count - read);
            if (n <= 0)
            {
                throw new IOException("Proxy closed the connection during the handshake.");
            }

            read += n;
        }

        return buffer;
    }
}
