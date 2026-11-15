using System.Net;
using System.Net.Sockets;
using System.Text;
using DotNetPacket.Core.Net;
using Xunit;

namespace DotNetPacket.Core.Tests;

public class ProxyTests
{
    [Theory]
    [InlineData("socks5://127.0.0.1:1080", ProxyScheme.Socks5, "127.0.0.1", 1080, null)]
    [InlineData("socks://10.0.0.1", ProxyScheme.Socks5, "10.0.0.1", 1080, null)]            // default SOCKS port
    [InlineData("socks5://user:pass@h:9050", ProxyScheme.Socks5, "h", 9050, "user")]
    [InlineData("socks4a://pivot:1081", ProxyScheme.Socks4a, "pivot", 1081, null)]
    [InlineData("socks4://1.2.3.4:1080", ProxyScheme.Socks4, "1.2.3.4", 1080, null)]
    [InlineData("http://burp:8080", ProxyScheme.Http, "burp", 8080, null)]
    [InlineData("http://proxy", ProxyScheme.Http, "proxy", 8080, null)]                      // default HTTP port
    public void Parse_ReadsScheme_Host_Port_User(string url, ProxyScheme scheme, string host, int port, string? user)
    {
        ProxyEndpoint ep = ProxyEndpoint.Parse(url);
        Assert.Equal(scheme, ep.Scheme);
        Assert.Equal(host, ep.Host);
        Assert.Equal(port, ep.Port);
        Assert.Equal(user, ep.Username);
    }

    [Theory]
    [InlineData("127.0.0.1:1080")]       // no scheme
    [InlineData("ftp://h:1")]            // unknown scheme
    [InlineData("socks5://")]            // no host
    public void Parse_RejectsBadUrls(string url) => Assert.Throws<FormatException>(() => ProxyEndpoint.Parse(url));

    [Fact]
    public void Socks5_Connect_TunnelsBytesToTarget()
    {
        // An in-process echo server is the "target"; an in-process SOCKS5 server tunnels to it.
        using var target = new EchoServer();
        using var proxy = new FakeSocks5Server(target.Port);

        TcpClient tunnel = ProxyConnector.Connect(
            ProxyEndpoint.Parse($"socks5://127.0.0.1:{proxy.Port}"), "127.0.0.1", target.Port, 5000);
        using (tunnel)
        {
            NetworkStream s = tunnel.GetStream();
            byte[] payload = Encoding.ASCII.GetBytes("hello-through-socks");
            s.Write(payload, 0, payload.Length);
            s.Flush();

            var got = new byte[payload.Length];
            int read = 0;
            while (read < got.Length)
            {
                int n = s.Read(got, read, got.Length - read);
                Assert.True(n > 0, "tunnel closed early");
                read += n;
            }

            Assert.Equal(payload, got);
        }

        Assert.True(proxy.SawConnectToPort(target.Port), "SOCKS5 server never received the expected CONNECT");
    }

    // --- minimal in-process helpers ---

    private sealed class EchoServer : IDisposable
    {
        private readonly TcpListener _l;
        public int Port => ((IPEndPoint)_l.LocalEndpoint).Port;

        public EchoServer()
        {
            _l = new TcpListener(IPAddress.Loopback, 0);
            _l.Start();
            _ = System.Threading.Tasks.Task.Run(Loop);
        }

        private void Loop()
        {
            try
            {
                using TcpClient c = _l.AcceptTcpClient();
                using NetworkStream s = c.GetStream();
                var buf = new byte[1024];
                int n;
                while ((n = s.Read(buf, 0, buf.Length)) > 0)
                {
                    s.Write(buf, 0, n);
                }
            }
            catch { /* listener stopped */ }
        }

        public void Dispose() => _l.Stop();
    }

    private sealed class FakeSocks5Server : IDisposable
    {
        private readonly TcpListener _l;
        private volatile int _connectedPort = -1;
        public int Port => ((IPEndPoint)_l.LocalEndpoint).Port;
        public bool SawConnectToPort(int p) => _connectedPort == p;

        public FakeSocks5Server(int upstreamPort)
        {
            _l = new TcpListener(IPAddress.Loopback, 0);
            _l.Start();
            _ = System.Threading.Tasks.Task.Run(() => Serve(upstreamPort));
        }

        private void Serve(int upstreamPort)
        {
            try
            {
                using TcpClient c = _l.AcceptTcpClient();
                using NetworkStream s = c.GetStream();
                // greeting: VER NMETHODS METHODS...
                Assert.Equal(0x05, ReadByte(s));
                int nm = ReadByte(s);
                for (int i = 0; i < nm; i++) ReadByte(s);
                s.Write(new byte[] { 0x05, 0x00 }, 0, 2); // no-auth

                // request: VER CMD RSV ATYP ADDR PORT
                Assert.Equal(0x05, ReadByte(s));
                Assert.Equal(0x01, ReadByte(s)); // CONNECT
                ReadByte(s);                      // RSV
                int atyp = ReadByte(s);
                string host = atyp switch
                {
                    0x01 => $"{ReadByte(s)}.{ReadByte(s)}.{ReadByte(s)}.{ReadByte(s)}",
                    0x03 => ReadDomain(s),
                    _ => throw new IOException("unexpected ATYP"),
                };
                int port = (ReadByte(s) << 8) | ReadByte(s);
                _connectedPort = port;

                using var up = new TcpClient();
                up.Connect(host, port);
                s.Write(new byte[] { 0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0 }, 0, 10); // success
                Pump(s, up.GetStream());
            }
            catch { /* done */ }
        }

        private static string ReadDomain(NetworkStream s)
        {
            int len = ReadByte(s);
            var b = new byte[len];
            int r = 0;
            while (r < len) r += s.Read(b, r, len - r);
            return Encoding.ASCII.GetString(b);
        }

        private static int ReadByte(NetworkStream s)
        {
            int b = s.ReadByte();
            if (b < 0) throw new IOException("closed");
            return b;
        }

        private static void Pump(NetworkStream a, NetworkStream b)
        {
            var t = System.Threading.Tasks.Task.Run(() => Copy(b, a));
            Copy(a, b);
            t.Wait(2000);
        }

        private static void Copy(NetworkStream from, NetworkStream to)
        {
            try
            {
                var buf = new byte[4096];
                int n;
                while ((n = from.Read(buf, 0, buf.Length)) > 0) to.Write(buf, 0, n);
            }
            catch { }
        }

        public void Dispose() => _l.Stop();
    }
}
