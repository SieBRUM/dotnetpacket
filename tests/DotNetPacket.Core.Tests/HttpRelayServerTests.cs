using System.Net;
using System.Net.Sockets;
using System.Text;
using DotNetPacket.Core;
using DotNetPacket.Protocols.Http;
using DotNetPacket.Protocols.Ntlm;
using Xunit;

namespace DotNetPacket.Core.Tests;

public class HttpRelayServerTests
{
    // A canned relay target: returns a fixed Type 2, records the victim's Type 3, reports SUCCESS.
    private sealed class FakeTarget : IRelayTarget
    {
        private readonly byte[] _challenge;
        public byte[]? SeenType1;
        public byte[]? SeenType3;

        public FakeTarget(byte[] challenge) => _challenge = challenge;

        public byte[] Negotiate(byte[] victimType1)
        {
            SeenType1 = victimType1;
            return _challenge;
        }

        public uint Authenticate(byte[] victimType3, byte[]? mechListMic)
        {
            SeenType3 = victimType3;
            return 0; // SUCCESS
        }
    }

    // Minimal parseable NTLMSSP CHALLENGE (Type 2) with the given server challenge + an EOL target info.
    private static byte[] BuildType2(byte[] serverChallenge)
    {
        byte[] targetInfo = { 0, 0, 0, 0 }; // MsvAvEOL
        const uint flags = 0x00000001 | 0x00000200 | 0x00800000; // UNICODE | NTLM | TARGET_INFO
        var w = new ByteWriter(ByteOrder.Little);
        w.WriteBytes(Encoding.ASCII.GetBytes("NTLMSSP\0"));
        w.WriteUInt32(2);                       // MessageType
        w.WriteUInt16(0); w.WriteUInt16(0); w.WriteUInt32(48); // TargetName (empty), payload at 48
        w.WriteUInt32(flags);
        w.WriteBytes(serverChallenge);          // 8
        w.WriteBytes(new byte[8]);              // Reserved
        w.WriteUInt16((ushort)targetInfo.Length);
        w.WriteUInt16((ushort)targetInfo.Length);
        w.WriteUInt32(48);                      // TargetInfo offset
        w.WriteBytes(targetInfo);
        return w.ToArray();
    }

    [Fact]
    public void HttpRelay_FullHandshake_RelaysChallengeAndCapturesType3()
    {
        byte[] challenge = BuildType2(Convert.FromHexString("1122334455667788"));
        var target = new FakeTarget(challenge);

        using var server = new HttpRelayServer(0, IPAddress.Loopback);
        server.Start();
        int port = server.Port;

        HttpRelayOutcome? outcome = null;
        var serverTask = System.Threading.Tasks.Task.Run(() => outcome = server.AcceptAndRelay(target));

        // Drive a bare-NTLM HTTP victim (no MIC, as a real browser would).
        var ntlm = new NtlmClient { IncludeMic = false };
        using var tcp = new TcpClient();
        tcp.Connect(IPAddress.Loopback, port);
        using NetworkStream s = tcp.GetStream();
        s.ReadTimeout = 10_000;

        Get(s, null);
        Assert.Equal(401, ReadStatus(s, out _));

        Get(s, "NTLM " + Convert.ToBase64String(ntlm.CreateNegotiate()));
        Assert.Equal(401, ReadStatus(s, out var ch));
        byte[] type2 = Convert.FromBase64String(ch["WWW-Authenticate"].Substring(5).Trim());
        Assert.Equal(challenge, type2); // the relayed (target's) challenge came back to the victim

        NtlmAuthResult auth = ntlm.CreateAuthenticate(type2, "LAB", "Administrator", "pw");
        Get(s, "NTLM " + Convert.ToBase64String(auth.Message));
        Assert.Equal(200, ReadStatus(s, out _)); // relay success -> 200 OK

        serverTask.Wait(10_000);
        Assert.NotNull(outcome);
        Assert.True(outcome!.Relayed);
        Assert.Equal(auth.Message, target.SeenType3);        // the server forwarded the victim's Type 3
        Assert.Equal(auth.Message, outcome.VictimAuthenticate);
    }

    private static void Get(NetworkStream s, string? authorization)
    {
        var sb = new StringBuilder("GET / HTTP/1.1\r\nHost: x\r\n");
        if (authorization is not null)
        {
            sb.Append("Authorization: ").Append(authorization).Append("\r\n");
        }

        sb.Append("Connection: keep-alive\r\n\r\n");
        byte[] b = Encoding.ASCII.GetBytes(sb.ToString());
        s.Write(b, 0, b.Length);
        s.Flush();
    }

    private static int ReadStatus(NetworkStream s, out Dictionary<string, string> headers)
    {
        headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        string statusLine = ReadLine(s);
        int code = int.Parse(statusLine.Split(' ')[1]);
        while (true)
        {
            string line = ReadLine(s);
            if (line.Length == 0)
            {
                break;
            }

            int colon = line.IndexOf(':');
            if (colon > 0)
            {
                headers[line[..colon].Trim()] = line[(colon + 1)..].Trim();
            }
        }

        if (headers.TryGetValue("content-length", out string? cl) && int.TryParse(cl, out int len) && len > 0)
        {
            var body = new byte[len];
            int read = 0;
            while (read < len) { int n = s.Read(body, read, len - read); if (n <= 0) break; read += n; }
        }

        return code;
    }

    private static string ReadLine(NetworkStream s)
    {
        var sb = new StringBuilder();
        int prev = -1;
        while (true)
        {
            int b = s.ReadByte();
            if (b < 0) return sb.ToString();
            if (prev == '\r' && b == '\n') { sb.Length -= 1; return sb.ToString(); }
            sb.Append((char)b);
            prev = b;
        }
    }
}
