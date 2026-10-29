using NetPacket.Core;
using NetPacket.Protocols.Ntlm;
using NetPacket.Transport;

namespace NetPacket.Protocols.Smb;

/// <summary>Outcome of a NEGOTIATE exchange: the structures and the exact bytes seen on the wire.</summary>
public sealed class Smb2NegotiateResult
{
    public required Smb2NegotiateRequest Request { get; init; }

    public required byte[] RequestBytes { get; init; }

    public required byte[] ResponseBytes { get; init; }

    public required Smb2NegotiateResponse Response { get; init; }
}

/// <summary>Outcome of an NTLM SESSION_SETUP: both handshake rounds and the final status.</summary>
public sealed class Smb2LoginResult
{
    public required ulong SessionId { get; init; }

    public required uint Round1Status { get; init; }

    public required uint Round2Status { get; init; }

    public bool Authenticated => Round2Status == NtStatus.Success;

    public required byte[] Round1Request { get; init; }

    public required byte[] Round1Response { get; init; }

    public required byte[] Round2Request { get; init; }

    public required byte[] Round2Response { get; init; }
}

/// <summary>
/// A stateful SMB2 client connection: NEGOTIATE then NTLM SESSION_SETUP, over a
/// single <see cref="DirectTcpTransport"/>. This is the realistic opening of an
/// SMB session and the richest signal for behavior research. Signing, tree
/// connect, and file operations build on top (tracked in PORTING_STATUS).
/// </summary>
public sealed class Smb2Client : IDisposable
{
    private readonly DirectTcpTransport _transport = new();
    private ulong _messageId;
    private ulong _sessionId;

    public void Connect(string host, int port = 445) => _transport.Connect(host, port);

    public Smb2NegotiateResult Negotiate(Smb2NegotiateRequest? request = null)
    {
        request ??= new Smb2NegotiateRequest();

        var header = new Smb2Header
        {
            Command = (ushort)Smb2Command.Negotiate,
            MessageId = _messageId,
        };

        byte[] requestBytes = Assemble(header, request.Pack());
        _transport.SendMessage(requestBytes);
        byte[] responseBytes = _transport.ReceiveMessage();
        _messageId++;

        var response = new Smb2NegotiateResponse();
        response.Unpack(responseBytes);

        return new Smb2NegotiateResult
        {
            Request = request,
            RequestBytes = requestBytes,
            ResponseBytes = responseBytes,
            Response = response,
        };
    }

    /// <summary>Performs the two-round NTLMv2 SESSION_SETUP. Negotiate first.</summary>
    public Smb2LoginResult Login(string domain, string user, string password)
    {
        var ntlm = new NtlmClient();

        // Round 1: SPNEGO(NegTokenInit) wrapping the NTLM NEGOTIATE (Type 1).
        byte[] spnegoInit = Spnego.WrapInitialToken(ntlm.CreateNegotiate());
        (byte[] request1, byte[] response1) = SendSessionSetup(spnegoInit, sessionId: 0);

        var header1 = new Smb2Header();
        header1.Unpack(response1);
        _sessionId = header1.SessionId;

        var setup1 = new Smb2SessionSetupResponse();
        setup1.Unpack(response1);
        byte[] challenge = Spnego.ExtractResponseToken(setup1.SecurityBuffer);

        // Round 2: SPNEGO(NegTokenResp) wrapping the NTLM AUTHENTICATE (Type 3),
        // with the mechListMIC that finalizes the SPNEGO exchange.
        NtlmAuthResult auth = ntlm.CreateAuthenticate(challenge, domain, user, password);
        byte[] signingKey = NtlmCrypto.ClientSigningKey(auth.SessionKey);
        byte[] mechListMic = NtlmCrypto.GssMic(signingKey, 0, Spnego.NtlmMechListDer);
        byte[] spnegoResp = Spnego.WrapResponseToken(auth.Message, mechListMic);
        (byte[] request2, byte[] response2) = SendSessionSetup(spnegoResp, _sessionId);

        var header2 = new Smb2Header();
        header2.Unpack(response2);

        return new Smb2LoginResult
        {
            SessionId = _sessionId,
            Round1Status = header1.Status,
            Round2Status = header2.Status,
            Round1Request = request1,
            Round1Response = response1,
            Round2Request = request2,
            Round2Response = response2,
        };
    }

    private (byte[] Request, byte[] Response) SendSessionSetup(byte[] securityBuffer, ulong sessionId)
    {
        var header = new Smb2Header
        {
            Command = (ushort)Smb2Command.SessionSetup,
            MessageId = _messageId,
            CreditCharge = 1,
            CreditRequest = 1,
            SessionId = sessionId,
        };

        var body = new Smb2SessionSetupRequest { SecurityBuffer = securityBuffer };
        byte[] request = Assemble(header, body.Pack());
        _transport.SendMessage(request);
        byte[] response = _transport.ReceiveMessage();
        _messageId++;
        return (request, response);
    }

    private static byte[] Assemble(Smb2Header header, byte[] body)
    {
        var writer = new ByteWriter(ByteOrder.Little);
        writer.WriteBytes(header.Pack());
        writer.WriteBytes(body);
        return writer.ToArray();
    }

    public void Dispose() => _transport.Dispose();
}
