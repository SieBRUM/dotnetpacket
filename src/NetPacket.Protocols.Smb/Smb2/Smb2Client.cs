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

    /// <summary>True once an SMB 3.1.1 signing key has been derived for the session.</summary>
    public required bool Signed { get; init; }

    public required byte[] Round1Request { get; init; }

    public required byte[] Round1Response { get; init; }

    public required byte[] Round2Request { get; init; }

    public required byte[] Round2Response { get; init; }
}

/// <summary>Outcome of a TREE_CONNECT: the granted share info and whether the server's reply verified.</summary>
public sealed class Smb2TreeConnectResult
{
    public required uint Status { get; init; }

    public required uint TreeId { get; init; }

    public required Smb2TreeConnectResponse Response { get; init; }

    public required bool ServerSignatureValid { get; init; }

    public required byte[] RequestBytes { get; init; }

    public required byte[] ResponseBytes { get; init; }

    public bool Connected => Status == NtStatus.Success;
}

/// <summary>
/// A stateful SMB2 client connection: NEGOTIATE, NTLMv2 SESSION_SETUP, then signed
/// TREE_CONNECT — the realistic opening of an SMB session through reaching a share,
/// over a single <see cref="DirectTcpTransport"/>. SMB 3.1.1 preauth integrity and
/// AES-CMAC signing are applied end to end. Create/Read/Write build on top
/// (tracked in PORTING_STATUS).
/// </summary>
public sealed class Smb2Client : IDisposable
{
    private readonly DirectTcpTransport _transport = new();
    private ulong _messageId;
    private ulong _sessionId;
    private byte[] _preauthHash = Smb2Crypto.PreauthInit();
    private byte[]? _signingKey;
    private Smb2Dialect _dialect;

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
        _dialect = response.DialectRevision;

        // Begin the SMB 3.1.1 preauth-integrity chain over negotiate req + resp.
        _preauthHash = Smb2Crypto.PreauthUpdate(_preauthHash, requestBytes);
        _preauthHash = Smb2Crypto.PreauthUpdate(_preauthHash, responseBytes);

        return new Smb2NegotiateResult
        {
            Request = request,
            RequestBytes = requestBytes,
            ResponseBytes = responseBytes,
            Response = response,
        };
    }

    /// <summary>Performs the two-round NTLMv2 SESSION_SETUP and derives the SMB 3.1.1 signing key.</summary>
    public Smb2LoginResult Login(string domain, string user, string password)
    {
        var ntlm = new NtlmClient();

        // Round 1: SPNEGO(NegTokenInit) wrapping the NTLM NEGOTIATE (Type 1).
        byte[] spnegoInit = Spnego.WrapInitialToken(ntlm.CreateNegotiate());
        (byte[] request1, byte[] response1) = SendSessionSetup(spnegoInit, sessionId: 0);
        _preauthHash = Smb2Crypto.PreauthUpdate(_preauthHash, request1);
        _preauthHash = Smb2Crypto.PreauthUpdate(_preauthHash, response1);

        var header1 = new Smb2Header();
        header1.Unpack(response1);
        _sessionId = header1.SessionId;

        var setup1 = new Smb2SessionSetupResponse();
        setup1.Unpack(response1);
        byte[] challenge = Spnego.ExtractResponseToken(setup1.SecurityBuffer);

        // Round 2: SPNEGO(NegTokenResp) wrapping the NTLM AUTHENTICATE (Type 3) + mechListMIC.
        NtlmAuthResult auth = ntlm.CreateAuthenticate(challenge, domain, user, password);
        byte[] signingKey = NtlmCrypto.ClientSigningKey(auth.SessionKey);
        byte[] mechListMic = NtlmCrypto.GssMic(signingKey, 0, Spnego.NtlmMechListDer);
        byte[] spnegoResp = Spnego.WrapResponseToken(auth.Message, mechListMic);

        (byte[] request2, byte[] response2) = SendSessionSetup(spnegoResp, _sessionId);

        // The signing key derives from the preauth hash through the final request
        // (not the success response), per MS-SMB2 3.2.5.3.
        _preauthHash = Smb2Crypto.PreauthUpdate(_preauthHash, request2);
        if (_dialect == Smb2Dialect.Smb311)
        {
            _signingKey = Smb2Crypto.Smb311SigningKey(auth.SessionKey, _preauthHash);
        }

        var header2 = new Smb2Header();
        header2.Unpack(response2);

        return new Smb2LoginResult
        {
            SessionId = _sessionId,
            Round1Status = header1.Status,
            Round2Status = header2.Status,
            Signed = _signingKey is not null,
            Round1Request = request1,
            Round1Response = response1,
            Round2Request = request2,
            Round2Response = response2,
        };
    }

    /// <summary>Connects to a share by UNC path (e.g. <c>\\host\share</c>), signed.</summary>
    public Smb2TreeConnectResult TreeConnect(string uncPath)
    {
        var body = new Smb2TreeConnectRequest { Path = uncPath };
        var header = new Smb2Header
        {
            Command = (ushort)Smb2Command.TreeConnect,
            MessageId = _messageId,
            CreditCharge = 1,
            CreditRequest = 1,
            SessionId = _sessionId,
        };

        byte[] request = SignIfKeyed(Assemble(header, body.Pack()));
        _transport.SendMessage(request);
        byte[] response = _transport.ReceiveMessage();
        _messageId++;

        var responseHeader = new Smb2Header();
        responseHeader.Unpack(response);

        var parsed = new Smb2TreeConnectResponse();
        if (responseHeader.Status == NtStatus.Success)
        {
            parsed.Unpack(response);
        }

        bool signatureValid = _signingKey is not null && Smb2Crypto.Verify(_signingKey, response);

        return new Smb2TreeConnectResult
        {
            Status = responseHeader.Status,
            TreeId = responseHeader.TreeId,
            Response = parsed,
            ServerSignatureValid = signatureValid,
            RequestBytes = request,
            ResponseBytes = response,
        };
    }

    /// <summary>Disconnects a tree previously connected with <see cref="TreeConnect"/>.</summary>
    public uint TreeDisconnect(uint treeId)
    {
        var header = new Smb2Header
        {
            Command = (ushort)Smb2Command.TreeDisconnect,
            MessageId = _messageId,
            CreditCharge = 1,
            CreditRequest = 1,
            SessionId = _sessionId,
            TreeId = treeId,
        };

        var body = new ByteWriter(ByteOrder.Little);
        body.WriteUInt16(4); // StructureSize
        body.WriteUInt16(0); // Reserved

        byte[] request = SignIfKeyed(Assemble(header, body.ToArray()));
        _transport.SendMessage(request);
        byte[] response = _transport.ReceiveMessage();
        _messageId++;

        var responseHeader = new Smb2Header();
        responseHeader.Unpack(response);
        return responseHeader.Status;
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

    private byte[] SignIfKeyed(byte[] message) =>
        _signingKey is null ? message : Smb2Crypto.Sign(_signingKey, message);

    private static byte[] Assemble(Smb2Header header, byte[] body)
    {
        var writer = new ByteWriter(ByteOrder.Little);
        writer.WriteBytes(header.Pack());
        writer.WriteBytes(body);
        return writer.ToArray();
    }

    public void Dispose() => _transport.Dispose();
}
