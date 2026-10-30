using DotNetPacket.Core;
using DotNetPacket.Protocols.Ntlm;
using DotNetPacket.Transport;

namespace DotNetPacket.Protocols.Smb;

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

/// <summary>Outcome of a CREATE (open): status plus the parsed response (FileId, size, ...).</summary>
public sealed class Smb2CreateResult
{
    public required uint Status { get; init; }

    public required Smb2CreateResponse Response { get; init; }

    public bool Succeeded => Status == NtStatus.Success;
}

/// <summary>Outcome of a READ: status plus the bytes returned.</summary>
public sealed class Smb2ReadResult
{
    public required uint Status { get; init; }

    public required byte[] Data { get; init; }

    public bool Succeeded => Status == NtStatus.Success;
}

/// <summary>Outcome of an IOCTL/FSCTL: status plus the output buffer.</summary>
public sealed class Smb2IoctlResult
{
    public required uint Status { get; init; }

    public required byte[] Output { get; init; }

    public bool Succeeded => Status == NtStatus.Success || Status == NtStatus.BufferOverflow;
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
        byte[] response = ReceiveFinal();
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
        byte[] response = ReceiveFinal();
        _messageId++;

        var responseHeader = new Smb2Header();
        responseHeader.Unpack(response);
        return responseHeader.Status;
    }

    /// <summary>Opens (or creates) a file on a connected tree.</summary>
    public Smb2CreateResult Create(
        uint treeId,
        string path,
        Smb2AccessMask access = Smb2AccessMask.FileGenericRead,
        Smb2CreateDisposition disposition = Smb2CreateDisposition.Open,
        Smb2CreateOptions options = Smb2CreateOptions.NonDirectoryFile)
    {
        var body = new Smb2CreateRequest
        {
            Path = path,
            DesiredAccess = access,
            CreateDisposition = disposition,
            CreateOptions = options,
        };

        (byte[] response, Smb2Header header) = Exchange(Smb2Command.Create, treeId, body.Pack());
        var parsed = new Smb2CreateResponse();
        if (header.Status == NtStatus.Success)
        {
            parsed.Unpack(response);
        }

        return new Smb2CreateResult { Status = header.Status, Response = parsed };
    }

    /// <summary>Reads <paramref name="length"/> bytes at <paramref name="offset"/> from an open FileId.</summary>
    public Smb2ReadResult Read(uint treeId, byte[] fileId, long offset, int length)
    {
        var body = new Smb2ReadRequest
        {
            FileId = fileId,
            Offset = (ulong)offset,
            Length = (uint)length,
        };

        (byte[] response, Smb2Header header) = Exchange(Smb2Command.Read, treeId, body.Pack());
        var parsed = new Smb2ReadResponse();
        if (header.Status == NtStatus.Success)
        {
            parsed.Unpack(response);
        }

        return new Smb2ReadResult { Status = header.Status, Data = parsed.Data };
    }

    /// <summary>Opens a directory and enumerates its entries (the dir/ls behavior).</summary>
    public IReadOnlyList<Smb2DirectoryEntry> ListDirectory(uint treeId, string path = "", string pattern = "*")
    {
        Smb2CreateResult dir = Create(
            treeId,
            path,
            Smb2AccessMask.FileGenericRead,
            Smb2CreateDisposition.Open,
            Smb2CreateOptions.DirectoryFile);
        if (!dir.Succeeded)
        {
            throw new IOException($"Could not open directory '{path}': {NtStatus.Describe(dir.Status)}");
        }

        try
        {
            var all = new List<Smb2DirectoryEntry>();
            // The scan continues across calls on the same handle until NO_MORE_FILES.
            for (int round = 0; round < 1024; round++)
            {
                var body = new Smb2QueryDirectoryRequest { FileId = dir.Response.FileId, SearchPattern = pattern };
                (byte[] response, Smb2Header header) = Exchange(Smb2Command.QueryDirectory, treeId, body.Pack());
                if (header.Status == NtStatus.NoMoreFiles)
                {
                    break;
                }

                if (header.Status != NtStatus.Success)
                {
                    throw new IOException($"QUERY_DIRECTORY failed: {NtStatus.Describe(header.Status)}");
                }

                all.AddRange(Smb2QueryDirectoryResponse.Parse(response));
            }

            return all;
        }
        finally
        {
            Close(treeId, dir.Response.FileId);
        }
    }

    /// <summary>Queries file-system volume info (serial + label) and size info for a connected tree.</summary>
    public (Smb2VolumeInfo Volume, Smb2FsSizeInfo Size) QueryFileSystemInfo(uint treeId)
    {
        Smb2CreateResult root = Create(
            treeId, string.Empty, Smb2AccessMask.FileGenericRead, Smb2CreateDisposition.Open, Smb2CreateOptions.DirectoryFile);
        if (!root.Succeeded)
        {
            throw new IOException($"Could not open share root: {NtStatus.Describe(root.Status)}");
        }

        try
        {
            byte[] volume = QueryInfo(treeId, root.Response.FileId, Smb2InfoType.FileSystem, (byte)Smb2FsInfoType.VolumeInformation);
            byte[] size = QueryInfo(treeId, root.Response.FileId, Smb2InfoType.FileSystem, (byte)Smb2FsInfoType.SizeInformation);
            return (Smb2QueryInfoResponse.ParseVolumeInfo(volume), Smb2QueryInfoResponse.ParseFsSizeInfo(size));
        }
        finally
        {
            Close(treeId, root.Response.FileId);
        }
    }

    /// <summary>Issues a QUERY_INFO on an open handle and returns the output buffer.</summary>
    public byte[] QueryInfo(uint treeId, byte[] fileId, Smb2InfoType infoType, byte infoClass)
    {
        var body = new Smb2QueryInfoRequest { InfoType = infoType, FileInfoClass = infoClass, FileId = fileId };
        (byte[] response, Smb2Header header) = Exchange(Smb2Command.QueryInfo, treeId, body.Pack());
        if (header.Status != NtStatus.Success)
        {
            throw new IOException($"QUERY_INFO failed: {NtStatus.Describe(header.Status)}");
        }

        return Smb2QueryInfoResponse.ExtractOutput(response);
    }

    /// <summary>Writes <paramref name="data"/> at <paramref name="offset"/> to an open FileId; returns bytes written.</summary>
    public uint Write(uint treeId, byte[] fileId, long offset, byte[] data)
    {
        var body = new Smb2WriteRequest { FileId = fileId, Offset = (ulong)offset, Data = data };
        (byte[] response, Smb2Header header) = Exchange(Smb2Command.Write, treeId, body.Pack());
        if (header.Status != NtStatus.Success)
        {
            return 0;
        }

        var parsed = new Smb2WriteResponse();
        parsed.Unpack(response);
        return parsed.Count;
    }

    /// <summary>Closes an open FileId.</summary>
    public uint Close(uint treeId, byte[] fileId)
    {
        var body = new Smb2CloseRequest { FileId = fileId };
        (_, Smb2Header header) = Exchange(Smb2Command.Close, treeId, body.Pack());
        return header.Status;
    }

    /// <summary>Issues an FSCTL/IOCTL (e.g. FSCTL_PIPE_TRANSCEIVE for DCERPC) and returns the output buffer.</summary>
    public Smb2IoctlResult Ioctl(uint treeId, byte[] fileId, uint ctlCode, byte[] input, uint maxOutput = 65536)
    {
        var body = new Smb2IoctlRequest
        {
            CtlCode = ctlCode,
            FileId = fileId,
            Input = input,
            MaxOutputResponse = maxOutput,
        };

        (byte[] response, Smb2Header header) = Exchange(Smb2Command.Ioctl, treeId, body.Pack());
        var parsed = new Smb2IoctlResponse();
        if (header.Status == NtStatus.Success || header.Status == NtStatus.BufferOverflow)
        {
            parsed.Unpack(response);
        }

        return new Smb2IoctlResult { Status = header.Status, Output = parsed.Output };
    }

    /// <summary>Opens a file, reads it in full (looping over READ), and closes it.</summary>
    public byte[] ReadFile(uint treeId, string path)
    {
        Smb2CreateResult create = Create(treeId, path);
        if (!create.Succeeded)
        {
            throw new IOException($"CREATE failed for '{path}': {NtStatus.Describe(create.Status)}");
        }

        try
        {
            var data = new List<byte>();
            ulong size = create.Response.EndOfFile;
            const int chunk = 65536;
            long offset = 0;
            while ((ulong)offset < size)
            {
                int want = (int)Math.Min((ulong)chunk, size - (ulong)offset);
                Smb2ReadResult read = Read(treeId, create.Response.FileId, offset, want);
                if (!read.Succeeded || read.Data.Length == 0)
                {
                    break;
                }

                data.AddRange(read.Data);
                offset += read.Data.Length;
            }

            return data.ToArray();
        }
        finally
        {
            Close(treeId, create.Response.FileId);
        }
    }

    private (byte[] Response, Smb2Header Header) Exchange(Smb2Command command, uint treeId, byte[] body)
    {
        var header = new Smb2Header
        {
            Command = (ushort)command,
            MessageId = _messageId,
            CreditCharge = 1,
            CreditRequest = 1,
            SessionId = _sessionId,
            TreeId = treeId,
        };

        byte[] request = SignIfKeyed(Assemble(header, body));
        _transport.SendMessage(request);
        byte[] response = ReceiveFinal();
        _messageId++;

        var responseHeader = new Smb2Header();
        responseHeader.Unpack(response);
        return (response, responseHeader);
    }

    /// <summary>
    /// Receives a response, skipping SMB2 async interim replies (STATUS_PENDING):
    /// the server sends those while it works and follows with the real response
    /// carrying the same MessageId.
    /// </summary>
    private byte[] ReceiveFinal()
    {
        while (true)
        {
            byte[] response = _transport.ReceiveMessage();
            var header = new Smb2Header();
            header.Unpack(response);
            if (header.Status != NtStatus.Pending)
            {
                return response;
            }
        }
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
