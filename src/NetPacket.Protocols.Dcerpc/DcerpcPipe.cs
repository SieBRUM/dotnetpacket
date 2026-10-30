using System.Security.Cryptography;
using NetPacket.Protocols.Ntlm;
using NetPacket.Protocols.Smb;

namespace NetPacket.Protocols.Dcerpc;

/// <summary>
/// DCERPC transport over an SMB2 named pipe (ncacn_np): opens a pipe on the IPC$
/// tree, then exchanges PDUs with SMB2 WRITE + READ. This is how impacket's
/// DCE/RPC examples reach srvsvc/lsarpc/svcctl/samr and friends. Supports an
/// unauthenticated bind and an NTLMSSP-authenticated bind with per-PDU packet
/// integrity or privacy (sign/seal).
/// </summary>
public sealed class DcerpcPipe
{
    // A named-pipe open: read + write + the usual attribute/control bits (matches
    // the access a Windows client requests for an RPC pipe).
    private const Smb2AccessMask PipeAccess = (Smb2AccessMask)0x0012019F;

    private readonly Smb2Client _client;
    private readonly uint _treeId;
    private readonly byte[] _fileId;
    private uint _callId = 1;

    private NtlmSecurityContext? _security;
    private DcerpcAuthLevel _authLevel = DcerpcAuthLevel.None;
    private uint _authContextId;

    private DcerpcPipe(Smb2Client client, uint treeId, byte[] fileId)
    {
        _client = client;
        _treeId = treeId;
        _fileId = fileId;
    }

    /// <summary>Opens <paramref name="pipeName"/> (e.g. "srvsvc") on an already-connected IPC$ tree.</summary>
    public static DcerpcPipe Open(Smb2Client client, uint ipcTreeId, string pipeName)
    {
        Smb2CreateResult create = client.Create(
            ipcTreeId,
            pipeName,
            PipeAccess,
            Smb2CreateDisposition.Open,
            Smb2CreateOptions.NonDirectoryFile);

        if (!create.Succeeded)
        {
            throw new IOException($"Could not open pipe '{pipeName}': {NtStatus.Describe(create.Status)}");
        }

        return new DcerpcPipe(client, ipcTreeId, create.Response.FileId);
    }

    /// <summary>Sends one PDU and reads the reply via FSCTL_PIPE_TRANSCEIVE (one atomic round-trip).</summary>
    public byte[] Transceive(byte[] pdu)
    {
        Smb2IoctlResult result = _client.Ioctl(_treeId, _fileId, Fsctl.PipeTransceive, pdu);
        if (!result.Succeeded)
        {
            throw new IOException($"Pipe transceive failed: {NtStatus.Describe(result.Status)}");
        }

        return result.Output;
    }

    /// <summary>Writes one PDU to the pipe with no reply expected (used for AUTH3).</summary>
    public void Send(byte[] pdu) => _client.Write(_treeId, _fileId, 0, pdu);

    /// <summary>Binds the pipe to an interface and returns the parsed BIND_ACK.</summary>
    public DcerpcBindAck Bind(DcerpcInterface iface)
    {
        var bind = new DcerpcBind
        {
            InterfaceUuid = iface.Uuid,
            InterfaceVersionMajor = iface.VersionMajor,
            InterfaceVersionMinor = iface.VersionMinor,
            CallId = _callId++,
        };

        return DcerpcBindAck.Parse(Transceive(bind.Pack()));
    }

    /// <summary>
    /// Binds the pipe with NTLMSSP authentication and establishes per-PDU protection at
    /// <paramref name="level"/> (packet integrity or privacy): BIND (+Type1) → BIND_ACK
    /// (Type2) → AUTH3 (Type3). After this, <see cref="Call"/> signs and, at privacy
    /// level, seals every request. Mirrors a modern Windows RPC client's sign/seal bind.
    /// </summary>
    public DcerpcBindAck BindAuthenticated(
        DcerpcInterface iface,
        string domain,
        string user,
        string password,
        DcerpcAuthLevel level = DcerpcAuthLevel.PacketPrivacy)
    {
        _authLevel = level;
        _authContextId = BitConverter.ToUInt32(RandomNumberGenerator.GetBytes(4), 0);

        var ntlm = new NtlmClient { KeyExchange = true, IncludeMic = false };
        byte[] type1 = ntlm.CreateNegotiate();

        uint bindCallId = _callId++;
        var bind = new DcerpcBind
        {
            InterfaceUuid = iface.Uuid,
            InterfaceVersionMajor = iface.VersionMajor,
            InterfaceVersionMinor = iface.VersionMinor,
            CallId = bindCallId,
            AuthTrailer = new DcerpcSecTrailer { AuthLevel = (byte)level, AuthContextId = _authContextId },
            AuthToken = type1,
        };

        DcerpcBindAck ack = DcerpcBindAck.Parse(Transceive(bind.Pack()));
        if (!ack.Accepted || ack.AuthValue.Length == 0)
        {
            return ack;
        }

        NtlmAuthResult auth = ntlm.CreateAuthenticate(ack.AuthValue, domain, user, password);
        var auth3 = new DcerpcAuth3
        {
            CallId = bindCallId,
            AuthTrailer = new DcerpcSecTrailer { AuthLevel = (byte)level, AuthContextId = _authContextId },
            AuthToken = auth.Message,
        };
        Send(auth3.Pack());

        _security = new NtlmSecurityContext(auth.SessionKey);
        return ack;
    }

    /// <summary>Invokes an opnum with an NDR request stub and returns the NDR response stub (throws on FAULT).</summary>
    public byte[] Call(ushort opnum, byte[] stub)
    {
        var request = new DcerpcRequest { Opnum = opnum, Stub = stub, CallId = _callId++ };

        if (_security is null)
        {
            return DcerpcResponse.Parse(Transceive(request.Pack())).Stub;
        }

        byte[] pdu = request.PackAuthenticated(_security, _authLevel, _authContextId);
        return DcerpcResponse.Parse(Transceive(pdu), _security, _authLevel).Stub;
    }

    /// <summary>Closes the pipe handle.</summary>
    public void Close() => _client.Close(_treeId, _fileId);
}
