using System.Security.Cryptography;
using DotNetPacket.Protocols.Ntlm;
using DotNetPacket.Protocols.Smb;

namespace DotNetPacket.Protocols.Dcerpc;

/// <summary>
/// Drives the DCERPC protocol (bind, per-PDU sign/seal, call) over an
/// <see cref="IDcerpcTransport"/> — either an SMB2 named pipe (ncacn_np) or a direct
/// TCP connection (ncacn_ip_tcp). This is how impacket's DCE/RPC examples reach
/// srvsvc/lsarpc/svcctl/samr and the endpoint mapper. Supports an unauthenticated
/// bind and an NTLMSSP-authenticated bind with per-PDU packet integrity or privacy.
/// </summary>
public sealed class DcerpcPipe
{
    private readonly IDcerpcTransport _transport;
    private uint _callId = 1;

    private NtlmSecurityContext? _security;
    private DcerpcAuthLevel _authLevel = DcerpcAuthLevel.None;
    private uint _authContextId;

    public DcerpcPipe(IDcerpcTransport transport) => _transport = transport;

    /// <summary>Opens <paramref name="pipeName"/> on an IPC$ tree and wraps it as a pipe (ncacn_np).</summary>
    public static DcerpcPipe Open(Smb2Client client, uint ipcTreeId, string pipeName) =>
        new(SmbPipeTransport.Open(client, ipcTreeId, pipeName));

    /// <summary>Connects to a DCERPC endpoint directly over TCP (ncacn_ip_tcp), e.g. the mapper on 135.</summary>
    public static DcerpcPipe OverTcp(string host, int port = 135) =>
        new(new TcpDcerpcTransport(host, port));

    /// <summary>Sends one PDU and reads the reply.</summary>
    public byte[] Transceive(byte[] pdu) => _transport.Transceive(pdu);

    /// <summary>Sends one PDU with no reply expected (used for AUTH3).</summary>
    public void Send(byte[] pdu) => _transport.Send(pdu);

    /// <summary>Binds to an interface and returns the parsed BIND_ACK.</summary>
    public DcerpcBindAck Bind(DcerpcInterface iface)
    {
        var bind = new DcerpcBind
        {
            InterfaceUuid = iface.Uuid,
            InterfaceVersionMajor = iface.VersionMajor,
            InterfaceVersionMinor = iface.VersionMinor,
            CallId = _callId++,
        };

        return DcerpcBindAck.Parse(_transport.Transceive(bind.Pack()));
    }

    /// <summary>
    /// Binds with NTLMSSP authentication and establishes per-PDU protection at
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

        DcerpcBindAck ack = DcerpcBindAck.Parse(_transport.Transceive(bind.Pack()));
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
        _transport.Send(auth3.Pack());

        _security = new NtlmSecurityContext(auth.SessionKey);
        return ack;
    }

    /// <summary>Invokes an opnum with an NDR request stub and returns the NDR response stub (throws on FAULT).</summary>
    public byte[] Call(ushort opnum, byte[] stub)
    {
        var request = new DcerpcRequest { Opnum = opnum, Stub = stub, CallId = _callId++ };

        if (_security is null)
        {
            return DcerpcResponse.Parse(_transport.Transceive(request.Pack())).Stub;
        }

        byte[] pdu = request.PackAuthenticated(_security, _authLevel, _authContextId);
        return DcerpcResponse.Parse(_transport.Transceive(pdu), _security, _authLevel).Stub;
    }

    /// <summary>Closes the underlying transport.</summary>
    public void Close() => _transport.Close();
}
