using System.Security.Cryptography;
using DotNetPacket.Protocols.Krb5;
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
    private KerberosDcerpcSecurity? _kerberos;
    private DcerpcAuthLevel _authLevel = DcerpcAuthLevel.None;
    private uint _authContextId;
    private byte[]? _sessionKey;

    public DcerpcPipe(IDcerpcTransport transport) => _transport = transport;

    /// <summary>
    /// The NTLMSSP exported session key negotiated by the authenticated bind (null until
    /// <see cref="BindAuthenticated"/> succeeds). This is the key MS-DRSR uses to decrypt
    /// ENCRYPTED_PAYLOAD attribute values during replication (DCSync) — the DCERPC sign/seal
    /// session key, NOT any SMB session key.
    /// </summary>
    public byte[]? SessionKey => _sessionKey;

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
    /// Binds offering a second presentation context with an alternate transfer syntax
    /// (e.g. NDR64) and returns the BIND_ACK with its per-context result list — the
    /// getarch probe. The server accepts the syntaxes it supports and rejects the rest.
    /// </summary>
    public DcerpcBindAck BindProbe(DcerpcInterface iface, Guid secondSyntax, ushort major, ushort minor)
    {
        var bind = new DcerpcBind
        {
            InterfaceUuid = iface.Uuid,
            InterfaceVersionMajor = iface.VersionMajor,
            InterfaceVersionMinor = iface.VersionMinor,
            CallId = _callId++,
            SecondTransferSyntax = secondSyntax,
            SecondTransferVersionMajor = major,
            SecondTransferVersionMinor = minor,
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
        _sessionKey = auth.SessionKey;
        return ack;
    }

    /// <summary>
    /// Binds with Kerberos (RPC_C_AUTHN_GSS_NEGOTIATE) using <paramref name="ticket"/>, at
    /// <paramref name="level"/>, via the DCE-style three-leg handshake: BIND carries a DCE-style GSS
    /// AP-REQ; BIND_ACK returns the AP-REP; the ALTER_CONTEXT returns the mutual-auth completion token.
    /// After this, <see cref="Call"/> seals/signs each request with the AP-REP acceptor subkey.
    /// </summary>
    public DcerpcBindAck BindKerberos(DcerpcInterface iface, ServiceTicket ticket, DcerpcAuthLevel level)
    {
        _authLevel = level;
        _authContextId = BitConverter.ToUInt32(RandomNumberGenerator.GetBytes(4), 0);

        KerberosApReq apReq = KerberosGss.BuildApReqToken(ticket, mutualAuth: true, gssFlags: KerberosGss.DcerpcGssFlags);
        byte[] spnegoInit = Spnego.WrapKerberosInitialToken(apReq.GssToken);

        uint bindCallId = _callId++;
        var bind = new DcerpcBind
        {
            InterfaceUuid = iface.Uuid,
            InterfaceVersionMajor = iface.VersionMajor,
            InterfaceVersionMinor = iface.VersionMinor,
            CallId = bindCallId,
            AuthTrailer = new DcerpcSecTrailer
            {
                AuthType = Dcerpc.AuthTypeGssNegotiate,
                AuthLevel = (byte)level,
                AuthContextId = _authContextId,
            },
            AuthToken = spnegoInit,
        };

        DcerpcBindAck ack = DcerpcBindAck.Parse(_transport.Transceive(bind.Pack()));
        if (!ack.Accepted || ack.AuthValue.Length == 0)
        {
            return ack;
        }

        // Process the AP-REP and build the third-leg (ALTER_CONTEXT) completion token.
        byte[] apRepToken = Spnego.ExtractResponseToken(ack.AuthValue);
        KerberosApRep.DceApRep dce = KerberosApRep.ProcessDceApRep(apRepToken, ticket.SessionKey, ticket.SessionKeyEtype);

        // The GSS context is keyed on the AP-REP acceptor subkey. The ALTER_CONTEXT carries the SPNEGO
        // mechListMIC (GSS MIC over the offered MechTypeList) — the first per-message token (seq 0), so
        // data messages start at seq 1.
        // The GSS context is keyed on the AP-REP acceptor subkey. Samba's strict SPNEGO requires the
        // client to send a mechListMIC (a GSS MIC over the offered MS-KRB5 MechTypeList) in the
        // ALTER_CONTEXT to complete the context — it is the first per-message token (seq 0), so data
        // messages start at seq 1.
        _kerberos = new KerberosDcerpcSecurity(dce.Subkey.Key, dce.Subkey.Etype);
        byte[] mechListMic = _kerberos.GetMic(Spnego.KerberosMechListDer());

        var alter = new DcerpcBind
        {
            InterfaceUuid = iface.Uuid,
            InterfaceVersionMajor = iface.VersionMajor,
            InterfaceVersionMinor = iface.VersionMinor,
            CallId = bindCallId,
            PduType = DcerpcPduType.AlterContext,
            AuthTrailer = new DcerpcSecTrailer
            {
                AuthType = Dcerpc.AuthTypeGssNegotiate,
                AuthLevel = (byte)level,
                AuthContextId = _authContextId,
            },
            AuthToken = Spnego.WrapResponseToken(dce.AltContextApRep, mechListMic),
        };

        _transport.Transceive(alter.Pack()); // ALTER_CONTEXT_RESP — context accepted
        _sessionKey = dce.Subkey.Key;
        return ack;
    }

    /// <summary>
    /// Invokes an opnum with an NDR request stub and returns the NDR response stub (throws on FAULT).
    /// A response larger than the server's fragment size arrives as several PDUs (PFC_FIRST_FRAG …
    /// PFC_LAST_FRAG); they are read and their stub bodies concatenated until the last fragment, with
    /// each fragment independently unsealed/verified (as the server sealed it).
    /// </summary>
    public byte[] Call(ushort opnum, byte[] stub)
    {
        var request = new DcerpcRequest { Opnum = opnum, Stub = stub, CallId = _callId++ };
        byte[] pdu = _kerberos is not null
            ? request.PackKerberos(_kerberos, _authLevel, _authContextId)
            : _security is null
                ? request.Pack()
                : request.PackAuthenticated(_security, _authLevel, _authContextId);

        DcerpcResponse first = ParseResponse(_transport.Transceive(pdu));
        if (first.IsLastFragment)
        {
            return first.Stub;
        }

        // Reassemble a fragmented response: keep reading PDUs until PFC_LAST_FRAG.
        var assembled = new List<byte>(first.Stub);
        while (true)
        {
            DcerpcResponse next = ParseResponse(_transport.Receive());
            assembled.AddRange(next.Stub);
            if (next.IsLastFragment)
            {
                return assembled.ToArray();
            }
        }
    }

    private DcerpcResponse ParseResponse(byte[] pdu) => _kerberos is not null
        ? DcerpcResponse.ParseKerberos(pdu, _kerberos, _authLevel)
        : DcerpcResponse.Parse(pdu, _security, _authLevel);

    /// <summary>Closes the underlying transport.</summary>
    public void Close() => _transport.Close();
}
