using NetPacket.Protocols.Smb;

namespace NetPacket.Protocols.Dcerpc;

/// <summary>
/// DCERPC transport over an SMB2 named pipe (ncacn_np): opens a pipe on the IPC$
/// tree, then exchanges PDUs with SMB2 WRITE + READ. This is how impacket's
/// DCE/RPC examples reach srvsvc/lsarpc/svcctl/samr and friends.
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

    /// <summary>Invokes an opnum with an NDR request stub and returns the NDR response stub (throws on FAULT).</summary>
    public byte[] Call(ushort opnum, byte[] stub)
    {
        var request = new DcerpcRequest { Opnum = opnum, Stub = stub, CallId = _callId++ };
        byte[] responsePdu = Transceive(request.Pack());
        return DcerpcResponse.Parse(responsePdu).Stub;
    }

    /// <summary>Closes the pipe handle.</summary>
    public void Close() => _client.Close(_treeId, _fileId);
}
