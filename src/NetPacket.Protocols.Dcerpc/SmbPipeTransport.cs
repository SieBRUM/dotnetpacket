using NetPacket.Protocols.Smb;

namespace NetPacket.Protocols.Dcerpc;

/// <summary>
/// DCERPC over an SMB2 named pipe (ncacn_np): PDUs ride FSCTL_PIPE_TRANSCEIVE
/// (request+reply) or an SMB2 WRITE (no reply). This is how impacket's DCE/RPC
/// examples reach srvsvc/lsarpc/svcctl/samr over IPC$.
/// </summary>
public sealed class SmbPipeTransport : IDcerpcTransport
{
    // A named-pipe open: read + write + the usual attribute/control bits (matches
    // the access a Windows client requests for an RPC pipe).
    private const Smb2AccessMask PipeAccess = (Smb2AccessMask)0x0012019F;

    private readonly Smb2Client _client;
    private readonly uint _treeId;
    private readonly byte[] _fileId;

    private SmbPipeTransport(Smb2Client client, uint treeId, byte[] fileId)
    {
        _client = client;
        _treeId = treeId;
        _fileId = fileId;
    }

    /// <summary>Opens <paramref name="pipeName"/> (e.g. "srvsvc") on an already-connected IPC$ tree.</summary>
    public static SmbPipeTransport Open(Smb2Client client, uint ipcTreeId, string pipeName)
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

        return new SmbPipeTransport(client, ipcTreeId, create.Response.FileId);
    }

    public byte[] Transceive(byte[] pdu)
    {
        Smb2IoctlResult result = _client.Ioctl(_treeId, _fileId, Fsctl.PipeTransceive, pdu);
        if (!result.Succeeded)
        {
            throw new IOException($"Pipe transceive failed: {NtStatus.Describe(result.Status)}");
        }

        return result.Output;
    }

    public void Send(byte[] pdu) => _client.Write(_treeId, _fileId, 0, pdu);

    public void Close() => _client.Close(_treeId, _fileId);
}
