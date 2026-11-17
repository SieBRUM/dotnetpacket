using DotNetPacket.Protocols.Smb;

namespace DotNetPacket.Protocols.Dcerpc;

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

    /// <summary>
    /// Reads one further response PDU from the pipe (SMB2 READ), to reassemble a fragmented
    /// response. Reads the 16-byte common header, then the remainder per <c>frag_length</c>.
    /// </summary>
    public byte[] Receive()
    {
        byte[] header = ReadExactly(DcerpcHeader.Size);
        var reader = new DotNetPacket.Core.ByteReader(header, DotNetPacket.Core.ByteOrder.Little);
        var parsed = new DcerpcHeader();
        parsed.Unpack(reader);

        int remaining = parsed.FragLength - DcerpcHeader.Size;
        if (remaining < 0)
        {
            throw new InvalidDataException($"DCERPC frag_length {parsed.FragLength} is smaller than the header.");
        }

        byte[] body = ReadExactly(remaining);
        var pdu = new byte[header.Length + body.Length];
        Array.Copy(header, 0, pdu, 0, header.Length);
        Array.Copy(body, 0, pdu, header.Length, body.Length);
        return pdu;
    }

    private byte[] ReadExactly(int count)
    {
        var buffer = new byte[count];
        int offset = 0;
        while (offset < count)
        {
            Smb2ReadResult result = _client.Read(_treeId, _fileId, 0, count - offset);
            if (!result.Succeeded && result.Status != NtStatus.BufferOverflow)
            {
                throw new IOException($"Pipe read failed: {NtStatus.Describe(result.Status)}");
            }

            if (result.Data.Length == 0)
            {
                throw new IOException("Pipe read returned no data mid-PDU.");
            }

            Array.Copy(result.Data, 0, buffer, offset, Math.Min(result.Data.Length, count - offset));
            offset += result.Data.Length;
        }

        return buffer;
    }

    public void Send(byte[] pdu) => _client.Write(_treeId, _fileId, 0, pdu);

    public void Close() => _client.Close(_treeId, _fileId);
}
