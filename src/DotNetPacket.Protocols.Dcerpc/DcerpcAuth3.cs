using DotNetPacket.Core;

namespace DotNetPacket.Protocols.Dcerpc;

/// <summary>
/// Builds a DCERPC AUTH3 PDU (DCE 1.1 / MS-RPCE 2.2.2.10): the third leg of an
/// authenticated bind, carrying the final auth token (an NTLMSSP AUTHENTICATE) in
/// its trailer. It elicits no reply. Port of impacket's <c>MSRPCHeader</c> used for
/// <c>rpc_auth_3</c>.
/// </summary>
public sealed class DcerpcAuth3
{
    public uint CallId { get; set; } = 1;

    public required DcerpcSecTrailer AuthTrailer { get; init; }

    public required byte[] AuthToken { get; init; }

    public byte[] Pack()
    {
        var header = new DcerpcHeader
        {
            PduType = (byte)DcerpcPduType.Auth3,
            CallId = CallId,
            FragLength = (ushort)(DcerpcHeader.Size + 4 + DcerpcSecTrailer.Size + AuthToken.Length),
            AuthLength = (ushort)AuthToken.Length,
        };

        var writer = new ByteWriter(ByteOrder.Little);
        writer.WriteBytes(header.Pack());
        writer.WriteUInt32(0); // pad (max_xmit/max_recv placeholder; ignored by the server)
        writer.WriteBytes(AuthTrailer.Pack());
        writer.WriteBytes(AuthToken);
        return writer.ToArray();
    }
}
