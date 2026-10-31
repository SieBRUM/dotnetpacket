using DotNetPacket.Core;

namespace DotNetPacket.Protocols.Dcerpc;

/// <summary>
/// Builds a DCERPC BIND PDU (DCE 1.1 / MS-RPCE 2.2.2.10) offering a single
/// presentation context: the requested abstract syntax (the target interface)
/// bound to the NDR transfer syntax. Port of impacket's <c>MSRPCBind</c>.
/// </summary>
public sealed class DcerpcBind
{
    public ushort MaxXmitFrag { get; set; } = Dcerpc.DefaultMaxFrag;

    public ushort MaxRecvFrag { get; set; } = Dcerpc.DefaultMaxFrag;

    public uint AssocGroupId { get; set; }

    public ushort ContextId { get; set; }

    public required Guid InterfaceUuid { get; init; }

    public required ushort InterfaceVersionMajor { get; init; }

    public required ushort InterfaceVersionMinor { get; init; }

    public uint CallId { get; set; } = 1;

    /// <summary>
    /// An optional alternate transfer syntax offered as a second presentation context
    /// (context id 1) for the same interface — used to probe NDR64 support (getarch).
    /// </summary>
    public Guid? SecondTransferSyntax { get; set; }

    public ushort SecondTransferVersionMajor { get; set; }

    public ushort SecondTransferVersionMinor { get; set; }

    /// <summary>Optional authentication: the sec_trailer describing the token, if any.</summary>
    public DcerpcSecTrailer? AuthTrailer { get; set; }

    /// <summary>Optional authentication token (e.g. an NTLMSSP NEGOTIATE) carried after the sec_trailer.</summary>
    public byte[]? AuthToken { get; set; }

    /// <summary>Serializes the full BIND PDU (header + body + optional auth trailer/token).</summary>
    public byte[] Pack()
    {
        var body = new ByteWriter(ByteOrder.Little);
        body.WriteUInt16(MaxXmitFrag);
        body.WriteUInt16(MaxRecvFrag);
        body.WriteUInt32(AssocGroupId);

        // p_context_elem: one context per offered transfer syntax (two when probing NDR64).
        bool twoContexts = SecondTransferSyntax is not null;
        body.WriteByte((byte)(twoContexts ? 2 : 1)); // n_context_elem
        body.WriteByte(0); // reserved
        body.WriteUInt16(0); // reserved2

        // Context 0: the interface bound to NDR v2.0.
        body.WriteUInt16(ContextId);
        body.WriteByte(1); // n_transfer_syn
        body.WriteByte(0); // reserved
        body.WriteBytes(InterfaceUuid.ToByteArray());
        body.WriteUInt16(InterfaceVersionMajor);
        body.WriteUInt16(InterfaceVersionMinor);
        body.WriteBytes(Dcerpc.NdrTransferSyntax.ToByteArray());
        body.WriteUInt16(Dcerpc.NdrVersionMajor);
        body.WriteUInt16(Dcerpc.NdrVersionMinor);

        if (twoContexts)
        {
            // Context 1: the same interface offered with the alternate transfer syntax.
            body.WriteUInt16((ushort)(ContextId + 1));
            body.WriteByte(1); // n_transfer_syn
            body.WriteByte(0); // reserved
            body.WriteBytes(InterfaceUuid.ToByteArray());
            body.WriteUInt16(InterfaceVersionMajor);
            body.WriteUInt16(InterfaceVersionMinor);
            body.WriteBytes(SecondTransferSyntax!.Value.ToByteArray());
            body.WriteUInt16(SecondTransferVersionMajor);
            body.WriteUInt16(SecondTransferVersionMinor);
        }

        byte[] bodyBytes = body.ToArray();
        byte[] token = AuthToken ?? Array.Empty<byte>();
        bool authenticated = AuthTrailer is not null && token.Length > 0;
        int authLength = authenticated ? token.Length : 0;
        int trailerLength = authenticated ? DcerpcSecTrailer.Size : 0;

        var header = new DcerpcHeader
        {
            PduType = (byte)DcerpcPduType.Bind,
            CallId = CallId,
            FragLength = (ushort)(DcerpcHeader.Size + bodyBytes.Length + trailerLength + authLength),
            AuthLength = (ushort)authLength,
        };

        var writer = new ByteWriter(ByteOrder.Little);
        writer.WriteBytes(header.Pack());
        writer.WriteBytes(bodyBytes);
        if (authenticated)
        {
            writer.WriteBytes(AuthTrailer!.Pack());
            writer.WriteBytes(token);
        }

        return writer.ToArray();
    }
}
