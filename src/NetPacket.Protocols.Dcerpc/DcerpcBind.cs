using NetPacket.Core;

namespace NetPacket.Protocols.Dcerpc;

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

    /// <summary>Serializes the full BIND PDU (header + body).</summary>
    public byte[] Pack()
    {
        var body = new ByteWriter(ByteOrder.Little);
        body.WriteUInt16(MaxXmitFrag);
        body.WriteUInt16(MaxRecvFrag);
        body.WriteUInt32(AssocGroupId);

        // p_context_elem: one context with one transfer syntax.
        body.WriteByte(1); // n_context_elem
        body.WriteByte(0); // reserved
        body.WriteUInt16(0); // reserved2

        body.WriteUInt16(ContextId);
        body.WriteByte(1); // n_transfer_syn
        body.WriteByte(0); // reserved

        // abstract_syntax: interface UUID + version.
        body.WriteBytes(InterfaceUuid.ToByteArray());
        body.WriteUInt16(InterfaceVersionMajor);
        body.WriteUInt16(InterfaceVersionMinor);

        // transfer_syntax: NDR v2.0.
        body.WriteBytes(Dcerpc.NdrTransferSyntax.ToByteArray());
        body.WriteUInt16(Dcerpc.NdrVersionMajor);
        body.WriteUInt16(Dcerpc.NdrVersionMinor);

        byte[] bodyBytes = body.ToArray();

        var header = new DcerpcHeader
        {
            PduType = (byte)DcerpcPduType.Bind,
            CallId = CallId,
            FragLength = (ushort)(DcerpcHeader.Size + bodyBytes.Length),
        };

        var writer = new ByteWriter(ByteOrder.Little);
        writer.WriteBytes(header.Pack());
        writer.WriteBytes(bodyBytes);
        return writer.ToArray();
    }
}
