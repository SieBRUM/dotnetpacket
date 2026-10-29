using NetPacket.Core;

namespace NetPacket.Protocols.Dcerpc;

/// <summary>Builds a DCERPC REQUEST PDU (DCE 1.1 / MS-RPCE 2.2.2.13): a call to one opnum with an NDR stub.</summary>
public sealed class DcerpcRequest
{
    public ushort ContextId { get; set; }

    public required ushort Opnum { get; init; }

    public required byte[] Stub { get; init; }

    public uint CallId { get; set; } = 1;

    public byte[] Pack()
    {
        var header = new DcerpcHeader
        {
            PduType = (byte)DcerpcPduType.Request,
            CallId = CallId,
            FragLength = (ushort)(DcerpcHeader.Size + 8 + Stub.Length),
        };

        var writer = new ByteWriter(ByteOrder.Little);
        writer.WriteBytes(header.Pack());
        writer.WriteUInt32((uint)Stub.Length); // alloc_hint
        writer.WriteUInt16(ContextId);
        writer.WriteUInt16(Opnum);
        writer.WriteBytes(Stub);
        return writer.ToArray();
    }
}

/// <summary>Thrown when the server returns a DCERPC FAULT PDU.</summary>
public sealed class DcerpcFaultException : Exception
{
    public DcerpcFaultException(uint status)
        : base($"DCERPC fault: 0x{status:X8}")
    {
        Status = status;
    }

    public uint Status { get; }
}

/// <summary>Parses a DCERPC RESPONSE PDU and exposes the NDR stub; throws on FAULT.</summary>
public sealed class DcerpcResponse
{
    public required byte[] Stub { get; init; }

    public static DcerpcResponse Parse(byte[] pdu)
    {
        var reader = new ByteReader(pdu, ByteOrder.Little);
        var header = new DcerpcHeader();
        header.Unpack(reader);

        if ((DcerpcPduType)header.PduType == DcerpcPduType.Fault)
        {
            reader.ReadUInt32(); // alloc_hint
            reader.ReadUInt16(); // cont_id
            reader.ReadByte();   // cancel_count
            reader.ReadByte();   // reserved
            uint status = reader.ReadUInt32();
            throw new DcerpcFaultException(status);
        }

        if ((DcerpcPduType)header.PduType != DcerpcPduType.Response)
        {
            throw new InvalidDataException($"Expected RESPONSE PDU but got {(DcerpcPduType)header.PduType}.");
        }

        reader.ReadUInt32(); // alloc_hint
        reader.ReadUInt16(); // p_cont_id
        reader.ReadByte();   // cancel_count
        reader.ReadByte();   // reserved

        int stubStart = reader.Position;
        int stubLength = header.FragLength - stubStart - header.AuthLength;
        var stub = new byte[stubLength];
        Array.Copy(pdu, stubStart, stub, 0, stubLength);
        return new DcerpcResponse { Stub = stub };
    }
}
