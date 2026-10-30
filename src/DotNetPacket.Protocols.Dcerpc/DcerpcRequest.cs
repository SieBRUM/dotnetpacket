using DotNetPacket.Core;
using DotNetPacket.Protocols.Ntlm;

namespace DotNetPacket.Protocols.Dcerpc;

/// <summary>Builds a DCERPC REQUEST PDU (DCE 1.1 / MS-RPCE 2.2.2.13): a call to one opnum with an NDR stub.</summary>
public sealed class DcerpcRequest
{
    public ushort ContextId { get; set; }

    public required ushort Opnum { get; init; }

    public required byte[] Stub { get; init; }

    public uint CallId { get; set; } = 1;

    /// <summary>Serializes an unauthenticated REQUEST PDU.</summary>
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

    /// <summary>
    /// Serializes an authenticated REQUEST PDU: the stub is padded to a 4-byte boundary,
    /// an auth verifier (sec_trailer + 16-byte signature) is appended, and the context
    /// signs the whole PDU (minus the verifier) and — at packet-privacy level — seals the
    /// stub body only. This "sign the whole PDU, seal just the stub" split is the NTLM2
    /// DCERPC behavior (impacket <c>rpcrt._transport_send</c>).
    /// </summary>
    public byte[] PackAuthenticated(NtlmSecurityContext context, DcerpcAuthLevel level, uint authContextId)
    {
        bool seal = level == DcerpcAuthLevel.PacketPrivacy;
        int sigSize = NtlmSecurityContext.SignatureLength;

        int padLength = (4 - (Stub.Length % 4)) % 4;
        byte[] plainData = new byte[Stub.Length + padLength];
        Array.Copy(Stub, plainData, Stub.Length);
        for (int i = Stub.Length; i < plainData.Length; i++)
        {
            plainData[i] = 0xBB; // auth pad fill (ignored on receipt; matches impacket)
        }

        byte[] trailerBytes = new DcerpcSecTrailer
        {
            AuthLevel = (byte)level,
            AuthPadLength = (byte)padLength,
            AuthContextId = authContextId,
        }.Pack();

        var header = new DcerpcHeader
        {
            PduType = (byte)DcerpcPduType.Request,
            CallId = CallId,
            FragLength = (ushort)(DcerpcHeader.Size + 8 + plainData.Length + DcerpcSecTrailer.Size + sigSize),
            AuthLength = (ushort)sigSize,
        };

        var pre = new ByteWriter(ByteOrder.Little);
        pre.WriteBytes(header.Pack());
        pre.WriteUInt32((uint)plainData.Length); // alloc_hint = stub + pad
        pre.WriteUInt16(ContextId);
        pre.WriteUInt16(Opnum);
        byte[] preBytes = pre.ToArray();

        // The signature covers the whole PDU except its own 16 bytes.
        byte[] toSign = Concat(preBytes, plainData, trailerBytes);
        (byte[] sealedData, byte[] signature) = context.Wrap(toSign, seal ? plainData : null);

        var writer = new ByteWriter(ByteOrder.Little);
        writer.WriteBytes(preBytes);
        writer.WriteBytes(seal ? sealedData : plainData);
        writer.WriteBytes(trailerBytes);
        writer.WriteBytes(signature);
        return writer.ToArray();
    }

    private static byte[] Concat(params byte[][] parts)
    {
        var result = new byte[parts.Sum(p => p.Length)];
        int offset = 0;
        foreach (byte[] part in parts)
        {
            Array.Copy(part, 0, result, offset, part.Length);
            offset += part.Length;
        }

        return result;
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

    /// <summary>Parses an unauthenticated RESPONSE PDU (or one whose auth data is ignored).</summary>
    public static DcerpcResponse Parse(byte[] pdu) => Parse(pdu, null, DcerpcAuthLevel.None);

    /// <summary>
    /// Parses a RESPONSE PDU. When a security <paramref name="context"/> is supplied, the
    /// trailing auth verifier is used to unseal (at packet privacy) and verify the stub,
    /// and the auth pad is stripped. Throws on FAULT.
    /// </summary>
    public static DcerpcResponse Parse(byte[] pdu, NtlmSecurityContext? context, DcerpcAuthLevel level)
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

        if (context is null || header.AuthLength == 0)
        {
            int plainLength = header.FragLength - stubStart - header.AuthLength;
            return new DcerpcResponse { Stub = pdu[stubStart..(stubStart + plainLength)] };
        }

        // Authenticated: [stub+pad][sec_trailer(8)][signature(AuthLength)].
        int trailerStart = header.FragLength - header.AuthLength - DcerpcSecTrailer.Size;
        int sigStart = trailerStart + DcerpcSecTrailer.Size;
        byte[] stubAndPad = pdu[stubStart..trailerStart];
        byte[] trailerBytes = pdu[trailerStart..sigStart];
        byte[] signature = pdu[sigStart..header.FragLength];

        var trailerReader = new ByteReader(trailerBytes, ByteOrder.Little);
        DcerpcSecTrailer trailer = DcerpcSecTrailer.Parse(trailerReader);

        // At packet privacy the stub body is sealed; decrypt it first (advancing the
        // handle), then verify the signature over the whole PDU (with the decrypted
        // stub) minus the verifier — mirroring how the server produced it.
        bool seal = level == DcerpcAuthLevel.PacketPrivacy;
        byte[] plain = seal ? context.Unseal(stubAndPad) : stubAndPad;

        byte[] signedRegion = Concat(pdu[..stubStart], plain, trailerBytes);
        context.Verify(signedRegion, signature);

        int stubLength = plain.Length - trailer.AuthPadLength;
        return new DcerpcResponse { Stub = plain[..stubLength] };
    }

    private static byte[] Concat(params byte[][] parts)
    {
        var result = new byte[parts.Sum(p => p.Length)];
        int offset = 0;
        foreach (byte[] part in parts)
        {
            Array.Copy(part, 0, result, offset, part.Length);
            offset += part.Length;
        }

        return result;
    }
}
