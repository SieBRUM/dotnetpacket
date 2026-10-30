using NetPacket.Core;

namespace NetPacket.Protocols.Dcerpc;

/// <summary>
/// The 8-byte DCERPC authentication verifier header (<c>sec_trailer</c>, MS-RPCE
/// 2.2.2.11 / DCE 1.1 <c>auth_verifier_co_t</c>): it precedes the auth token at the
/// end of an authenticated PDU and says which auth service and level produced it,
/// how much the stub was padded, and which security context it belongs to. Port of
/// impacket's <c>rpcrt.SEC_TRAILER</c>.
/// </summary>
public sealed class DcerpcSecTrailer
{
    public const int Size = 8;

    public byte AuthType { get; set; } = Dcerpc.AuthTypeNtlm;

    public byte AuthLevel { get; set; }

    public byte AuthPadLength { get; set; }

    public byte AuthReserved { get; set; }

    public uint AuthContextId { get; set; }

    public byte[] Pack()
    {
        var writer = new ByteWriter(ByteOrder.Little);
        writer.WriteByte(AuthType);
        writer.WriteByte(AuthLevel);
        writer.WriteByte(AuthPadLength);
        writer.WriteByte(AuthReserved);
        writer.WriteUInt32(AuthContextId);
        return writer.ToArray();
    }

    public static DcerpcSecTrailer Parse(ByteReader reader) => new()
    {
        AuthType = reader.ReadByte(),
        AuthLevel = reader.ReadByte(),
        AuthPadLength = reader.ReadByte(),
        AuthReserved = reader.ReadByte(),
        AuthContextId = reader.ReadUInt32(),
    };
}
