using System.Text;
using DotNetPacket.Core;

namespace DotNetPacket.Protocols.Dcerpc;

/// <summary>
/// Parses a DCERPC BIND_ACK / BIND_NAK PDU (DCE 1.1 / MS-RPCE 2.2.2.11) and
/// exposes whether the presentation context was accepted.
/// </summary>
public sealed class DcerpcBindAck
{
    /// <summary>Context negotiation result: 0 = acceptance, 1 = user rejection, 2 = provider rejection.</summary>
    public enum ContextResult : ushort
    {
        Acceptance = 0,
        UserRejection = 1,
        ProviderRejection = 2,
    }

    public DcerpcPduType PduType { get; private set; }

    public ushort MaxXmitFrag { get; private set; }

    public ushort MaxRecvFrag { get; private set; }

    public uint AssocGroupId { get; private set; }

    public string SecondaryAddress { get; private set; } = string.Empty;

    public ContextResult Result { get; private set; }

    public ushort Reason { get; private set; }

    /// <summary>Per-presentation-context results, in order (one entry per offered context).</summary>
    public IReadOnlyList<(ContextResult Result, ushort Reason)> Results { get; private set; } =
        Array.Empty<(ContextResult, ushort)>();

    /// <summary>The authentication token (e.g. an NTLMSSP CHALLENGE) from the trailing auth verifier, if any.</summary>
    public byte[] AuthValue { get; private set; } = Array.Empty<byte>();

    public bool Accepted => PduType == DcerpcPduType.BindAck && Result == ContextResult.Acceptance;

    public static DcerpcBindAck Parse(byte[] pdu)
    {
        var reader = new ByteReader(pdu, ByteOrder.Little);

        var header = new DcerpcHeader();
        header.Unpack(reader); // consumes the 16-byte header

        var ack = new DcerpcBindAck { PduType = (DcerpcPduType)header.PduType };

        // The auth token, when present, is the trailing AuthLength bytes of the PDU
        // (the sec_trailer sits just before it); extract it independently of the
        // context-list parsing below.
        if (header.AuthLength > 0 && header.FragLength <= pdu.Length)
        {
            int tokenStart = header.FragLength - header.AuthLength;
            ack.AuthValue = pdu[tokenStart..header.FragLength];
        }

        if (ack.PduType != DcerpcPduType.BindAck)
        {
            return ack; // BIND_NAK or unexpected — nothing more to parse reliably
        }

        ack.MaxXmitFrag = reader.ReadUInt16();
        ack.MaxRecvFrag = reader.ReadUInt16();
        ack.AssocGroupId = reader.ReadUInt32();

        ushort secAddrLength = reader.ReadUInt16();
        if (secAddrLength > 0)
        {
            byte[] secAddr = reader.ReadBytes(secAddrLength);
            ack.SecondaryAddress = Encoding.ASCII.GetString(secAddr).TrimEnd('\0');
        }

        // p_result_list is 4-byte aligned from the start of the PDU.
        int padding = (4 - (reader.Position % 4)) % 4;
        reader.Position += padding;

        byte resultCount = reader.ReadByte();
        reader.ReadByte();   // reserved
        reader.ReadUInt16(); // reserved2

        var results = new List<(ContextResult, ushort)>(resultCount);
        for (int i = 0; i < resultCount; i++)
        {
            var result = (ContextResult)reader.ReadUInt16();
            ushort reason = reader.ReadUInt16();
            reader.Position += 20; // transfer_syntax (UUID + version) for this context
            results.Add((result, reason));
        }

        ack.Results = results;
        if (resultCount > 0)
        {
            ack.Result = results[0].Item1; // first context, for the single-context callers
            ack.Reason = results[0].Item2;
        }

        return ack;
    }
}
