using NetPacket.Core;

namespace NetPacket.Protocols.Ntlm;

/// <summary>
/// An ordered NTLMv2 AV_PAIR target-info list (MS-NLMP 2.2.2.1): a sequence of
/// (id, value) pairs terminated by an EOL pair. The client echoes the server's
/// list back inside its NTLMv2 response, optionally adding pairs (e.g. the MIC
/// flag), so this type both parses and rebuilds the list.
/// </summary>
public sealed class AvPairs
{
    private readonly List<(NtlmAvId Id, byte[] Value)> _pairs = new();

    public static AvPairs Parse(byte[] data)
    {
        var result = new AvPairs();
        var reader = new ByteReader(data, ByteOrder.Little);
        while (reader.Remaining >= 4)
        {
            var id = (NtlmAvId)reader.ReadUInt16();
            int length = reader.ReadUInt16();
            byte[] value = reader.ReadBytes(length);
            if (id == NtlmAvId.EOL)
            {
                break;
            }

            result._pairs.Add((id, value));
        }

        return result;
    }

    public byte[]? Get(NtlmAvId id)
    {
        foreach ((NtlmAvId pairId, byte[] value) in _pairs)
        {
            if (pairId == id)
            {
                return value;
            }
        }

        return null;
    }

    /// <summary>Adds or replaces a pair, preserving order (new pairs append before EOL).</summary>
    public void Set(NtlmAvId id, byte[] value)
    {
        for (int i = 0; i < _pairs.Count; i++)
        {
            if (_pairs[i].Id == id)
            {
                _pairs[i] = (id, value);
                return;
            }
        }

        _pairs.Add((id, value));
    }

    public byte[] ToArray()
    {
        var writer = new ByteWriter(ByteOrder.Little);
        foreach ((NtlmAvId id, byte[] value) in _pairs)
        {
            writer.WriteUInt16((ushort)id);
            writer.WriteUInt16((ushort)value.Length);
            writer.WriteBytes(value);
        }

        writer.WriteUInt16((ushort)NtlmAvId.EOL);
        writer.WriteUInt16(0);
        return writer.ToArray();
    }
}
