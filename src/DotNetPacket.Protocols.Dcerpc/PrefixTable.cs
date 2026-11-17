namespace DotNetPacket.Protocols.Dcerpc;

/// <summary>
/// A DRSUAPI schema prefix table (MS-DRSR 5.177 SCHEMA_PREFIX_TABLE) with ATTRTYP conversion,
/// ported from impacket's <c>drsuapi.MakeAttid</c> (section 5.16.4). An attribute OID is split
/// into a BER prefix (interned in this table, yielding an index) and a final arc; the two are
/// packed into a 32-bit ATTRTYP. A GetNCChanges request carries this table so the DC can map the
/// compact ATTRTYP ids back to attribute OIDs.
/// </summary>
public sealed class PrefixTable
{
    private readonly List<byte[]> _prefixes = new();

    /// <summary>The number of distinct OID prefixes interned so far.</summary>
    public int Count => _prefixes.Count;

    /// <summary>
    /// Converts a dotted OID into an ATTRTYP, interning its BER prefix (MS-DRSR 5.16.4 MakeAttid).
    /// </summary>
    public uint MakeAttid(string oid)
    {
        int lastDot = oid.LastIndexOf('.');
        uint lastValue = uint.Parse(oid[(lastDot + 1)..]);

        byte[] binaryOid = EncodeOidContents(oid);
        // The final arc occupies 1 BER byte when < 128, otherwise 2 (base-128 continuation).
        int prefixLen = lastValue < 128 ? binaryOid.Length - 1 : binaryOid.Length - 2;
        byte[] prefix = binaryOid[..prefixLen];

        int pos = IndexOfPrefix(prefix);
        if (pos < 0)
        {
            pos = _prefixes.Count;
            _prefixes.Add(prefix);
        }

        uint lowerWord = lastValue % 16384;
        if (lastValue >= 16384)
        {
            lowerWord += 32768; // mark that lowerWord is not the whole final arc
        }

        return ((uint)pos << 16) + lowerWord;
    }

    /// <summary>Writes the prefix table as a PrefixTableEntry conformant array (deferred pointee).</summary>
    public void Write(NdrWriter ndr)
    {
        if (_prefixes.Count == 0)
        {
            return;
        }

        ndr.WriteUInt32((uint)_prefixes.Count); // array conformant max_count
        for (int i = 0; i < _prefixes.Count; i++)
        {
            ndr.WriteUInt32((uint)i);                      // ndx
            ndr.WriteUInt32((uint)_prefixes[i].Length);    // prefix.length (OID_t)
            ndr.WriteReferent(true);                       // prefix.elements pointer
        }

        foreach (byte[] prefix in _prefixes)
        {
            ndr.WriteUInt32((uint)prefix.Length);          // BYTE_ARRAY conformant max_count
            ndr.WriteBytes(prefix);                        // elements
            ndr.Align(4);
        }
    }

    private int IndexOfPrefix(byte[] prefix)
    {
        for (int i = 0; i < _prefixes.Count; i++)
        {
            if (_prefixes[i].AsSpan().SequenceEqual(prefix))
            {
                return i;
            }
        }

        return -1;
    }

    /// <summary>BER content octets (without tag/length) of a dotted OID — impacket's encode(...)[2:].</summary>
    public static byte[] EncodeOidContents(string oid)
    {
        string[] parts = oid.Split('.');
        var arcs = new uint[parts.Length];
        for (int i = 0; i < parts.Length; i++)
        {
            arcs[i] = uint.Parse(parts[i]);
        }

        var output = new List<byte> { (byte)(40 * arcs[0] + arcs[1]) };
        for (int i = 2; i < arcs.Length; i++)
        {
            output.AddRange(Base128(arcs[i]));
        }

        return output.ToArray();
    }

    private static byte[] Base128(uint value)
    {
        if (value < 128)
        {
            return new[] { (byte)value };
        }

        var stack = new Stack<byte>();
        stack.Push((byte)(value & 0x7F)); // last byte has no continuation bit
        value >>= 7;
        while (value > 0)
        {
            stack.Push((byte)((value & 0x7F) | 0x80));
            value >>= 7;
        }

        return stack.ToArray();
    }
}
