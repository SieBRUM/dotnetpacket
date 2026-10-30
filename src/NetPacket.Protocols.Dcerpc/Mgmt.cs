namespace NetPacket.Protocols.Dcerpc;

/// <summary>One entry of an RPC interface-id vector: an interface's abstract-syntax UUID and version.</summary>
public sealed record DcerpcInterfaceId(Guid Uuid, ushort VersionMajor, ushort VersionMinor)
{
    /// <summary>The well-known interface name for this UUID, or null if not recognised.</summary>
    public string? Name => DcerpcInterface.NameOf(Uuid);

    public override string ToString() =>
        $"{Uuid} v{VersionMajor}.{VersionMinor}{(Name is null ? string.Empty : $"  ({Name})")}";
}

/// <summary>
/// The DCE remote-management interface (rpc_mgmt). Port of the slice of impacket's
/// <c>dcerpc.v5.mgmt</c> used by <c>rpcdump.py</c>: enumerate the interface ids
/// registered on an endpoint (<c>rpc_mgmt_inq_if_ids</c>, opnum 0). The pipe must
/// already be bound to the mgmt interface.
/// </summary>
public static class Mgmt
{
    private const ushort OpnumInqIfIds = 0;

    /// <summary>
    /// Calls rpc_mgmt_inq_if_ids and returns the registered interface ids. Response NDR:
    /// a unique pointer to a conformant <c>rpc_if_id_vector_t</c> (max_count, count, then
    /// a unique pointer per entry), the deferred <c>rpc_if_id_t</c> structs (uuid + major +
    /// minor), and a trailing error_status.
    /// </summary>
    public static IReadOnlyList<DcerpcInterfaceId> InquireInterfaceIds(DcerpcPipe pipe)
    {
        byte[] stub = pipe.Call(OpnumInqIfIds, Array.Empty<byte>());
        var reader = new NdrReader(stub);

        if (reader.ReadReferent() == 0)
        {
            return Array.Empty<DcerpcInterfaceId>();
        }

        reader.ReadUInt32();              // conformant max_count
        uint count = reader.ReadUInt32(); // count

        var present = new bool[count];
        for (uint i = 0; i < count; i++)
        {
            present[i] = reader.ReadReferent() != 0;
        }

        var result = new List<DcerpcInterfaceId>((int)count);
        for (uint i = 0; i < count; i++)
        {
            if (!present[i])
            {
                continue;
            }

            byte[] uuid = reader.ReadBytes(16);
            ushort major = reader.ReadUInt16();
            ushort minor = reader.ReadUInt16();
            result.Add(new DcerpcInterfaceId(new Guid(uuid), major, minor));
        }

        return result;
    }
}
