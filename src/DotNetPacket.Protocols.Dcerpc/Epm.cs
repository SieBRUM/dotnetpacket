using DotNetPacket.Core;

namespace DotNetPacket.Protocols.Dcerpc;

/// <summary>A resolved endpoint-mapper result: the protocol binding an interface listens on.</summary>
public sealed record EpmMapResult(string Protocol, string Address, int Port)
{
    public override string ToString() => $"{Protocol}:{Address}[{Port}]";
}

/// <summary>
/// The endpoint mapper (EPM, MS-RPCE 2.2.1.2.5). Port of the <c>ept_map</c> slice of
/// impacket's <c>dcerpc.v5.epm</c>: ask the mapper on TCP/135 which dynamic port an
/// interface is listening on. The request and response carry DCE protocol towers
/// (a floor stack: interface UUID, NDR, RPC protocol, port, host); this builds the
/// request tower and reads the port out of the returned one. The pipe must already
/// be bound to the epm interface.
/// </summary>
public static class Epm
{
    private const ushort OpnumEptMap = 3;

    // Tower floor protocol identifiers (DCE / MS-RPCE Appendix I / C706).
    private const byte FloorUuid = 0x0D;       // UUID-derived (interface or transfer syntax)
    private const byte FloorRpcConnOriented = 0x0B;
    private const byte FloorTcp = 0x07;
    private const byte FloorIp = 0x09;

    private static readonly Guid NdrSyntax = new("8a885d04-1ceb-11c9-9fe8-08002b104860");

    /// <summary>
    /// Maps an interface to the ncacn_ip_tcp endpoint it listens on (ept_map, opnum 3),
    /// returning the first tower the mapper reports, or null if it reports none.
    /// </summary>
    public static EpmMapResult? MapTcp(DcerpcPipe pipe, DcerpcInterface iface)
    {
        byte[] tower = BuildTcpTower(iface);

        var ndr = new NdrWriter();
        ndr.WriteReferent(true);            // object pointer (nil UUID follows)
        ndr.WriteBytes(new byte[16]);       // nil object UUID
        ndr.WriteReferent(true);            // map_tower pointer
        ndr.WriteUInt32((uint)tower.Length); // conformant max_count
        ndr.WriteUInt32((uint)tower.Length); // tower_length
        ndr.WriteBytes(tower);
        ndr.Align(4);
        ndr.WriteContextHandle(new byte[20]); // entry_handle (nil)
        ndr.WriteUInt32(1);                   // max_towers

        byte[] stub = pipe.Call(OpnumEptMap, ndr.ToArray());
        return ParseFirstTower(stub);
    }

    /// <summary>Parses an ept_map response and returns the endpoint from its first returned tower.</summary>
    public static EpmMapResult? ParseFirstTower(byte[] stub)
    {
        var reader = new NdrReader(stub);
        reader.ReadContextHandle();         // entry_handle (out)
        uint numTowers = reader.ReadUInt32();
        if (numTowers == 0)
        {
            return null;
        }

        reader.ReadUInt32();                // ITowers max_count
        reader.ReadUInt32();                // offset
        uint actualCount = reader.ReadUInt32();

        var present = new bool[actualCount];
        for (uint i = 0; i < actualCount; i++)
        {
            present[i] = reader.ReadReferent() != 0;
        }

        for (uint i = 0; i < actualCount; i++)
        {
            if (!present[i])
            {
                continue;
            }

            reader.ReadUInt32();            // twr_t conformant max_count
            uint towerLength = reader.ReadUInt32();
            byte[] octets = reader.ReadBytes((int)towerLength);
            reader.Align(4);

            EpmMapResult? result = ParseTowerOctets(octets);
            if (result is not null)
            {
                return result;
            }
        }

        return null;
    }

    /// <summary>Walks a tower's floors and extracts the TCP port (floor 4) and IP host (floor 5).</summary>
    private static EpmMapResult? ParseTowerOctets(byte[] octets)
    {
        var reader = new ByteReader(octets, ByteOrder.Little);
        ushort floors = reader.ReadUInt16();

        int port = 0;
        string address = "0.0.0.0";
        for (int i = 0; i < floors; i++)
        {
            byte[] lhs = reader.ReadBytes(reader.ReadUInt16());
            byte[] rhs = reader.ReadBytes(reader.ReadUInt16());
            if (lhs.Length == 0)
            {
                continue;
            }

            switch (lhs[0])
            {
                case FloorTcp when rhs.Length >= 2:
                    port = (rhs[0] << 8) | rhs[1]; // ports are big-endian in towers
                    break;
                case FloorIp when rhs.Length >= 4:
                    address = $"{rhs[0]}.{rhs[1]}.{rhs[2]}.{rhs[3]}";
                    break;
            }
        }

        return port == 0 ? null : new EpmMapResult("ncacn_ip_tcp", address, port);
    }

    /// <summary>Builds the 5-floor ncacn_ip_tcp request tower for <paramref name="iface"/>.</summary>
    private static byte[] BuildTcpTower(DcerpcInterface iface)
    {
        var w = new ByteWriter(ByteOrder.Little);
        w.WriteUInt16(5); // floor count

        // Floor 1: interface UUID + version.
        WriteFloor(w, UuidFloorLhs(iface.Uuid, iface.VersionMajor), U16(iface.VersionMinor));
        // Floor 2: NDR transfer syntax, version 2.0.
        WriteFloor(w, UuidFloorLhs(NdrSyntax, 2), U16(0));
        // Floor 3: RPC connection-oriented protocol.
        WriteFloor(w, new[] { FloorRpcConnOriented }, U16(0));
        // Floor 4: TCP, port 0 (asking to be told).
        WriteFloor(w, new[] { FloorTcp }, U16(0));
        // Floor 5: IP host, 0.0.0.0.
        WriteFloor(w, new[] { FloorIp }, new byte[4]);

        return w.ToArray();
    }

    private static void WriteFloor(ByteWriter w, byte[] lhs, byte[] rhs)
    {
        w.WriteUInt16((ushort)lhs.Length);
        w.WriteBytes(lhs);
        w.WriteUInt16((ushort)rhs.Length);
        w.WriteBytes(rhs);
    }

    private static byte[] UuidFloorLhs(Guid uuid, ushort versionMajor)
    {
        var lhs = new byte[1 + 16 + 2];
        lhs[0] = FloorUuid;
        uuid.ToByteArray().CopyTo(lhs, 1);
        lhs[17] = (byte)versionMajor;
        lhs[18] = (byte)(versionMajor >> 8);
        return lhs;
    }

    private static byte[] U16(ushort value) => new[] { (byte)value, (byte)(value >> 8) };
}
