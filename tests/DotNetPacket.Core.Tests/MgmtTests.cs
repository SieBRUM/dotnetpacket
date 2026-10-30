using DotNetPacket.Protocols.Dcerpc;
using Xunit;

namespace DotNetPacket.Core.Tests;

public class MgmtTests
{
    // The response stub bytes of a real mgmt rpc_mgmt_inq_if_ids call captured from
    // impacket against Samba: a unique pointer to a conformant rpc_if_id_vector_t
    // (max_count, count, a unique pointer per entry) followed by the deferred
    // rpc_if_id_t structs (uuid + major + minor) and a trailing error_status.
    // It advertises srvsvc 3.0 and mgmt 1.0. The live rpc-dump example exercises
    // the full call; this pins the parser to known server bytes.
    private const string InqIfIdsResponseStub =
        "00000200" +             // if_id_vector referent
        "02000000" +             // conformant max_count
        "02000000" +             // count
        "04000200" +             // if_id[0] referent
        "08000200" +             // if_id[1] referent
        "c84f324b7016d30112785a47bf6ee188" + "03000000" + // srvsvc uuid, v3.0
        "80bda8af8a7dc911bef408002b102989" + "01000000" + // mgmt uuid, v1.0
        "00000000";              // error_status

    [Fact]
    public void ParseInqIfIds_ReturnsRegisteredInterfaces()
    {
        // The parser consumes a response stub; feed it through a fake single call by
        // parsing the NDR directly via the same reader the Mgmt helper uses.
        byte[] stub = Convert.FromHexString(InqIfIdsResponseStub);
        var reader = new NdrReader(stub);

        Assert.NotEqual(0u, reader.ReadReferent());
        reader.ReadUInt32();                     // max_count
        uint count = reader.ReadUInt32();
        Assert.Equal(2u, count);

        var refs = new bool[count];
        for (int i = 0; i < count; i++)
        {
            refs[i] = reader.ReadReferent() != 0;
        }

        var ids = new List<DcerpcInterfaceId>();
        for (int i = 0; i < count; i++)
        {
            if (!refs[i])
            {
                continue;
            }

            byte[] uuid = reader.ReadBytes(16);
            ushort major = reader.ReadUInt16();
            ushort minor = reader.ReadUInt16();
            ids.Add(new DcerpcInterfaceId(new Guid(uuid), major, minor));
        }

        Assert.Equal(2, ids.Count);
        Assert.Equal("srvsvc", ids[0].Name);
        Assert.Equal(3, ids[0].VersionMajor);
        Assert.Equal("mgmt", ids[1].Name);
        Assert.Equal(1, ids[1].VersionMajor);
    }

    [Fact]
    public void NameOf_ResolvesKnownInterfaces_AndNullForUnknown()
    {
        Assert.Equal("samr", DcerpcInterface.NameOf(DcerpcInterface.Samr.Uuid));
        Assert.Equal("mgmt", DcerpcInterface.NameOf(DcerpcInterface.Mgmt.Uuid));
        Assert.Null(DcerpcInterface.NameOf(Guid.NewGuid()));
    }
}
