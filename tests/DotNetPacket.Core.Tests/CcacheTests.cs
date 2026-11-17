using DotNetPacket.Protocols.Krb5;
using Xunit;

namespace DotNetPacket.Core.Tests;

/// <summary>
/// MIT ccache (v4) read/write tests. The format is validated structurally and by round-trip; it is
/// also validated live against impacket's <c>describeTicket.py</c> (which parses a DotNetPacket-written
/// ccache — session key, principals and ticket flags — see docs/PORTING_STATUS.md).
/// </summary>
public class CcacheTests
{
    private static CcacheCredential SampleTgt() => new(
        ClientName: "Administrator", ClientRealm: "LAB.LOCAL",
        ServerName: "krbtgt/LAB.LOCAL", ServerRealm: "LAB.LOCAL",
        KeyType: 18, Key: Enumerable.Range(1, 32).Select(i => (byte)i).ToArray(),
        AuthTime: DateTimeOffset.FromUnixTimeSeconds(1_700_000_000),
        StartTime: DateTimeOffset.FromUnixTimeSeconds(1_700_000_010),
        EndTime: DateTimeOffset.FromUnixTimeSeconds(1_700_036_000),
        RenewTill: DateTimeOffset.FromUnixTimeSeconds(1_700_600_000),
        Flags: new byte[] { 0x50, 0xe1, 0x00, 0x00 },
        Ticket: Convert.FromHexString("6182010030820100a003020105"));

    [Fact]
    public void Build_StartsWithV4HeaderAndDeltaTime()
    {
        byte[] data = CCache.Build("Administrator", "LAB.LOCAL", new[] { SampleTgt() });
        // file_format_version 0x0504, headerlen 0x000c, tag 0x0001, taglen 0x0008, DeltaTime ffffffff 00000000.
        Assert.Equal("0504000c00010008ffffffff00000000",
            Convert.ToHexString(data.AsSpan(0, 16).ToArray()).ToLowerInvariant());
    }

    [Fact]
    public void BuildThenParse_RoundTrips()
    {
        CcacheCredential c = SampleTgt();
        byte[] data = CCache.Build("Administrator", "LAB.LOCAL", new[] { c });

        CCacheFile parsed = CCache.Parse(data);
        Assert.Equal("Administrator", parsed.DefaultClient);
        Assert.Equal("LAB.LOCAL", parsed.DefaultRealm);
        Assert.Single(parsed.Credentials);

        CcacheCredential r = parsed.Credentials[0];
        Assert.Equal(c.ClientName, r.ClientName);
        Assert.Equal(c.ServerName, r.ServerName);
        Assert.Equal(c.ServerRealm, r.ServerRealm);
        Assert.Equal(c.KeyType, r.KeyType);
        Assert.Equal(c.Key, r.Key);
        Assert.Equal(c.EndTime, r.EndTime);
        Assert.Equal(c.RenewTill, r.RenewTill);
        Assert.Equal(c.Flags, r.Flags);
        Assert.Equal(c.Ticket, r.Ticket);
    }

    [Fact]
    public void ToTgt_RecoversTheTgtCredential()
    {
        // A ccache with a service ticket and the TGT; ToTgt must pick the krbtgt credential.
        CcacheCredential st = SampleTgt() with { ServerName = "cifs/vm.lab.local", Ticket = new byte[] { 0x61, 0x00 } };
        byte[] data = CCache.Build("Administrator", "LAB.LOCAL", new[] { st, SampleTgt() });

        Tgt tgt = CCache.ToTgt(CCache.Parse(data));
        Assert.Equal("krbtgt/LAB.LOCAL", tgt.ServiceName);
        Assert.Equal(18, tgt.SessionKeyEtype);
        Assert.Equal(SampleTgt().Key, tgt.SessionKey);
        Assert.Equal("Administrator", tgt.User);
        Assert.Equal("LAB.LOCAL", tgt.Realm);
    }

    [Fact]
    public void FromTgt_UsesTheTgtFieldsIncludingFlags()
    {
        var tgt = new Tgt(
            Ticket: new byte[] { 1, 2, 3 }, SessionKeyEtype: 18, SessionKey: new byte[32],
            EndTime: DateTimeOffset.FromUnixTimeSeconds(1_700_036_000), Realm: "LAB.LOCAL", User: "svc",
            ServiceName: "krbtgt/LAB.LOCAL", TicketFlags: new byte[] { 0x40, 0x81, 0x00, 0x00 });

        CcacheCredential c = CCache.FromTgt(tgt);
        Assert.Equal("svc", c.ClientName);
        Assert.Equal("krbtgt/LAB.LOCAL", c.ServerName);
        Assert.Equal(new byte[] { 0x40, 0x81, 0x00, 0x00 }, c.Flags);
        Assert.Equal(tgt.Ticket, c.Ticket);
    }
}
