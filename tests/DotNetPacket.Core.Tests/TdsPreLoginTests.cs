using DotNetPacket.Protocols.Tds;
using Xunit;

namespace DotNetPacket.Core.Tests;

public class TdsPreLoginTests
{
    // Reference PRELOGIN payload produced by stock impacket (tds.TDS_PRELOGIN) with the default
    // client version, instance "MSSQLServer" and a fixed ThreadID 0x11223344. The ThreadID is the
    // only variable the example seeds per-run, so pinning it makes the bytes deterministic.
    private const string ExpectedPayload =
        "000015000601001b000102001c000c0300280004ff" + // option table (version/encryption/instance/threadid) + 0xff
        "080001550000" +                                 // VERSION 8.0.0x155
        "00" +                                           // ENCRYPTION = ENCRYPT_OFF
        "4d5353514c5365727665720044332211";              // "MSSQLServer\0" + ThreadID 0x11223344 little-endian

    [Fact]
    public void Build_MatchesImpacketPreLoginBytes()
    {
        byte[] payload = TdsPreLogin.Build(TdsConstants.EncryptOff, 0x11223344);
        Assert.Equal(ExpectedPayload, Convert.ToHexString(payload).ToLowerInvariant());
    }

    [Fact]
    public void Parse_RoundTripsEncryptionAndVersion()
    {
        byte[] payload = TdsPreLogin.Build(TdsConstants.EncryptRequired, 0x11223344);
        TdsPreLoginResponse parsed = TdsPreLogin.Parse(payload);

        Assert.Equal(TdsConstants.EncryptRequired, parsed.Encryption);
        Assert.Equal(TdsPreLogin.ClientVersion, parsed.Version);
        Assert.Equal("8.0.341", parsed.VersionString); // 0x0155 == 341
    }

    [Fact]
    public void Parse_ReadsServerEncryptionPosture()
    {
        // A minimal server-style PRELOGIN that only advertises ENCRYPTION = ENCRYPT_REQ.
        byte[] response =
        {
            0x01, 0x00, 0x06, 0x00, 0x01, // ENCRYPTION option: offset 6, length 1
            0xff,                         // END
            0x03,                         // the ENCRYPTION byte (ENCRYPT_REQ)
        };

        TdsPreLoginResponse parsed = TdsPreLogin.Parse(response);
        Assert.Equal(TdsConstants.EncryptRequired, parsed.Encryption);
    }
}
