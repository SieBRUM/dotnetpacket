using DotNetPacket.Protocols.Krb5;
using Xunit;

namespace DotNetPacket.Core.Tests;

/// <summary>
/// RFC 4121 CFX GSS Wrap (the SASL sign-and-seal a Kerberos LDAP bind negotiates) known-answer tests,
/// pinned to impacket's <c>GSSAPI_AES256.GSS_Wrap_LDAP</c> with a fixed confounder. Proves the sealed
/// LDAP payloads match stock impacket on the wire.
/// </summary>
public class GssSealTests
{
    private static byte[] Hex(string s) => Convert.FromHexString(s);

    private static readonly byte[] Key = Hex("55a6ac740ad17b4846941051e1e8b0a7548d93b0ab30a8bc3ff16280382b8c2a");
    private static readonly byte[] Plaintext = Hex("30050201014200");
    private const ulong Seq = 0x1122334455667788UL;
    private static readonly byte[] FixedConfounder = Enumerable.Range(0, 16).Select(i => (byte)i).ToArray();

    [Fact]
    public void Wrap_MatchesImpacketInitiatorToken()
    {
        var ctx = new KerberosGssContext(Key, 18, Seq);
        byte[] token = ctx.Wrap(Plaintext, FixedConfounder);

        // impacket GSS_Wrap_LDAP (INITIATOR_SEAL, usage 24) with confounder 00..0f.
        Assert.Equal(
            "050406ff0000001c1122334455667788468ccfb93f4362736e1f5af03e64bef209c3250a75983f9f4f81d2c7f2ababb8742ff73982e7497a1e327b5ff8f859f2184d6f",
            Convert.ToHexString(token).ToLowerInvariant());
    }

    [Fact]
    public void Unwrap_RecoversImpacketAcceptorToken()
    {
        // A token sealed by the acceptor (ACCEPTOR_SEAL, usage 22) — what the DC sends back.
        byte[] acceptorToken = Hex(
            "050406ff0000001c11223344556677883c33860d33e52f06ec0f4efd46d1ea51ab7d965ee63b83acda51f62a0e98e1010236e1cedb5f4c86cc2e9e41e6158d16238b15");

        var ctx = new KerberosGssContext(Key, 18);
        byte[] plain = ctx.Unwrap(acceptorToken);
        Assert.Equal(Plaintext, plain);
    }

    [Fact]
    public void Wrap_HeaderAdvertisesSealAndRrc28()
    {
        var ctx = new KerberosGssContext(Key, 18, Seq);
        byte[] token = ctx.Wrap(Plaintext);

        Assert.Equal(0x05, token[0]);
        Assert.Equal(0x04, token[1]);            // TOK_ID 0x0504
        Assert.Equal(0x06, token[2]);            // Flags: Sealed | AcceptorSubkey
        Assert.Equal(0xFF, token[3]);            // Filler
        Assert.Equal(0x00, token[4]);
        Assert.Equal(0x00, token[5]);            // EC = 0
        Assert.Equal(0x00, token[6]);
        Assert.Equal(0x1C, token[7]);            // RRC = 28
    }

    [Fact]
    public void Wrap_ThenPeerUnwrap_RoundTrips()
    {
        // Our wrap (usage 24) is recovered by the peer's unwrap (which keys the same usage 24).
        var mine = new KerberosGssContext(Key, 18);
        byte[] token = mine.Wrap(Plaintext);

        // Reverse exactly as a GSS acceptor does: strip header, unrotate by RRC, decrypt with usage 24.
        int rrc = (token[6] << 8) | token[7];
        byte[] rotated = token[16..];
        int n = rrc % rotated.Length;
        byte[] cipher = rotated[n..].Concat(rotated[..n]).ToArray();
        byte[] plain = AesCtsCrypto.Decrypt(Key, 24, cipher);
        Assert.Equal(Plaintext, plain[..^16]); // drop the trailing inner header
    }

    [Fact]
    public void Rc4_IsNotSupportedForSealing()
    {
        Assert.False(KerberosGssContext.Supports(23));
        Assert.Throws<NotSupportedException>(() => new KerberosGssContext(new byte[16], 23));
    }
}
