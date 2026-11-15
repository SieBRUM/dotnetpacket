using DotNetPacket.Protocols.Ntlm;
using Xunit;

namespace DotNetPacket.Core.Tests;

public class PassTheHashTests
{
    // Pass-the-hash must be cryptographically identical to password auth: NTOWFv2 derived from the
    // pre-computed NT hash equals NTOWFv2 derived from the password. (Only the NT hash is needed for
    // NTLMv2 — the LM hash in impacket's LMHASH:NTHASH is unused here.) The end-to-end CreateAuthenticate
    // override path is covered live (right hash authenticates, wrong hash fails) against the lab DC.
    [Theory]
    [InlineData("Passw0rd!Lab", "Administrator", "LAB")]
    [InlineData("S3cr3t", "svc_sql", "lab.local")]
    public void NtowfV2FromNtHash_EqualsPasswordPath(string password, string user, string domain)
    {
        byte[] ntHash = NtlmCrypto.NtHash(password);
        Assert.Equal(16, ntHash.Length);

        byte[] fromPassword = NtlmCrypto.NtowfV2(password, user, domain);
        byte[] fromHash = NtlmCrypto.NtowfV2FromNtHash(ntHash, user, domain);

        Assert.Equal(fromPassword, fromHash);
    }

    [Fact]
    public void NtowfV2FromNtHash_RejectsWrongLength()
        => Assert.Throws<ArgumentException>(() => NtlmCrypto.NtowfV2FromNtHash(new byte[15], "u", "d"));
}
