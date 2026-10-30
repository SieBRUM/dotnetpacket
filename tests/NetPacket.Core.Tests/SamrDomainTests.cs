using NetPacket.Protocols.Dcerpc;
using Xunit;

namespace NetPacket.Core.Tests;

public class SamrDomainTests
{
    // Response stub bytes captured from impacket's SamrQueryInformationDomain against
    // Samba: a unique pointer to the SAMPR_DOMAIN_INFO_BUFFER union (4-byte referent +
    // 4-byte discriminant), then the level struct. The live rpc-passpol example drives
    // the full call; these pin the parsers to known server bytes.
    private const string PasswordInfoStub =
        "00000200" +                 // Buffer referent
        "01000000" +                 // union discriminant (level 1)
        "0500" +                     // MinPasswordLength = 5
        "0000" +                     // PasswordHistoryLength = 0
        "00000000" +                 // PasswordProperties = 0
        "7f969800806967ff" +         // MaxPasswordAge (NT relative time)
        "0000000000000000" +         // MinPasswordAge = 0
        "00000000";                  // trailing alignment

    private const string LockoutInfoStub =
        "00000200" +                 // Buffer referent
        "0c000000" +                 // union discriminant (level 12)
        "ffcb1dcffbffffff" +         // LockoutDuration
        "ffcb1dcffbffffff" +         // LockoutObservationWindow
        "0000" +                     // LockoutThreshold = 0
        "000000000000";              // trailing alignment

    [Fact]
    public void ParsePasswordPolicy_ReadsFields()
    {
        SamrPasswordPolicy p = Samr.ParsePasswordPolicy(Convert.FromHexString(PasswordInfoStub));

        Assert.Equal(5, p.MinPasswordLength);
        Assert.Equal(0, p.PasswordHistoryLength);
        Assert.Equal(0u, p.PasswordProperties);
        Assert.True(p.MaxPasswordAge < 0);       // a real (negative) relative time
        Assert.Equal(0L, p.MinPasswordAge);
        Assert.NotNull(Samr.RelativeTimeToDays(p.MaxPasswordAge));
        Assert.Null(Samr.RelativeTimeToDays(p.MinPasswordAge)); // 0 => no minimum
    }

    [Fact]
    public void ParseLockoutPolicy_ReadsFields()
    {
        SamrLockoutPolicy l = Samr.ParseLockoutPolicy(Convert.FromHexString(LockoutInfoStub));

        Assert.Equal(0, l.LockoutThreshold);
        Assert.True(l.LockoutDuration < 0);
        Assert.True(l.LockoutObservationWindow < 0);
    }

    [Fact]
    public void RelativeTimeToDays_HandlesNeverSentinel()
    {
        Assert.Null(Samr.RelativeTimeToDays(long.MinValue));
        Assert.Null(Samr.RelativeTimeToDays(0));
        // -30 days expressed as NT relative 100ns ticks.
        long thirtyDays = -30L * 86400 * 10_000_000;
        Assert.Equal(30.0, Samr.RelativeTimeToDays(thirtyDays)!.Value, 3);
    }
}
