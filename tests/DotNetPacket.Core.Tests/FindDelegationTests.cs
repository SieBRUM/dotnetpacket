using DotNetPacket.Protocols.Ldap;
using Xunit;

namespace DotNetPacket.Core.Tests;

public class FindDelegationTests
{
    // The findDelegation.py search filter — the recon action itself, so it stays faithful to
    // impacket (behaviour, not a tool-invented payload). This pins the exact encoding; the live
    // capture (dotnetpacket-find-delegation.pcap) decodes to the same filter in Wireshark.
    private static readonly string[] Attrs =
    {
        "sAMAccountName", "pwdLastSet", "userAccountControl", "objectCategory",
        "msDS-AllowedToActOnBehalfOfOtherIdentity", "msDS-AllowedToDelegateTo",
    };

    private static LdapFilter DelegationFilter() => LdapFilter.AllOf(
        LdapFilter.AnyOf(
            LdapFilter.Extensible("1.2.840.113556.1.4.803", "userAccountControl", "524288"),    // unconstrained
            LdapFilter.Extensible("1.2.840.113556.1.4.803", "userAccountControl", "16777216"),  // protocol transition
            LdapFilter.PresentOf("msDS-AllowedToDelegateTo"),                                    // constrained
            LdapFilter.PresentOf("msDS-AllowedToActOnBehalfOfOtherIdentity")),                   // RBCD
        LdapFilter.Negate(LdapFilter.Extensible("1.2.840.113556.1.4.803", "userAccountControl", "2"))); // not disabled

    [Fact]
    public void EncodeSearchRequest_ReproducesDelegationFilter()
    {
        byte[] encoded = LdapConnection.EncodeSearchRequest(
            messageId: 2, baseObject: "dc=lab,dc=local", filter: DelegationFilter(), attributes: Attrs);

        Assert.Equal(DelegationRequest, Convert.ToHexString(encoded).ToLowerInvariant());
    }

    private const string DelegationRequest = "3082019902010263820192040f64633d6c61622c64633d6c6f63616c0a01020a0100020100020100010100a081e8a181b2a9348116312e322e3834302e3131333535362e312e342e3830338212757365724163636f756e74436f6e74726f6c8306353234323838a9368116312e322e3834302e3131333535362e312e342e3830338212757365724163636f756e74436f6e74726f6c8308313637373732313687186d7344532d416c6c6f776564546f44656c6567617465546f87286d7344532d416c6c6f776564546f4163744f6e426568616c664f664f746865724964656e74697479a231a92f8116312e322e3834302e3131333535362e312e342e3830338212757365724163636f756e74436f6e74726f6c830132308184040e73414d4163636f756e744e616d65040a7077644c6173745365740412757365724163636f756e74436f6e74726f6c040e6f626a65637443617465676f727904286d7344532d416c6c6f776564546f4163744f6e426568616c664f664f746865724964656e7469747904186d7344532d416c6c6f776564546f44656c6567617465546f";
}
