using DotNetPacket.Protocols.Ldap;
using Xunit;

namespace DotNetPacket.Core.Tests;

public class LdapSearchTests
{
    // Verbatim SearchResultEntry LDAPMessage captured from the lab Samba AD DC answering the
    // GetADComputers search (base dc=lab,dc=local, filter (&(objectCategory=computer)
    // (objectClass=computer))). Authentic server bytes — the DC's own computer object.
    private const string SearchResEntry =
        "3081c00201026481ba042b434e3d564d2c4f553d446f6d61696e20436f6e74726f6c6c6572732c44433d6c" +
        "61622c44433d6c6f63616c30818a3017040e73414d4163636f756e744e616d6531050403564d2430280" +
        "40f6f7065726174696e6753797374656d3115041353616d62612d342e31392e352d5562756e747530260" +
        "4166f7065726174696e6753797374656d56657273696f6e310c040a362e3120283736303029301d040b6" +
        "44e53486f73744e616d65310e040c766d2e6c61622e6c6f63616c";

    [Fact]
    public void ParseSearchEntry_DecodesComputerObject()
    {
        SearchEntry e = LdapConnection.ParseSearchEntry(Convert.FromHexString(SearchResEntry));

        Assert.Equal("CN=VM,OU=Domain Controllers,DC=lab,DC=local", e.ObjectName);
        Assert.Equal("VM$", e.Get("sAMAccountName"));
        Assert.Equal("vm.lab.local", e.Get("dNSHostName"));
        Assert.Equal("Samba-4.19.5-Ubuntu", e.Get("operatingSystem"));
        Assert.Equal("6.1 (7600)", e.Get("operatingSystemVersion"));
        Assert.Equal(string.Empty, e.Get("whenCreated")); // absent attribute -> empty
    }

    // The exact SearchRequest LDAPMessage (messageID 2) this client put on the wire for the
    // GetADComputers search, confirmed by Wireshark's LDAP dissector to decode to
    // base=dc=lab,dc=local, scope wholeSubtree, filter (&(objectCategory=computer)
    // (objectClass=computer)), attrs sAMAccountName/dNSHostName/operatingSystem/…Version.
    private const string SearchRequest =
        "3081a502010263819f040f64633d6c61622c64633d6c6f63616c0a01020a01000201000201000101" +
        "00a035a31a040e6f626a65637443617465676f72790408636f6d7075746572a317040b6f626a6563" +
        "74436c6173730408636f6d70757465723046040e73414d4163636f756e744e616d65040b644e5348" +
        "6f73744e616d65040f6f7065726174696e6753797374656d04166f7065726174696e675379737465" +
        "6d56657273696f6e";

    [Fact]
    public void EncodeSearchRequest_ReproducesTheWireBytes()
    {
        byte[] encoded = LdapConnection.EncodeSearchRequest(
            messageId: 2,
            baseObject: "dc=lab,dc=local",
            filter: LdapFilter.AllOf(
                LdapFilter.Equal("objectCategory", "computer"),
                LdapFilter.Equal("objectClass", "computer")),
            attributes: new[] { "sAMAccountName", "dNSHostName", "operatingSystem", "operatingSystemVersion" });

        Assert.Equal(SearchRequest, Convert.ToHexString(encoded).ToLowerInvariant());
    }

    // The exact SearchRequest LDAPMessages (messageID 2) the GetADUsers port put on the wire,
    // both accepted by the lab DC (searchResDone resultCode 0). Attributes for both:
    // sAMAccountName / pwdLastSet / mail / lastLogon.
    private const string AllUsersRequest =
        "307e0201026379040f64633d6c61622c64633d6c6f63616c0a01020a01000201000201000101" +
        "00a028870e73414d4163636f756e744e616d65a316040e6f626a65637443617465676f727904" +
        "0475736572302d040e73414d4163636f756e744e616d65040a7077644c6173745365740404" +
        "6d61696c04096c6173744c6f676f6e";

    // The default GetADUsers filter: (&(sAMAccountName=*)(mail=*)
    // (!(userAccountControl:1.2.840.113556.1.4.803:=2))) — exercises present + not + extensibleMatch.
    private const string EnabledMailUsersRequest =
        "3081a002010263819a040f64633d6c61622c64633d6c6f63616c0a01020a01000201000201000101" +
        "00a049870e73414d4163636f756e744e616d6587046d61696ca231a92f8116312e322e3834302e31" +
        "31333535362e312e342e3830338212757365724163636f756e74436f6e74726f6c830132302d040e" +
        "73414d4163636f756e744e616d65040a7077644c61737453657404046d61696c04096c6173744c6f" +
        "676f6e";

    private static readonly string[] UserAttrs = { "sAMAccountName", "pwdLastSet", "mail", "lastLogon" };

    [Fact]
    public void EncodeSearchRequest_ReproducesAllUsersFilter()
    {
        byte[] encoded = LdapConnection.EncodeSearchRequest(
            messageId: 2, baseObject: "dc=lab,dc=local",
            filter: LdapFilter.AllOf(
                LdapFilter.PresentOf("sAMAccountName"),
                LdapFilter.Equal("objectCategory", "user")),
            attributes: UserAttrs);

        Assert.Equal(AllUsersRequest, Convert.ToHexString(encoded).ToLowerInvariant());
    }

    [Fact]
    public void EncodeSearchRequest_ReproducesEnabledMailUsersFilter()
    {
        byte[] encoded = LdapConnection.EncodeSearchRequest(
            messageId: 2, baseObject: "dc=lab,dc=local",
            filter: LdapFilter.AllOf(
                LdapFilter.PresentOf("sAMAccountName"),
                LdapFilter.PresentOf("mail"),
                LdapFilter.Negate(LdapFilter.Extensible(
                    "1.2.840.113556.1.4.803", "userAccountControl", "2"))),
            attributes: UserAttrs);

        Assert.Equal(EnabledMailUsersRequest, Convert.ToHexString(encoded).ToLowerInvariant());
    }

    // Verbatim SearchResultEntry for the Administrator user, captured from the lab DC.
    private const string AdminEntry =
        "30818c0201026481860429434e3d41646d696e6973747261746f722c434e3d55736572732c44433d" +
        "6c61622c44433d6c6f63616c3059301004096c6173744c6f676f6e31030401303022040a7077644c" +
        "617374536574311404123133343337383436333536373138333634303021040e73414d4163636f75" +
        "6e744e616d65310f040d41646d696e6973747261746f72";

    [Fact]
    public void ParseSearchEntry_DecodesUserWithTimestamps()
    {
        SearchEntry e = LdapConnection.ParseSearchEntry(Convert.FromHexString(AdminEntry));

        Assert.Equal("CN=Administrator,CN=Users,DC=lab,DC=local", e.ObjectName);
        Assert.Equal("Administrator", e.Get("sAMAccountName"));
        // AD timestamps come back as decimal FILETIME strings; lastLogon 0 = never.
        Assert.Equal("134378463567183640", e.Get("pwdLastSet"));
        Assert.Equal("0", e.Get("lastLogon"));
    }

    [Fact]
    public void PresenceFilter_EncodesAsContextPrimitive()
    {
        // (objectClass=*) -> present [7] primitive "objectClass"; a small structural check.
        byte[] encoded = LdapConnection.EncodeSearchRequest(
            messageId: 1, baseObject: "", filter: LdapFilter.PresentOf("objectClass"),
            attributes: Array.Empty<string>());

        // 0x87 = context [7] primitive, length 11, then "objectClass".
        Assert.Contains("870b6f626a656374436c617373", Convert.ToHexString(encoded).ToLowerInvariant());
    }
}
