using DotNetPacket.Protocols.Laps;
using DotNetPacket.Protocols.Ldap;
using Xunit;

namespace DotNetPacket.Core.Tests;

public class LapsTests
{
    [Fact]
    public void ParseWindowsLapsCleartext_ExtractsNameAndPassword()
    {
        // The Windows LAPS cleartext msLAPS-Password JSON format (MS-LAPS): {"n":user,"p":pass,"t":ticks}.
        var (user, pass) = LapsPassword.ParseWindowsLapsCleartext(
            "{\"n\":\"Administrator\",\"t\":\"1d9a1c0...\",\"p\":\"Str0ng-LAPS-Pw!\"}");

        Assert.Equal("Administrator", user);
        Assert.Equal("Str0ng-LAPS-Pw!", pass);
    }

    [Fact]
    public void ParseWindowsLapsCleartext_NonJson_ReturnsNulls()
    {
        var (user, pass) = LapsPassword.ParseWindowsLapsCleartext("not json");
        Assert.Null(user);
        Assert.Null(pass);
    }

    // The exact SearchRequest LDAPMessage (messageID 2) the GetLAPSPassword port put on the wire,
    // accepted by the lab DC (searchResDone resultCode 0). Filter:
    // (&(objectCategory=computer)(|(msLAPS-EncryptedPassword=*)(ms-MCS-AdmPwd=*)(msLAPS-Password=*)))
    private const string LapsRequest =
        "3082010a02010263820103040f64633d6c61622c64633d6c6f63616c0a01020a010002010002010001" +
        "0100a058a31a040e6f626a65637443617465676f72790408636f6d7075746572a13a87186d734c4150" +
        "532d456e6372797074656450617373776f7264870d6d732d4d43532d41646d507764870f6d734c4150" +
        "532d50617373776f726430818604186d734c4150532d456e6372797074656450617373776f7264041d" +
        "6d734c4150532d50617373776f726445787069726174696f6e54696d65040f6d734c4150532d506173" +
        "73776f7264040e73414d4163636f756e744e616d65041b6d732d4d63732d41646d507764457870697261" +
        "74696f6e54696d65040d6d732d4d43532d41646d507764";

    [Fact]
    public void EncodeSearchRequest_ReproducesLapsFilterAndAttributes()
    {
        LdapFilter filter = LdapFilter.AllOf(
            LdapFilter.Equal("objectCategory", "computer"),
            LdapFilter.AnyOf(
                LdapFilter.PresentOf("msLAPS-EncryptedPassword"),
                LdapFilter.PresentOf("ms-MCS-AdmPwd"),
                LdapFilter.PresentOf("msLAPS-Password")));
        string[] attrs =
        {
            "msLAPS-EncryptedPassword", "msLAPS-PasswordExpirationTime", "msLAPS-Password",
            "sAMAccountName", "ms-Mcs-AdmPwdExpirationTime", "ms-MCS-AdmPwd",
        };

        byte[] encoded = LdapConnection.EncodeSearchRequest(2, "dc=lab,dc=local", filter, attrs);
        Assert.Equal(LapsRequest, Convert.ToHexString(encoded).ToLowerInvariant());
    }
}
