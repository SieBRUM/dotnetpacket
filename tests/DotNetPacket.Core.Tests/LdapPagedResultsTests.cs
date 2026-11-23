using System.Formats.Asn1;
using System.Text;
using DotNetPacket.Protocols.Ldap;
using Xunit;

namespace DotNetPacket.Core.Tests;

/// <summary>
/// Simple paged-results control (RFC 2696 / MS-ADTS, OID 1.2.840.113556.1.4.319). Without it an LDAP
/// enumeration silently stops at Active Directory's MaxPageSize (1000), so these pin the control value
/// encoding, the request-level wiring (criticality TRUE, as impacket sends it) and the cookie round-trip.
/// </summary>
public class LdapPagedResultsTests
{
    [Fact]
    public void EncodePagedResultsControlValue_EmptyCookie_KnownBytes()
    {
        // SEQUENCE { INTEGER 1000, OCTET STRING "" } = 30 06 02 02 03 E8 04 00
        byte[] cv = LdapConnection.EncodePagedResultsControlValue(1000, System.Array.Empty<byte>());
        Assert.Equal("3006020203e80400", Convert.ToHexString(cv).ToLowerInvariant());
    }

    [Fact]
    public void EncodePagedResultsControlValue_WithCookie_KnownBytes()
    {
        // SEQUENCE { INTEGER 0, OCTET STRING DE AD BE EF } = 30 09 02 01 00 04 04 DE AD BE EF
        byte[] cv = LdapConnection.EncodePagedResultsControlValue(0, new byte[] { 0xDE, 0xAD, 0xBE, 0xEF });
        Assert.Equal("30090201000404deadbeef", Convert.ToHexString(cv).ToLowerInvariant());
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1000)]
    [InlineData(int.MaxValue)]
    public void PagedResultsControlValue_RoundTrips(int size)
    {
        byte[] cookie = { 0x01, 0x02, 0x03, 0x04, 0x05 };
        byte[] cv = LdapConnection.EncodePagedResultsControlValue(size, cookie);

        (int parsedSize, byte[] parsedCookie) = LdapConnection.ParsePagedResultsControlValue(cv);

        Assert.Equal(size, parsedSize);
        Assert.Equal(cookie, parsedCookie);
    }

    [Fact]
    public void EncodeSearchRequest_WithoutPaging_HasNoControls()
    {
        byte[] msg = LdapConnection.EncodeSearchRequest(
            1, "dc=lab,dc=local", LdapFilter.PresentOf("objectClass"), new[] { "cn" });

        Assert.Null(FindControls(msg));
    }

    [Fact]
    public void EncodeSearchRequest_WithPaging_CarriesCriticalControlAndValue()
    {
        byte[] msg = LdapConnection.EncodeSearchRequest(
            2, "dc=lab,dc=local", LdapFilter.PresentOf("objectClass"), new[] { "cn" }, pageSize: 1000);

        AsnReader? controls = FindControls(msg);
        Assert.NotNull(controls);

        AsnReader ctrl = controls!.ReadSequence();
        string oid = Encoding.ASCII.GetString(ctrl.ReadOctetString());
        Assert.Equal("1.2.840.113556.1.4.319", oid);

        // impacket sends the paged-results control as critical.
        Assert.True(ctrl.ReadBoolean());

        (int size, byte[] cookie) = LdapConnection.ParsePagedResultsControlValue(ctrl.ReadOctetString());
        Assert.Equal(1000, size);
        Assert.Empty(cookie);                 // first page -> empty cookie
        Assert.False(controls.HasData);       // exactly one control
    }

    // Walks an LDAPMessage SEQUENCE to its controls [0] (skipping messageID + protocolOp); null if absent.
    private static AsnReader? FindControls(byte[] message)
    {
        AsnReader ldapMessage = new AsnReader(message, AsnEncodingRules.BER).ReadSequence();
        ldapMessage.ReadInteger();            // messageID
        ldapMessage.ReadEncodedValue();       // protocolOp (SearchRequest)
        if (!ldapMessage.HasData)
        {
            return null;
        }

        var controlsTag = new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true);
        return ldapMessage.PeekTag().HasSameClassAndValue(controlsTag)
            ? ldapMessage.ReadSequence(controlsTag)
            : null;
    }
}
