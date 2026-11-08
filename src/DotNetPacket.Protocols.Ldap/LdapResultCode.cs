namespace DotNetPacket.Protocols.Ldap;

/// <summary>
/// LDAP result codes (RFC 4511 4.1.9) relevant to the bind path. Ported from the values
/// impacket's <c>impacket.ldap.ldap</c> keys on.
/// </summary>
public static class LdapResultCode
{
    public const int Success = 0;
    public const int StrongerAuthRequired = 8;   // signing/sealing required for this bind
    public const int SaslBindInProgress = 14;    // intermediate leg of a multi-step SASL bind
    public const int InvalidCredentials = 49;
}

/// <summary>Result of an LDAP add/modify/delete operation (RFC 4511 LDAPResult).</summary>
public sealed record LdapResult(int ResultCode, string DiagnosticMessage)
{
    public bool Success => ResultCode == LdapResultCode.Success;
}

/// <summary>LDAP modify operation (RFC 4511 4.6).</summary>
public enum LdapModifyOp
{
    Add = 0,
    Delete = 1,
    Replace = 2,
}
