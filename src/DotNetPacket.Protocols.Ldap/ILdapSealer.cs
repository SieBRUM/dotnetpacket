namespace DotNetPacket.Protocols.Ldap;

/// <summary>
/// A per-message seal/unseal layer for an LDAP connection — the SASL "sign and seal" negotiated by a
/// Kerberos (GSS-SPNEGO) bind. Once enabled on an <see cref="LdapConnection"/>, every LDAP PDU after
/// the bind is wrapped on the way out and unwrapped on the way in. The implementation lives in a higher
/// layer (it needs the Kerberos session key); this interface keeps the LDAP code free of that dependency.
/// </summary>
public interface ILdapSealer
{
    /// <summary>Seals one plaintext LDAP message, returning the token to frame (without the 4-byte SASL length).</summary>
    byte[] Wrap(byte[] ldapMessage);

    /// <summary>Unseals one received token (the SASL buffer with its 4-byte length already stripped).</summary>
    byte[] Unwrap(byte[] token);
}
