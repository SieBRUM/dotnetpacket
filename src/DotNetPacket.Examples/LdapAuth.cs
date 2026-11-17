using DotNetPacket.Protocols.Krb5;
using DotNetPacket.Protocols.Ldap;
using DotNetPacket.Protocols.Ntlm;
using DotNetPacket.Protocols.Smb;

namespace DotNetPacket.Examples;

/// <summary>
/// Shared authentication for the LDAP examples (GetADUsers, GetADComputers, findDelegation,
/// GetLAPSPassword, …). Honors the impacket-style global options: a simple bind by default, or a
/// Kerberos GSS-SPNEGO bind when <c>-k</c> is set (ticket for <c>ldap/&lt;host&gt;</c>, same AP-REQ
/// token the SMB path uses), with <c>-target-ip</c> separating the connect address from the SPN host.
/// </summary>
internal static class LdapAuth
{
    /// <summary>
    /// Connects to the DC (connecting to <c>-target-ip</c> when set, else <paramref name="host"/>) and
    /// binds. With <c>-k</c> it performs a Kerberos GSS-SPNEGO bind; otherwise a simple bind of
    /// <c>user@domain</c>. The caller inspects <paramref name="bind"/> for success.
    /// </summary>
    public static LdapConnection ConnectAndBind(
        string host, int port, string bindName, string password, string domainFqdn, out LdapBindResponse bind)
    {
        string connectHost = Smb2Client.TargetIpOverride ?? host;
        LdapConnection ldap = LdapConnection.Connect(connectHost, port);

        if (Smb2Client.UseKerberos)
        {
            string user = bindName.Contains('@') ? bindName[..bindName.IndexOf('@')] : bindName;
            bind = KerberosBind(ldap, host, domainFqdn, user, password);
        }
        else
        {
            bind = ldap.SimpleBind(bindName, password);
        }

        return ldap;
    }

    private static LdapBindResponse KerberosBind(LdapConnection ldap, string spnHost, string domainFqdn, string user, string password)
    {
        string realm = domainFqdn.ToUpperInvariant();
        string kdc = Smb2Client.KerberosKdc ?? Smb2Client.TargetIpOverride ?? spnHost;

        // A service ticket for ldap/<host>, then a mutual-auth GSS AP-REQ wrapped in SPNEGO (MS KRB5).
        // Mutual auth makes the DC return an AP-REP carrying an acceptor subkey, which (per [MS-KILE]
        // 3.1.1.2) is the GSS context key the sealed LDAP traffic keys on. Overpass-the-hash via
        // -hashes (RC4) / -aesKey (AES).
        ServiceTicket st = KerberosClient.GetServiceTicketForSpn(
            kdc, realm, user, password, NtlmClient.NtHashOverride, Smb2Client.KerberosAesKey, $"ldap/{spnHost}");

        KerberosApReq apReq = KerberosGss.BuildApReqToken(st, mutualAuth: true, gssFlags: KerberosGss.LdapGssFlags | 0x02);
        byte[] token = Spnego.WrapKerberosInitialToken(apReq.GssToken);

        LdapBindResponse r = ldap.SaslBind("GSS-SPNEGO", token);
        if (r.SaslInProgress)
        {
            // The DC asked for another leg; complete the SASL handshake with an empty continuation token.
            r = ldap.SaslBind("GSS-SPNEGO", Array.Empty<byte>());
        }

        if (r.Success)
        {
            // Recover the acceptor subkey from the AP-REP in the server's SASL creds and seal with it.
            byte[] responseToken = Spnego.ExtractResponseToken(r.ServerSaslCreds);
            KerberosSubkey? subkey = KerberosApRep.ExtractSubkey(responseToken, st.SessionKey, st.SessionKeyEtype);
            byte[] sealKey = subkey?.Key ?? st.SessionKey;
            int sealEtype = subkey?.Etype ?? st.SessionKeyEtype;
            ldap.EnableSealing(new KerberosLdapSealer(new KerberosGssContext(sealKey, sealEtype)));
        }

        return r;
    }

    /// <summary>Adapts <see cref="KerberosGssContext"/> to the LDAP seal layer (keeps Krb5 out of the Ldap project).</summary>
    private sealed class KerberosLdapSealer : ILdapSealer
    {
        private readonly KerberosGssContext _gss;

        public KerberosLdapSealer(KerberosGssContext gss) => _gss = gss;

        public byte[] Wrap(byte[] ldapMessage) => _gss.Wrap(ldapMessage);

        public byte[] Unwrap(byte[] token) => _gss.Unwrap(token);
    }
}
