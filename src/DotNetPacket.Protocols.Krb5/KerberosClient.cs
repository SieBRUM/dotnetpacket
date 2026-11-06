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
    {
        realm = realm.ToUpperInvariant();
        byte[] clientKey = Krb5Crypto.Rc4StringToKey(password);

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
}
