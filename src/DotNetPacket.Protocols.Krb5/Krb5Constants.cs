namespace DotNetPacket.Protocols.Krb5;

/// <summary>
/// Kerberos v5 (RFC 4120) constants used by the AS exchange. Values mirror impacket's
/// <c>impacket.krb5.constants</c>.
/// </summary>
public static class Krb5Constants
{
    // Application tag numbers (the [APPLICATION n] wrapping each message).
    public const int AsReq = 10;
    public const int AsRep = 11;
    public const int ApReq = 14;
    public const int TgsReq = 12;
    public const int TgsRep = 13;
    public const int Authenticator = 2;
    public const int KrbError = 30;

    public const int Pvno = 5;

    // PrincipalName name-types: NT_PRINCIPAL = 1, NT_SRV_INST = 2 (SPN components).
    public const int NtPrincipal = 1;
    public const int NtSrvInst = 2;

    // PA-DATA types.
    public const int PaTgsReq = 1;
    public const int PaEncTimestamp = 2;
    public const int PaPacRequest = 128;

    /// <summary>
    /// KDC-Options for a TGS-REQ as impacket sends: forwardable (1) + renewable (8) + canonicalize
    /// (15) + renewable-ok (27) = 0x40810010.
    /// </summary>
    public static readonly byte[] KdcOptionsTgs = { 0x40, 0x81, 0x00, 0x10 };

    // Encryption types (RFC 3961 / 4120).
    public const int Rc4Hmac = 23;

    /// <summary>RC4-HMAC keyed checksum type (KERB_CHECKSUM_HMAC_MD5, -138).</summary>
    public const int Rc4HmacChecksumType = -138;
    public const int Aes128CtsHmacSha1 = 17;
    public const int Aes256CtsHmacSha1 = 18;

    // A handful of KDC error codes we care about for AS-REP roasting.
    public const int KdcErrPreauthFailed = 24;
    public const int KdcErrPreauthRequired = 25;
    public const int KdcErrCPrincipalUnknown = 6;
    public const int KdcErrEtypeNoSupp = 14;
    public const int KdcErrClientRevoked = 18;

    /// <summary>
    /// KDC-Options bit string used by impacket's GetNPUsers: forwardable (bit 1), proxiable
    /// (bit 3), renewable (bit 8) — a 32-bit flags field, MSB first. 0x50800000.
    /// </summary>
    public static readonly byte[] KdcOptionsForwardableRenewableProxiable = { 0x50, 0x80, 0x00, 0x00 };

    public static string DescribeError(int code) => code switch
    {
        KdcErrCPrincipalUnknown => "KDC_ERR_C_PRINCIPAL_UNKNOWN (no such user)",
        KdcErrPreauthFailed => "KDC_ERR_PREAUTH_FAILED (wrong password / bad pre-auth)",
        KdcErrEtypeNoSupp => "KDC_ERR_ETYPE_NOSUPP (no supported etype)",
        KdcErrPreauthRequired => "KDC_ERR_PREAUTH_REQUIRED (pre-auth required — not roastable)",
        KdcErrClientRevoked => "KDC_ERR_CLIENT_REVOKED (account disabled/locked)",
        _ => $"KDC error {code}",
    };
}
