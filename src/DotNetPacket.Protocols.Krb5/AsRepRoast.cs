namespace DotNetPacket.Protocols.Krb5;

/// <summary>
/// Formats an AS-REP enc-part into the crackable "AS-REP roast" string, matching impacket's
/// <c>GetNPUsers.py</c> output (hashcat mode 18200 / john). The layout differs between RC4 and
/// AES because the integrity checksum sits at different ends of the ciphertext.
/// </summary>
public static class AsRepRoast
{
    /// <summary>Hashcat-format AS-REP roast string for the given enc-part.</summary>
    public static string Hashcat(int etype, string user, string realm, byte[] cipher)
    {
        realm = realm.ToUpperInvariant();
        if (etype is Krb5Constants.Aes128CtsHmacSha1 or Krb5Constants.Aes256CtsHmacSha1)
        {
            // AES: checksum is the trailing 12 bytes.
            string tag = Hex(cipher[^12..]);
            string data = Hex(cipher[..^12]);
            return $"$krb5asrep${etype}${user}${realm}${tag}${data}";
        }

        // RC4 (and others): checksum is the leading 16 bytes, after a ':'.
        string sum = Hex(cipher[..16]);
        string rest = Hex(cipher[16..]);
        return $"$krb5asrep${etype}${user}@{realm}:{sum}${rest}";
    }

    /// <summary>John-format AS-REP roast string for the given enc-part.</summary>
    public static string John(int etype, string user, string realm, byte[] cipher)
    {
        realm = realm.ToUpperInvariant();
        if (etype is Krb5Constants.Aes128CtsHmacSha1 or Krb5Constants.Aes256CtsHmacSha1)
        {
            string data = Hex(cipher[..^12]);
            string tag = Hex(cipher[^12..]);
            return $"$krb5asrep${etype}${realm}{user}${data}${tag}";
        }

        string sum = Hex(cipher[..16]);
        string rest = Hex(cipher[16..]);
        return $"$krb5asrep${user}@{realm}:{sum}${rest}";
    }

    private static string Hex(ReadOnlySpan<byte> b) => Convert.ToHexString(b).ToLowerInvariant();
}
