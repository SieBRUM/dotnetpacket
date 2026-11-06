namespace DotNetPacket.Protocols.Krb5;

/// <summary>
/// Formats a service ticket's enc-part into the crackable "Kerberoast" string, matching impacket's
/// <c>GetUserSPNs.py</c> output (hashcat mode 13100 for RC4). As in impacket, the SPN's ':' is
/// written as '~'. RC4 puts the 16-byte checksum first; AES puts the 12-byte checksum last.
/// </summary>
public static class KerbTgsRoast
{
    public static string Hashcat(int etype, string user, string realm, string spn, byte[] cipher)
    {
        realm = realm.ToUpperInvariant();
        string safeSpn = spn.Replace(':', '~');
        if (etype is Krb5Constants.Aes128CtsHmacSha1 or Krb5Constants.Aes256CtsHmacSha1)
        {
            string tag = Hex(cipher[^12..]);
            string data = Hex(cipher[..^12]);
            return $"$krb5tgs${etype}${user}${realm}$*{safeSpn}*${tag}${data}";
        }

        // RC4 (and DES): checksum is the leading 16 bytes.
        string sum = Hex(cipher[..16]);
        string rest = Hex(cipher[16..]);
        return $"$krb5tgs${etype}$*{user}${realm}${safeSpn}*${sum}${rest}";
    }

    private static string Hex(ReadOnlySpan<byte> b) => Convert.ToHexString(b).ToLowerInvariant();
}
