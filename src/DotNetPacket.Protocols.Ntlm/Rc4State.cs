namespace DotNetPacket.Protocols.Ntlm;

/// <summary>
/// A stateful RC4 keystream cipher. Unlike <see cref="NtlmCrypto.Rc4"/> (which
/// re-keys on every call), this keeps the S-box and indices across calls so one
/// cipher handle can be used continuously — as NTLM connection-oriented sign/seal
/// requires (MS-NLMP 3.4: ClientHandle / ServerHandle). Encrypt and decrypt are
/// the same operation.
/// </summary>
public sealed class Rc4State
{
    private readonly byte[] _s = new byte[256];
    private int _x;
    private int _y;

    public Rc4State(byte[] key)
    {
        for (int i = 0; i < 256; i++)
        {
            _s[i] = (byte)i;
        }

        int j = 0;
        for (int i = 0; i < 256; i++)
        {
            j = (j + _s[i] + key[i % key.Length]) & 0xFF;
            (_s[i], _s[j]) = (_s[j], _s[i]);
        }
    }

    /// <summary>Processes <paramref name="data"/> against the current keystream position and advances it.</summary>
    public byte[] Process(byte[] data)
    {
        var output = new byte[data.Length];
        for (int k = 0; k < data.Length; k++)
        {
            _x = (_x + 1) & 0xFF;
            _y = (_y + _s[_x]) & 0xFF;
            (_s[_x], _s[_y]) = (_s[_y], _s[_x]);
            output[k] = (byte)(data[k] ^ _s[(_s[_x] + _s[_y]) & 0xFF]);
        }

        return output;
    }
}
