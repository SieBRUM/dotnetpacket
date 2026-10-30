using System.Text;

namespace DotNetPacket.Core;

/// <summary>Hex-dump helpers for lab output so packed bytes can be eyeballed and diffed.</summary>
public static class Hex
{
    /// <summary>
    /// Formats <paramref name="data"/> as a classic offset / hex / ASCII dump,
    /// 16 bytes per line.
    /// </summary>
    public static string Dump(ReadOnlySpan<byte> data)
    {
        var sb = new StringBuilder();
        for (int i = 0; i < data.Length; i += 16)
        {
            sb.Append($"{i:x4}  ");
            int lineLength = Math.Min(16, data.Length - i);
            for (int j = 0; j < 16; j++)
            {
                sb.Append(j < lineLength ? $"{data[i + j]:x2} " : "   ");
                if (j == 7)
                {
                    sb.Append(' ');
                }
            }

            sb.Append(' ');
            for (int j = 0; j < lineLength; j++)
            {
                byte b = data[i + j];
                sb.Append(b is >= 0x20 and < 0x7f ? (char)b : '.');
            }

            sb.Append('\n');
        }

        return sb.ToString();
    }

    /// <summary>Formats <paramref name="data"/> as a single lowercase hex string.</summary>
    public static string ToHexString(ReadOnlySpan<byte> data)
    {
        var sb = new StringBuilder(data.Length * 2);
        foreach (byte b in data)
        {
            sb.Append($"{b:x2}");
        }

        return sb.ToString();
    }
}
