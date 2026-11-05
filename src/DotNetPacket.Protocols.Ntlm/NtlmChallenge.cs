using System.Text;
using DotNetPacket.Core;

namespace DotNetPacket.Protocols.Ntlm;

/// <summary>
/// NTLMSSP CHALLENGE message (Type 2, MS-NLMP 2.2.1.2) parser. Extracts the fields
/// the client needs to build the AUTHENTICATE response: the negotiate flags, the
/// 8-byte server challenge, and the target-info AV_PAIR list.
/// </summary>
public sealed class NtlmChallenge
{
    public uint NegotiateFlags { get; private set; }

    public byte[] ServerChallenge { get; private set; } = new byte[8];

    public string TargetName { get; private set; } = string.Empty;

    public byte[] TargetInfo { get; private set; } = Array.Empty<byte>();

    /// <summary>
    /// The 8-byte OS VERSION field (MS-NLMP 2.2.2.10), present only when the server
    /// sets NEGOTIATE_VERSION. Empty otherwise. Layout: ProductMajor(1), ProductMinor(1),
    /// ProductBuild(2 LE), Reserved(3), NTLMRevisionCurrent(1).
    /// </summary>
    public byte[] Version { get; private set; } = Array.Empty<byte>();

    /// <summary>True when the server disclosed its OS version block.</summary>
    public bool HasVersion => Version.Length >= 4;

    public byte OsMajor => HasVersion ? Version[0] : (byte)0;

    public byte OsMinor => HasVersion ? Version[1] : (byte)0;

    public ushort OsBuild => HasVersion ? (ushort)(Version[2] | (Version[3] << 8)) : (ushort)0;

    /// <summary>The raw message bytes, needed verbatim for the AUTHENTICATE MIC.</summary>
    public byte[] Raw { get; private set; } = Array.Empty<byte>();

    public static NtlmChallenge Parse(byte[] message)
    {
        var challenge = new NtlmChallenge { Raw = message };
        var reader = new ByteReader(message, ByteOrder.Little);

        byte[] signature = reader.ReadBytes(8);
        if (!signature.AsSpan().SequenceEqual(Ntlm.Signature))
        {
            throw new InvalidDataException("Buffer does not start with the NTLMSSP signature.");
        }

        uint messageType = reader.ReadUInt32();
        if (messageType != Ntlm.ChallengeMessage)
        {
            throw new InvalidDataException($"Expected CHALLENGE (2) message but found type {messageType}.");
        }

        ushort targetNameLength = reader.ReadUInt16();
        reader.ReadUInt16(); // MaxLen
        uint targetNameOffset = reader.ReadUInt32();

        challenge.NegotiateFlags = reader.ReadUInt32();
        challenge.ServerChallenge = reader.ReadBytes(8);
        reader.ReadBytes(8); // Reserved

        ushort targetInfoLength = reader.ReadUInt16();
        reader.ReadUInt16(); // MaxLen
        uint targetInfoOffset = reader.ReadUInt32();

        // The optional 8-byte VERSION field sits here (offset 48), before the payload,
        // only when the server negotiated NEGOTIATE_VERSION. A short message omits it.
        bool hasVersion = (challenge.NegotiateFlags & (uint)NtlmNegotiateFlags.NegotiateVersion) != 0;
        if (hasVersion && reader.Remaining >= 8)
        {
            challenge.Version = reader.ReadBytes(8);
        }

        if (targetNameLength > 0)
        {
            reader.Position = (int)targetNameOffset;
            byte[] nameBytes = reader.ReadBytes(targetNameLength);
            bool unicode = (challenge.NegotiateFlags & (uint)NtlmNegotiateFlags.NegotiateUnicode) != 0;
            challenge.TargetName = unicode
                ? Encoding.Unicode.GetString(nameBytes)
                : Encoding.ASCII.GetString(nameBytes);
        }

        if (targetInfoLength > 0)
        {
            reader.Position = (int)targetInfoOffset;
            challenge.TargetInfo = reader.ReadBytes(targetInfoLength);
        }

        return challenge;
    }
}
