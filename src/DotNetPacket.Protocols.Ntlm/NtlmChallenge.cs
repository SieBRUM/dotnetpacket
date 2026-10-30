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
