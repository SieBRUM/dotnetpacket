using NetPacket.Core;
using NetPacket.Transport;

namespace NetPacket.Protocols.Smb;

/// <summary>Outcome of a negotiate exchange: the structures and the exact bytes seen on the wire.</summary>
public sealed class Smb2NegotiateResult
{
    public required Smb2NegotiateRequest Request { get; init; }

    public required byte[] RequestBytes { get; init; }

    public required byte[] ResponseBytes { get; init; }

    public required Smb2NegotiateResponse Response { get; init; }
}

/// <summary>
/// Minimal SMB2 client: performs the opening NEGOTIATE exchange against a server.
/// This is the first step of every SMB session and the cleanest realistic signal
/// to study. Session setup / auth build on top of this (tracked in PORTING_STATUS).
/// </summary>
public sealed class Smb2Client
{
    /// <summary>
    /// Connects to <paramref name="host"/>:<paramref name="port"/>, sends an SMB2
    /// NEGOTIATE, and parses the response. Returns both the parsed structures and
    /// the raw bytes for capture/diffing.
    /// </summary>
    public Smb2NegotiateResult Negotiate(string host, int port = 445, Smb2NegotiateRequest? request = null)
    {
        request ??= new Smb2NegotiateRequest();

        var header = new Smb2Header
        {
            Command = (ushort)Smb2Command.Negotiate,
            MessageId = 0,
            CreditRequest = 0,
        };

        var message = new ByteWriter(ByteOrder.Little);
        message.WriteBytes(header.Pack());
        request.PackInto(message);
        byte[] requestBytes = message.ToArray();

        using var transport = new DirectTcpTransport();
        transport.Connect(host, port);
        transport.SendMessage(requestBytes);
        byte[] responseBytes = transport.ReceiveMessage();

        var response = new Smb2NegotiateResponse();
        response.Unpack(responseBytes);

        return new Smb2NegotiateResult
        {
            Request = request,
            RequestBytes = requestBytes,
            ResponseBytes = responseBytes,
            Response = response,
        };
    }
}
