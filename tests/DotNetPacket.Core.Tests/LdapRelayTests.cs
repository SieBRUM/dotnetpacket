using System.Formats.Asn1;
using System.Net;
using System.Net.Sockets;
using DotNetPacket.Protocols.Ldap;
using DotNetPacket.Protocols.Ntlm;
using Xunit;

namespace DotNetPacket.Core.Tests;

public class LdapRelayTests
{
    // Minimal fake LDAP server for the two SASL-bind legs an LDAP relay drives:
    //   leg 1  -> bindResponse saslBindInProgress (14) with serverSaslCreds = SPNEGO(Type 2)
    //   leg 2  -> bindResponse success (0)
    [Fact]
    public void RelayBindLegs_DriveSaslBind_AndReturnChallengeThenSuccess()
    {
        byte[] type2 = new byte[] { 0x4E, 0x54, 0x4C, 0x4D, 0x53, 0x53, 0x50, 0x00, 0x02, 0xAA, 0xBB, 0xCC };
        byte[] saslCreds = Spnego.WrapChallenge(type2);

        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;

        Exception? serverError = null;
        var serverTask = System.Threading.Tasks.Task.Run(() =>
        {
            try
            {
                using TcpClient c = listener.AcceptTcpClient();
                using NetworkStream s = c.GetStream();
                ConsumeOneBerMessage(s);                          // bindRequest leg 1
                WriteBindResponse(s, 1, 14, saslCreds);          // saslBindInProgress + challenge
                ConsumeOneBerMessage(s);                          // bindRequest leg 2
                WriteBindResponse(s, 2, 0, null);                // success
                System.Threading.Thread.Sleep(200);              // let the client read leg 2 before close
            }
            catch (Exception ex)
            {
                serverError = ex;
            }
        });

        try
        {
            using var ldap = LdapConnection.Connect("127.0.0.1", port);
            byte[] gotType2 = ldap.RelayBindChallenge(new byte[] { 0x4E, 0x54, 0x4C, 0x4D, 0x53, 0x53, 0x50, 0x00, 0x01 });
            Assert.Equal(type2, gotType2);

            int result = ldap.RelayBindAuthenticate(new byte[] { 0x4E, 0x54, 0x4C, 0x4D, 0x53, 0x53, 0x50, 0x00, 0x03 }, null);
            Assert.Equal(0, result); // bind succeeded -> relay authenticated as the victim
        }
        catch (Exception) when (serverTask.Wait(2000) && serverError is not null)
        {
            throw new Xunit.Sdk.XunitException("fake LDAP server failed: " + serverError);
        }

        serverTask.Wait(10_000);
        listener.Stop();
    }

    private static void WriteBindResponse(NetworkStream s, int messageId, int resultCode, byte[]? serverSaslCreds)
    {
        var w = new AsnWriter(AsnEncodingRules.BER);
        using (w.PushSequence())                                 // LDAPMessage
        {
            w.WriteInteger(messageId);
            using (w.PushSequence(new Asn1Tag(TagClass.Application, 1, true))) // BindResponse [APP 1]
            {
                w.WriteEnumeratedValue((LdapRc)resultCode); // resultCode ENUMERATED
                w.WriteOctetString(ReadOnlySpan<byte>.Empty);   // matchedDN
                w.WriteOctetString(ReadOnlySpan<byte>.Empty);   // diagnosticMessage
                if (serverSaslCreds is not null)
                {
                    w.WriteOctetString(serverSaslCreds, new Asn1Tag(TagClass.ContextSpecific, 7, false)); // serverSaslCreds [7]
                }
            }
        }

        byte[] msg = w.Encode();
        s.Write(msg, 0, msg.Length);
        s.Flush();
    }

    // Reads and discards one complete BER-framed message (tag + length + content).
    private static void ConsumeOneBerMessage(NetworkStream s)
    {
        s.ReadByte();                                           // tag
        int first = s.ReadByte();
        int contentLength;
        if (first < 0x80)
        {
            contentLength = first;
        }
        else
        {
            int n = first & 0x7F;
            contentLength = 0;
            for (int i = 0; i < n; i++)
            {
                contentLength = (contentLength << 8) | s.ReadByte();
            }
        }

        for (int i = 0; i < contentLength; i++)
        {
            s.ReadByte();
        }
    }

    // LDAP result codes used by the fake server, so WriteEnumeratedValue emits the right ENUMERATED.
    private enum LdapRc
    {
        Success = 0,
        SaslBindInProgress = 14,
    }
}
