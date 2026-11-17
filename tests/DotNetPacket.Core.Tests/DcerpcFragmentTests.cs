using System;
using System.Collections.Generic;
using System.Linq;
using DotNetPacket.Protocols.Dcerpc;
using Xunit;

namespace DotNetPacket.Core.Tests;

/// <summary>
/// DCERPC fragmented-response reassembly. A response larger than the server's fragment size arrives
/// as several PDUs (PFC_FIRST_FRAG … PFC_LAST_FRAG); <see cref="DcerpcPipe.Call"/> must read every
/// fragment and concatenate their stub bodies. This regression pins the fix for the DCSync bulk dump,
/// where the DC fragments large GetNCChanges replies (the bug: only the first fragment was read, so
/// the trailing fragment desynced the next call).
/// </summary>
public class DcerpcFragmentTests
{
    [Fact]
    public void Call_ReassemblesMultiFragmentResponse()
    {
        byte[] part1 = Enumerable.Range(0, 100).Select(i => (byte)i).ToArray();
        byte[] part2 = Enumerable.Range(100, 50).Select(i => (byte)i).ToArray();
        byte[] part3 = Enumerable.Range(200, 25).Select(i => (byte)i).ToArray();

        var transport = new FakeTransport(new[]
        {
            ResponsePdu(part1, first: true, last: false),
            ResponsePdu(part2, first: false, last: false),
            ResponsePdu(part3, first: false, last: true),
        });

        byte[] stub = new DcerpcPipe(transport).Call(opnum: 3, stub: Array.Empty<byte>());
        Assert.Equal(part1.Concat(part2).Concat(part3).ToArray(), stub);
    }

    [Fact]
    public void Call_SingleFragmentResponse_ReturnsStubDirectly()
    {
        byte[] body = Enumerable.Range(0, 40).Select(i => (byte)i).ToArray();
        var transport = new FakeTransport(new[] { ResponsePdu(body, first: true, last: true) });
        Assert.Equal(body, new DcerpcPipe(transport).Call(opnum: 0, stub: Array.Empty<byte>()));
    }

    // A minimal unauthenticated DCERPC RESPONSE PDU carrying the given stub and PFC flags.
    private static byte[] ResponsePdu(byte[] stub, bool first, bool last)
    {
        byte pfc = (byte)((first ? 0x01 : 0) | (last ? 0x02 : 0));
        ushort fragLen = (ushort)(24 + stub.Length);
        var pdu = new List<byte>
        {
            0x05, 0x00,          // version 5.0
            0x02,                // PDU type = RESPONSE
            pfc,                 // PFC flags
            0x10, 0x00, 0x00, 0x00, // data representation (little-endian)
            (byte)fragLen, (byte)(fragLen >> 8), // frag_length
            0x00, 0x00,          // auth_length = 0
            0x01, 0x00, 0x00, 0x00, // call_id = 1
            0x00, 0x00, 0x00, 0x00, // alloc_hint
            0x00, 0x00,          // p_cont_id
            0x00,                // cancel_count
            0x00,                // reserved
        };
        pdu.AddRange(stub);
        return pdu.ToArray();
    }

    private sealed class FakeTransport : IDcerpcTransport
    {
        private readonly Queue<byte[]> _pdus;

        public FakeTransport(IEnumerable<byte[]> pdus) => _pdus = new Queue<byte[]>(pdus);

        public byte[] Transceive(byte[] pdu) => _pdus.Dequeue();

        public byte[] Receive() => _pdus.Dequeue();

        public void Send(byte[] pdu)
        {
        }

        public void Close()
        {
        }
    }
}
