using NetPacket.Core;
using NetPacket.Protocols.Ntlm;
using NetPacket.Protocols.Smb;

// NetPacket examples runner — the lab harness, mirroring impacket's examples/ dir.
//
// Each example is a named command that builds and/or parses protocol structures
// so their wire bytes can be observed and diffed against stock impacket in the
// SOC lab. As protocol clients are ported, add their commands here (or, as they
// grow, as a class per example). Keep output observable: hex dumps, verbose logs.

if (args.Length == 0)
{
    PrintUsage();
    return 0;
}

switch (args[0])
{
    case "smb-header":
    {
        // Build a sample SMB_COM_NEGOTIATE header and show its 32 wire bytes.
        var header = new SmbHeader
        {
            Command = 0x72, // SMB_COM_NEGOTIATE
            Flags = 0x18,
            Flags2 = 0xC853,
            Mid = 1,
        };
        Console.WriteLine("SMBv1 header (impacket smb.SMB.SMBHeader):");
        Console.Write(Hex.Dump(header.Pack()));
        return 0;
    }

    case "ntlm-negotiate":
    {
        // Build a sample NTLMSSP NEGOTIATE message and show its wire bytes.
        var message = new NtlmNegotiate
        {
            NegotiateFlags = 0xE2088297,
            DomainName = string.Empty,
            Workstation = string.Empty,
        };
        Console.WriteLine("NTLMSSP NEGOTIATE (impacket ntlm.NTLMAuthNegotiate):");
        Console.Write(Hex.Dump(message.Pack()));
        return 0;
    }

    case "smb2-negotiate":
    {
        // Live SMB2 NEGOTIATE against a lab host, mirroring a modern Windows client.
        if (args.Length < 2)
        {
            Console.Error.WriteLine("usage: smb2-negotiate <host> [port]");
            return 2;
        }

        string host = args[1];
        int port = args.Length >= 3 ? int.Parse(args[2]) : 445;

        using var client = new Smb2Client();
        client.Connect(host, port);
        Smb2NegotiateResult result = client.Negotiate();
        Smb2NegotiateResponse response = result.Response;

        Console.WriteLine($"Connected to {host}:{port}");
        Console.WriteLine($"  Dialect:      0x{(ushort)response.DialectRevision:x4} ({response.DialectRevision})");
        Console.WriteLine($"  ServerGuid:   {Hex.ToHexString(response.ServerGuid)}");
        Console.WriteLine($"  SecurityMode: {response.SecurityMode}");
        Console.WriteLine($"  Capabilities: {response.Capabilities}");
        Console.WriteLine($"  SecBuffer:    {response.SecurityBufferLength} bytes (SPNEGO/GSS token)");
        Console.WriteLine();
        Console.WriteLine($"--> NEGOTIATE request ({result.RequestBytes.Length} bytes):");
        Console.Write(Hex.Dump(result.RequestBytes));
        Console.WriteLine($"<-- NEGOTIATE response ({result.ResponseBytes.Length} bytes):");
        Console.Write(Hex.Dump(result.ResponseBytes));
        return 0;
    }

    case "smb2-login":
    {
        // Live SMB2 NEGOTIATE + NTLMv2 SESSION_SETUP against a lab host.
        if (args.Length < 4)
        {
            Console.Error.WriteLine("usage: smb2-login <host> <user> <password> [domain] [port]");
            return 2;
        }

        string host = args[1];
        string user = args[2];
        string password = args[3];
        string domain = args.Length >= 5 ? args[4] : string.Empty;
        int port = args.Length >= 6 ? int.Parse(args[5]) : 445;

        using var client = new Smb2Client();
        client.Connect(host, port);
        Smb2NegotiateResult negotiate = client.Negotiate();
        Smb2LoginResult login = client.Login(domain, user, password);

        Console.WriteLine($"Connected to {host}:{port}");
        Console.WriteLine($"  Dialect:   0x{(ushort)negotiate.Response.DialectRevision:x4} ({negotiate.Response.DialectRevision})");
        Console.WriteLine($"  SessionId: 0x{login.SessionId:x16}");
        Console.WriteLine($"  Round 1:   {NtStatus.Describe(login.Round1Status)}");
        Console.WriteLine($"  Round 2:   {NtStatus.Describe(login.Round2Status)}");
        Console.WriteLine($"  Result:    {(login.Authenticated ? "AUTHENTICATED" : "FAILED")}");
        Console.WriteLine();
        Console.WriteLine($"--> SESSION_SETUP #1 ({login.Round1Request.Length} bytes):");
        Console.Write(Hex.Dump(login.Round1Request));
        Console.WriteLine($"<-- SESSION_SETUP #1 response ({login.Round1Response.Length} bytes):");
        Console.Write(Hex.Dump(login.Round1Response));
        Console.WriteLine($"--> SESSION_SETUP #2 ({login.Round2Request.Length} bytes):");
        Console.Write(Hex.Dump(login.Round2Request));
        Console.WriteLine($"<-- SESSION_SETUP #2 response ({login.Round2Response.Length} bytes):");
        Console.Write(Hex.Dump(login.Round2Response));
        return login.Authenticated ? 0 : 1;
    }

    case "smb2-connect":
    {
        // Live NEGOTIATE + NTLMv2 SESSION_SETUP + signed TREE_CONNECT to a share.
        if (args.Length < 5)
        {
            Console.Error.WriteLine("usage: smb2-connect <host> <share> <user> <password> [domain] [port]");
            return 2;
        }

        string host = args[1];
        string share = args[2];
        string user = args[3];
        string password = args[4];
        string domain = args.Length >= 6 ? args[5] : string.Empty;
        int port = args.Length >= 7 ? int.Parse(args[6]) : 445;

        using var client = new Smb2Client();
        client.Connect(host, port);
        Smb2NegotiateResult negotiate = client.Negotiate();
        Smb2LoginResult login = client.Login(domain, user, password);
        if (!login.Authenticated)
        {
            Console.Error.WriteLine($"Login failed: {NtStatus.Describe(login.Round2Status)}");
            return 1;
        }

        string uncPath = $@"\\{host}\{share}";
        Smb2TreeConnectResult tree = client.TreeConnect(uncPath);

        Console.WriteLine($"Connected to {host}:{port}");
        Console.WriteLine($"  Dialect:       0x{(ushort)negotiate.Response.DialectRevision:x4}");
        Console.WriteLine($"  Authenticated: yes (signing={(login.Signed ? "on" : "off")})");
        Console.WriteLine($"  TREE_CONNECT:  {NtStatus.Describe(tree.Status)} -> {uncPath}");
        if (tree.Connected)
        {
            Console.WriteLine($"  TreeId:        0x{tree.TreeId:x8}");
            Console.WriteLine($"  ShareType:     {tree.Response.ShareType}");
            Console.WriteLine($"  ShareFlags:    {tree.Response.ShareFlags}");
            Console.WriteLine($"  MaximalAccess: 0x{tree.Response.MaximalAccess:x8}");
            Console.WriteLine($"  ServerSig OK:  {tree.ServerSignatureValid}");
            uint disconnect = client.TreeDisconnect(tree.TreeId);
            Console.WriteLine($"  TREE_DISCONNECT: {NtStatus.Describe(disconnect)}");
        }

        return tree.Connected ? 0 : 1;
    }

    case "smb2-cat":
    {
        // Full file read: NEGOTIATE + SESSION_SETUP + TREE_CONNECT + CREATE + READ + CLOSE.
        if (args.Length < 6)
        {
            Console.Error.WriteLine("usage: smb2-cat <host> <share> <path> <user> <password> [domain] [port]");
            return 2;
        }

        string host = args[1];
        string share = args[2];
        string path = args[3];
        string user = args[4];
        string password = args[5];
        string domain = args.Length >= 7 ? args[6] : string.Empty;
        int port = args.Length >= 8 ? int.Parse(args[7]) : 445;

        using var client = new Smb2Client();
        client.Connect(host, port);
        client.Negotiate();
        Smb2LoginResult login = client.Login(domain, user, password);
        if (!login.Authenticated)
        {
            Console.Error.WriteLine($"Login failed: {NtStatus.Describe(login.Round2Status)}");
            return 1;
        }

        Smb2TreeConnectResult tree = client.TreeConnect($@"\\{host}\{share}");
        if (!tree.Connected)
        {
            Console.Error.WriteLine($"Tree connect failed: {NtStatus.Describe(tree.Status)}");
            return 1;
        }

        byte[] content = client.ReadFile(tree.TreeId, path);
        client.TreeDisconnect(tree.TreeId);

        Console.WriteLine($@"Read \\{host}\{share}\{path} ({content.Length} bytes, signing={(login.Signed ? "on" : "off")}):");
        Console.WriteLine("--------");
        Console.Out.Write(System.Text.Encoding.UTF8.GetString(content));
        Console.WriteLine("--------");
        return 0;
    }

    case "-h":
    case "--help":
    case "help":
        PrintUsage();
        return 0;

    default:
        Console.Error.WriteLine($"Unknown command '{args[0]}'. Run with no arguments for usage.");
        return 1;
}

static void PrintUsage()
{
    Console.WriteLine("NetPacket examples (SOC lab harness)");
    Console.WriteLine();
    Console.WriteLine("Usage: netpacket-examples <command>");
    Console.WriteLine();
    Console.WriteLine("Commands:");
    Console.WriteLine("  smb-header       Build a sample SMBv1 header and hex-dump its bytes.");
    Console.WriteLine("  ntlm-negotiate   Build a sample NTLMSSP NEGOTIATE message and hex-dump its bytes.");
    Console.WriteLine("  smb2-negotiate <host> [port]");
    Console.WriteLine("                   Perform a live SMB2 NEGOTIATE against a host and dump both directions.");
    Console.WriteLine("  smb2-login <host> <user> <password> [domain] [port]");
    Console.WriteLine("                   Live SMB2 NEGOTIATE + NTLMv2 SESSION_SETUP; dump both handshake rounds.");
    Console.WriteLine("  smb2-connect <host> <share> <user> <password> [domain] [port]");
    Console.WriteLine("                   Full session: NEGOTIATE + SESSION_SETUP + signed TREE_CONNECT to a share.");
    Console.WriteLine("  smb2-cat <host> <share> <path> <user> <password> [domain] [port]");
    Console.WriteLine("                   Read a file over SMB2: TREE_CONNECT + CREATE + READ + CLOSE.");
    Console.WriteLine("  help             Show this help.");
}
