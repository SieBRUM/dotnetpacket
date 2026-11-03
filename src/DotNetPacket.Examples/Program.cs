using DotNetPacket.Core;
using DotNetPacket.Protocols.Dcerpc;
using DotNetPacket.Protocols.Ntlm;
using DotNetPacket.Protocols.Smb;

// DotNetPacket examples runner — the lab harness, mirroring impacket's examples/ dir.
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

    case "dcerpc-bind":
    {
        // NEGOTIATE + SESSION_SETUP + TREE_CONNECT(IPC$) + open pipe + DCERPC BIND.
        if (args.Length < 4)
        {
            Console.Error.WriteLine("usage: dcerpc-bind <host> <user> <password> [interface] [domain] [port]");
            Console.Error.WriteLine("  interface: srvsvc (default) | wkssvc | lsarpc | samr | svcctl");
            return 2;
        }

        string host = args[1];
        string user = args[2];
        string password = args[3];
        string interfaceName = args.Length >= 5 ? args[4] : "srvsvc";
        string domain = args.Length >= 6 ? args[5] : string.Empty;
        int port = args.Length >= 7 ? int.Parse(args[6]) : 445;

        DcerpcInterface? iface = DcerpcInterface.ByName(interfaceName);
        if (iface is null)
        {
            Console.Error.WriteLine($"Unknown interface '{interfaceName}'.");
            return 2;
        }

        using var client = new Smb2Client();
        client.Connect(host, port);
        client.Negotiate();
        Smb2LoginResult login = client.Login(domain, user, password);
        if (!login.Authenticated)
        {
            Console.Error.WriteLine($"Login failed: {NtStatus.Describe(login.Round2Status)}");
            return 1;
        }

        Smb2TreeConnectResult ipc = client.TreeConnect($@"\\{host}\IPC$");
        if (!ipc.Connected)
        {
            Console.Error.WriteLine($"IPC$ connect failed: {NtStatus.Describe(ipc.Status)}");
            return 1;
        }

        DcerpcPipe pipe = DcerpcPipe.Open(client, ipc.TreeId, iface.Pipe);
        DcerpcBindAck ack = pipe.Bind(iface);
        pipe.Close();
        client.TreeDisconnect(ipc.TreeId);

        Console.WriteLine($"Connected to {host}:{port}, IPC$ (signing={(login.Signed ? "on" : "off")})");
        Console.WriteLine($"  Pipe:         \\PIPE\\{iface.Pipe}");
        Console.WriteLine($"  Interface:    {iface.Name} {iface.Uuid} v{iface.VersionMajor}.{iface.VersionMinor}");
        Console.WriteLine($"  BIND reply:   {ack.PduType}");
        Console.WriteLine($"  Result:       {ack.Result} (reason {ack.Reason})");
        Console.WriteLine($"  SecondaryAddr: {ack.SecondaryAddress}");
        Console.WriteLine($"  Bound:        {(ack.Accepted ? "YES" : "NO")}");
        return ack.Accepted ? 0 : 1;
    }

    case "rpc-shares":
    {
        // Remote share enumeration via srvsvc NetrShareEnum (DCERPC over IPC$).
        if (args.Length < 4)
        {
            Console.Error.WriteLine("usage: rpc-shares <host> <user> <password> [domain] [port]");
            return 2;
        }

        string host = args[1];
        string user = args[2];
        string password = args[3];
        string domain = args.Length >= 5 ? args[4] : string.Empty;
        int port = args.Length >= 6 ? int.Parse(args[5]) : 445;

        using var client = new Smb2Client();
        client.Connect(host, port);
        client.Negotiate();
        Smb2LoginResult login = client.Login(domain, user, password);
        if (!login.Authenticated)
        {
            Console.Error.WriteLine($"Login failed: {NtStatus.Describe(login.Round2Status)}");
            return 1;
        }

        Smb2TreeConnectResult ipc = client.TreeConnect($@"\\{host}\IPC$");
        DcerpcPipe pipe = DcerpcPipe.Open(client, ipc.TreeId, DcerpcInterface.Srvsvc.Pipe);
        pipe.Bind(DcerpcInterface.Srvsvc);
        IReadOnlyList<ShareInfo1> shares = Srvsvc.NetrShareEnum(pipe);
        pipe.Close();
        client.TreeDisconnect(ipc.TreeId);

        Console.WriteLine($"Shares on {host} (via srvsvc NetrShareEnum, {shares.Count}):");
        Console.WriteLine($"  {"NAME",-16} {"TYPE",-10} REMARK");
        foreach (ShareInfo1 share in shares)
        {
            string type = share.Type + (share.IsSpecial ? "*" : string.Empty);
            Console.WriteLine($"  {share.Name,-16} {type,-10} {share.Remark}");
        }

        return 0;
    }

    case "rpc-shares-sealed":
    {
        // Same srvsvc NetrShareEnum, but over an NTLMSSP-authenticated bind with
        // per-PDU packet privacy (seal) or integrity (sign) — the sign/seal RPC a
        // modern Windows client speaks. Lets the SOC capture signed/sealed DCERPC.
        if (args.Length < 4)
        {
            Console.Error.WriteLine("usage: rpc-shares-sealed <host> <user> <password> [seal|sign] [domain] [port]");
            return 2;
        }

        string host = args[1];
        string user = args[2];
        string password = args[3];
        DcerpcAuthLevel level = args.Length >= 5 && args[4].Equals("sign", StringComparison.OrdinalIgnoreCase)
            ? DcerpcAuthLevel.PacketIntegrity
            : DcerpcAuthLevel.PacketPrivacy;
        string domain = args.Length >= 6 ? args[5] : string.Empty;
        int port = args.Length >= 7 ? int.Parse(args[6]) : 445;

        using var client = new Smb2Client();
        client.Connect(host, port);
        client.Negotiate();
        Smb2LoginResult login = client.Login(domain, user, password);
        if (!login.Authenticated)
        {
            Console.Error.WriteLine($"Login failed: {NtStatus.Describe(login.Round2Status)}");
            return 1;
        }

        Smb2TreeConnectResult ipc = client.TreeConnect($@"\\{host}\IPC$");
        DcerpcPipe pipe = DcerpcPipe.Open(client, ipc.TreeId, DcerpcInterface.Srvsvc.Pipe);
        DcerpcBindAck ack = pipe.BindAuthenticated(DcerpcInterface.Srvsvc, domain, user, password, level);
        if (!ack.Accepted)
        {
            Console.Error.WriteLine($"Authenticated bind rejected (result {ack.Result}, reason {ack.Reason}).");
            return 1;
        }

        IReadOnlyList<ShareInfo1> shares = Srvsvc.NetrShareEnum(pipe);
        pipe.Close();
        client.TreeDisconnect(ipc.TreeId);

        string levelName = level == DcerpcAuthLevel.PacketPrivacy ? "PKT_PRIVACY (seal)" : "PKT_INTEGRITY (sign)";
        Console.WriteLine($"Shares on {host} (srvsvc NetrShareEnum over NTLMSSP {levelName}, {shares.Count}):");
        Console.WriteLine($"  {"NAME",-16} {"TYPE",-10} REMARK");
        foreach (ShareInfo1 share in shares)
        {
            string type = share.Type + (share.IsSpecial ? "*" : string.Empty);
            Console.WriteLine($"  {share.Name,-16} {type,-10} {share.Remark}");
        }

        return 0;
    }

    case "rpc-dump":
    {
        // Enumerate the RPC interfaces registered on an endpoint via the mgmt
        // interface (rpc_mgmt_inq_if_ids) — the impacket rpcdump.py recon behavior.
        if (args.Length < 4)
        {
            Console.Error.WriteLine("usage: rpc-dump <host> <user> <password> [domain] [port]");
            return 2;
        }

        string host = args[1];
        string user = args[2];
        string password = args[3];
        string domain = args.Length >= 5 ? args[4] : string.Empty;
        int port = args.Length >= 6 ? int.Parse(args[5]) : 445;

        using var client = new Smb2Client();
        client.Connect(host, port);
        client.Negotiate();
        Smb2LoginResult login = client.Login(domain, user, password);
        if (!login.Authenticated)
        {
            Console.Error.WriteLine($"Login failed: {NtStatus.Describe(login.Round2Status)}");
            return 1;
        }

        Smb2TreeConnectResult ipc = client.TreeConnect($@"\\{host}\IPC$");
        DcerpcPipe pipe = DcerpcPipe.Open(client, ipc.TreeId, DcerpcInterface.Mgmt.Pipe);
        pipe.Bind(DcerpcInterface.Mgmt);
        IReadOnlyList<DcerpcInterfaceId> ifaces = Mgmt.InquireInterfaceIds(pipe);
        pipe.Close();
        client.TreeDisconnect(ipc.TreeId);

        Console.WriteLine($"RPC interfaces registered on {host} (via mgmt inq_if_ids, {ifaces.Count}):");
        foreach (DcerpcInterfaceId iface in ifaces)
        {
            Console.WriteLine($"  {iface}");
        }

        return 0;
    }

    case "rpc-dump-tcp":
    {
        // DCERPC directly over TCP (ncacn_ip_tcp) to the endpoint mapper on 135 —
        // no SMB, anonymous bind — then enumerate the endpoint's interfaces via
        // mgmt inq_if_ids. Demonstrates the TCP transport the rpcdump.py / epmapper
        // path uses.
        if (args.Length < 2)
        {
            Console.Error.WriteLine("usage: rpc-dump-tcp <host> [port]");
            return 2;
        }

        string host = args[1];
        int port = args.Length >= 3 ? int.Parse(args[2]) : 135;

        DcerpcPipe pipe = DcerpcPipe.OverTcp(host, port);
        DcerpcBindAck ack = pipe.Bind(DcerpcInterface.Mgmt);
        if (!ack.Accepted)
        {
            Console.Error.WriteLine($"Bind rejected (result {ack.Result}, reason {ack.Reason}).");
            return 1;
        }

        IReadOnlyList<DcerpcInterfaceId> ifaces = Mgmt.InquireInterfaceIds(pipe);
        pipe.Close();

        Console.WriteLine($"RPC interfaces on {host}:{port} over ncacn_ip_tcp (mgmt inq_if_ids, {ifaces.Count}):");
        foreach (DcerpcInterfaceId iface in ifaces)
        {
            Console.WriteLine($"  {iface}");
        }

        return 0;
    }

    case "rpc-getarch":
    {
        // Detect the target RPC runtime's architecture (impacket getarch): bind the
        // endpoint mapper offering two presentation contexts — NDR (ctx 0) and NDR64
        // (ctx 1). A modern x64 Windows host accepts the NDR64 context; a 32-bit host
        // or a non-Windows stack (Samba) rejects it. No SMB, anonymous.
        if (args.Length < 2)
        {
            Console.Error.WriteLine("usage: rpc-getarch <host> [port]");
            return 2;
        }

        string host = args[1];
        int port = args.Length >= 3 ? int.Parse(args[2]) : 135;

        DcerpcPipe pipe = DcerpcPipe.OverTcp(host, port);
        DcerpcBindAck ack = pipe.BindProbe(
            DcerpcInterface.Mgmt, Dcerpc.Ndr64TransferSyntax, Dcerpc.Ndr64VersionMajor, Dcerpc.Ndr64VersionMinor);
        pipe.Close();

        bool ndr64Accepted = ack.Results.Count >= 2
            && ack.Results[1].Result == DcerpcBindAck.ContextResult.Acceptance;

        Console.WriteLine($"Architecture probe of {host}:{port} (NDR + NDR64 bind):");
        for (int i = 0; i < ack.Results.Count; i++)
        {
            string syntax = i == 0 ? "NDR  (32-bit)" : "NDR64 (64-bit)";
            Console.WriteLine($"  ctx {i}: {syntax,-14} -> {ack.Results[i].Result} (reason {ack.Results[i].Reason})");
        }

        Console.WriteLine(ndr64Accepted
            ? "  => NDR64 accepted: target is x64 (Windows)."
            : "  => NDR64 rejected: x86 or a non-Windows RPC stack (e.g. Samba).");
        return 0;
    }

    case "rpc-epm-map":
    {
        // Ask the endpoint mapper (TCP/135) which dynamic ncacn_ip_tcp port an
        // interface listens on — the ept_map call a Windows RPC client makes before
        // connecting to a TCP-bound service (drsuapi, samr, lsarpc, ...).
        if (args.Length < 2)
        {
            Console.Error.WriteLine("usage: rpc-epm-map <host> [interface=samr] [port=135]");
            Console.Error.WriteLine("       interfaces: srvsvc wkssvc lsarpc samr svcctl winreg");
            return 2;
        }

        string host = args[1];
        string ifaceName = args.Length >= 3 ? args[2] : "samr";
        int port = args.Length >= 4 ? int.Parse(args[3]) : 135;

        DcerpcInterface? target = DcerpcInterface.ByName(ifaceName);
        if (target is null)
        {
            Console.Error.WriteLine($"Unknown interface '{ifaceName}'. Known: srvsvc wkssvc lsarpc samr svcctl winreg.");
            return 2;
        }

        DcerpcPipe pipe = DcerpcPipe.OverTcp(host, port);
        DcerpcBindAck ack = pipe.Bind(DcerpcInterface.Epm);
        if (!ack.Accepted)
        {
            Console.Error.WriteLine($"Bind to endpoint mapper rejected (result {ack.Result}, reason {ack.Reason}).");
            return 1;
        }

        EpmMapResult? mapped = Epm.MapTcp(pipe, target);
        pipe.Close();

        if (mapped is null)
        {
            Console.WriteLine($"{host}: endpoint mapper has no ncacn_ip_tcp binding for {ifaceName}.");
            return 0;
        }

        Console.WriteLine($"{ifaceName} ({target.Uuid} v{target.VersionMajor}.{target.VersionMinor}) on {host}:");
        Console.WriteLine($"  {mapped}");
        return 0;
    }

    case "rpc-samr-tcp":
    {
        // The full Windows-style RPC-over-TCP flow: ask the endpoint mapper (135)
        // for samr's dynamic port, connect straight to it over ncacn_ip_tcp, bind
        // with NTLMSSP packet privacy (sign+seal), then enumerate the SAM domains
        // and their users. No SMB anywhere — this is how a modern client reaches a
        // TCP-bound RPC service.
        if (args.Length < 4)
        {
            Console.Error.WriteLine("usage: rpc-samr-tcp <host> <user> <password> [domain] [epm-port]");
            return 2;
        }

        string host = args[1];
        string user = args[2];
        string password = args[3];
        string domain = args.Length >= 5 ? args[4] : string.Empty;
        int epmPort = args.Length >= 6 ? int.Parse(args[5]) : 135;

        // 1) Resolve samr's dynamic TCP port via the endpoint mapper.
        DcerpcPipe mapper = DcerpcPipe.OverTcp(host, epmPort);
        if (!mapper.Bind(DcerpcInterface.Epm).Accepted)
        {
            Console.Error.WriteLine("Bind to endpoint mapper rejected.");
            return 1;
        }

        EpmMapResult? mapped = Epm.MapTcp(mapper, DcerpcInterface.Samr);
        mapper.Close();
        if (mapped is null)
        {
            Console.Error.WriteLine("Endpoint mapper has no ncacn_ip_tcp binding for samr.");
            return 1;
        }

        Console.WriteLine($"samr endpoint on {host}: {mapped}  (resolved via ept_map)");

        // 2) Connect to the resolved port and bind samr with packet privacy.
        DcerpcPipe pipe = DcerpcPipe.OverTcp(host, mapped.Port);
        DcerpcBindAck ack = pipe.BindAuthenticated(
            DcerpcInterface.Samr, domain, user, password, DcerpcAuthLevel.PacketPrivacy);
        if (!ack.Accepted)
        {
            Console.Error.WriteLine($"Authenticated samr bind over TCP rejected (result {ack.Result}, reason {ack.Reason}).");
            return 1;
        }

        // 3) samrdump over TCP: connect, enumerate domains, enumerate users.
        SamrHandleResult server = Samr.Connect(pipe);
        SamrEnumResult domains = Samr.EnumerateDomains(pipe, server.Handle);
        Console.WriteLine($"SAM domains (over ncacn_ip_tcp, sealed): {string.Join(", ", domains.Entries.Select(d => d.Name))}");

        string accountDomain = domains.Entries.Count > 0 ? domains.Entries[0].Name : string.Empty;
        (SamrSid? sid, uint lookupRc) = Samr.LookupDomain(pipe, server.Handle, accountDomain);
        if (sid is not null)
        {
            SamrHandleResult dom = Samr.OpenDomain(pipe, server.Handle, sid);
            SamrEnumResult users = Samr.EnumerateUsers(pipe, dom.Handle);
            Console.WriteLine($"Users in {accountDomain} ({sid}), {users.Entries.Count}:");
            foreach (SamrRidEntry u in users.Entries)
            {
                Console.WriteLine($"  RID {u.Rid,-6} {u.Name}");
            }

            Samr.CloseHandle(pipe, dom.Handle);
        }
        else
        {
            Console.WriteLine($"LookupDomain failed: 0x{lookupRc:X8}");
        }

        Samr.CloseHandle(pipe, server.Handle);
        pipe.Close();
        return 0;
    }

    case "rpc-services":
    {
        // List the installed services via svcctl REnumServicesStatusW (the impacket
        // services.py "list" recon). Read-only: opens the SCM with ENUMERATE access,
        // enumerates, and prints each service's name, state, and display name.
        if (args.Length < 4)
        {
            Console.Error.WriteLine("usage: rpc-services <host> <user> <password> [domain] [port]");
            return 2;
        }

        string host = args[1];
        string user = args[2];
        string password = args[3];
        string domain = args.Length >= 5 ? args[4] : string.Empty;
        int port = args.Length >= 6 ? int.Parse(args[5]) : 445;

        using var client = new Smb2Client();
        client.Connect(host, port);
        client.Negotiate();
        Smb2LoginResult login = client.Login(domain, user, password);
        if (!login.Authenticated)
        {
            Console.Error.WriteLine($"Login failed: {NtStatus.Describe(login.Round2Status)}");
            return 1;
        }

        Smb2TreeConnectResult ipc = client.TreeConnect($@"\\{host}\IPC$");
        DcerpcPipe pipe = DcerpcPipe.Open(client, ipc.TreeId, DcerpcInterface.Svcctl.Pipe);
        pipe.Bind(DcerpcInterface.Svcctl);

        ScHandleResult scm = Svcctl.OpenScManager(pipe, null, ScManagerAccess.Connect | ScManagerAccess.EnumerateService);
        if (!scm.Success)
        {
            Console.Error.WriteLine($"OpenSCManager failed: {Svcctl.DescribeWin32(scm.ReturnCode)}");
            return 1;
        }

        IReadOnlyList<ServiceStatusEntry> services = Svcctl.EnumerateServices(pipe, scm.Handle);
        Svcctl.CloseServiceHandle(pipe, scm.Handle);
        pipe.Close();
        client.TreeDisconnect(ipc.TreeId);

        Console.WriteLine($"Services on {host} (via svcctl REnumServicesStatusW, {services.Count}):");
        Console.WriteLine($"  {"STATE",-14} {"NAME",-24} DISPLAY");
        foreach (ServiceStatusEntry svc in services)
        {
            Console.WriteLine($"  {svc.State,-14} {svc.Name,-24} {svc.DisplayName}");
        }

        return 0;
    }

    case "rpc-svcconfig":
    {
        // Read one service's configuration via svcctl RQueryServiceConfigW
        // (services.py per-service detail): binary path, start type, logon account.
        if (args.Length < 5)
        {
            Console.Error.WriteLine("usage: rpc-svcconfig <host> <user> <password> <service> [domain] [port]");
            return 2;
        }

        string host = args[1];
        string user = args[2];
        string password = args[3];
        string serviceName = args[4];
        string domain = args.Length >= 6 ? args[5] : string.Empty;
        int port = args.Length >= 7 ? int.Parse(args[6]) : 445;

        using var client = new Smb2Client();
        client.Connect(host, port);
        client.Negotiate();
        Smb2LoginResult login = client.Login(domain, user, password);
        if (!login.Authenticated)
        {
            Console.Error.WriteLine($"Login failed: {NtStatus.Describe(login.Round2Status)}");
            return 1;
        }

        Smb2TreeConnectResult ipc = client.TreeConnect($@"\\{host}\IPC$");
        DcerpcPipe pipe = DcerpcPipe.Open(client, ipc.TreeId, DcerpcInterface.Svcctl.Pipe);
        pipe.Bind(DcerpcInterface.Svcctl);

        ScHandleResult scm = Svcctl.OpenScManager(pipe, null, ScManagerAccess.Connect);
        if (!scm.Success)
        {
            Console.Error.WriteLine($"OpenSCManager failed: {Svcctl.DescribeWin32(scm.ReturnCode)}");
            return 1;
        }

        ScHandleResult svc = Svcctl.OpenService(pipe, scm.Handle, serviceName, ServiceAccess.QueryConfig);
        if (!svc.Success)
        {
            Console.Error.WriteLine($"OpenService({serviceName}) failed: {Svcctl.DescribeWin32(svc.ReturnCode)}");
            return 1;
        }

        ServiceConfig cfg = Svcctl.QueryServiceConfig(pipe, svc.Handle);
        Svcctl.CloseServiceHandle(pipe, svc.Handle);
        Svcctl.CloseServiceHandle(pipe, scm.Handle);
        pipe.Close();
        client.TreeDisconnect(ipc.TreeId);

        Console.WriteLine($"Service config for {serviceName} on {host}:");
        Console.WriteLine($"  Display name:  {cfg.DisplayName}");
        Console.WriteLine($"  Binary path:   {cfg.BinaryPath}");
        Console.WriteLine($"  Start type:    {cfg.StartTypeName}");
        Console.WriteLine($"  Service type:  0x{cfg.ServiceType:x}");
        Console.WriteLine($"  Logon account: {cfg.StartName}");
        if (!string.IsNullOrEmpty(cfg.Dependencies))
        {
            Console.WriteLine($"  Dependencies:  {cfg.Dependencies}");
        }

        return 0;
    }

    case "rpc-svcstatus":
    {
        // Query one service's live SERVICE_STATUS via svcctl RQueryServiceStatus (opnum 6):
        // run state, accepted control codes, last exit codes.
        if (args.Length < 5)
        {
            Console.Error.WriteLine("usage: rpc-svcstatus <host> <user> <password> <service> [domain] [port]");
            return 2;
        }

        string host = args[1];
        string user = args[2];
        string password = args[3];
        string serviceName = args[4];
        string domain = args.Length >= 6 ? args[5] : string.Empty;
        int port = args.Length >= 7 ? int.Parse(args[6]) : 445;

        using var client = new Smb2Client();
        client.Connect(host, port);
        client.Negotiate();
        Smb2LoginResult login = client.Login(domain, user, password);
        if (!login.Authenticated)
        {
            Console.Error.WriteLine($"Login failed: {NtStatus.Describe(login.Round2Status)}");
            return 1;
        }

        Smb2TreeConnectResult ipc = client.TreeConnect($@"\\{host}\IPC$");
        DcerpcPipe pipe = DcerpcPipe.Open(client, ipc.TreeId, DcerpcInterface.Svcctl.Pipe);
        pipe.Bind(DcerpcInterface.Svcctl);

        ScHandleResult scm = Svcctl.OpenScManager(pipe, null, ScManagerAccess.Connect);
        if (!scm.Success)
        {
            Console.Error.WriteLine($"OpenSCManager failed: {Svcctl.DescribeWin32(scm.ReturnCode)}");
            return 1;
        }

        ScHandleResult svc = Svcctl.OpenService(pipe, scm.Handle, serviceName, ServiceAccess.QueryStatus);
        if (!svc.Success)
        {
            Console.Error.WriteLine($"OpenService({serviceName}) failed: {Svcctl.DescribeWin32(svc.ReturnCode)}");
            return 1;
        }

        ServiceStatus status = Svcctl.QueryServiceStatus(pipe, svc.Handle);
        Svcctl.CloseServiceHandle(pipe, svc.Handle);
        Svcctl.CloseServiceHandle(pipe, scm.Handle);
        pipe.Close();
        client.TreeDisconnect(ipc.TreeId);

        Console.WriteLine($"Service status for {serviceName} on {host}:");
        Console.WriteLine($"  Current state:      {status.State}");
        Console.WriteLine($"  Service type:       0x{status.ServiceType:x}");
        Console.WriteLine($"  Controls accepted:  {status.ControlsAcceptedText}");
        Console.WriteLine($"  Win32 exit code:    {status.Win32ExitCode}");
        if (status.ServiceSpecificExitCode != 0)
        {
            Console.WriteLine($"  Specific exit code: {status.ServiceSpecificExitCode}");
        }
        if (status.CheckPoint != 0 || status.WaitHint != 0)
        {
            Console.WriteLine($"  Checkpoint/wait:    {status.CheckPoint} / {status.WaitHint} ms");
        }

        return 0;
    }

    case "rpc-svcctl":
    {
        // Lab-only: generate the remote service-creation ("psexec") wire signature
        // via svcctl. Opens the SCM, attempts to create a BENIGN marker service,
        // and reports exactly what the server returns. Nothing destructive.
        if (args.Length < 4)
        {
            Console.Error.WriteLine("usage: rpc-svcctl <host> <user> <password> [domain] [port]");
            return 2;
        }

        string host = args[1];
        string user = args[2];
        string password = args[3];
        string domain = args.Length >= 5 ? args[4] : string.Empty;
        int port = args.Length >= 6 ? int.Parse(args[5]) : 445;

        using var client = new Smb2Client();
        client.Connect(host, port);
        client.Negotiate();
        Smb2LoginResult login = client.Login(domain, user, password);
        if (!login.Authenticated)
        {
            Console.Error.WriteLine($"Login failed: {NtStatus.Describe(login.Round2Status)}");
            return 1;
        }

        Smb2TreeConnectResult ipc = client.TreeConnect($@"\\{host}\IPC$");
        DcerpcPipe pipe = DcerpcPipe.Open(client, ipc.TreeId, DcerpcInterface.Svcctl.Pipe);
        pipe.Bind(DcerpcInterface.Svcctl);

        Console.WriteLine($"svcctl on {host} (lab service-control demo):");

        // Try the access psexec requests; fall back to a modest access to still get a handle.
        ScHandleResult scm = Svcctl.OpenScManager(pipe, null, ScManagerAccess.AllAccess);
        Console.WriteLine($"  OpenSCManager(ALL_ACCESS):  {Svcctl.DescribeWin32(scm.ReturnCode)}");
        if (!scm.Success)
        {
            scm = Svcctl.OpenScManager(pipe, null, ScManagerAccess.Connect | ScManagerAccess.EnumerateService);
            Console.WriteLine($"  OpenSCManager(CONNECT):     {Svcctl.DescribeWin32(scm.ReturnCode)}");
        }

        if (scm.Success)
        {
            const string serviceName = "DotNetPacketLab";
            const string binaryPath = @"%SystemRoot%\System32\cmd.exe /c echo netpacket-lab-marker";
            try
            {
                ScHandleResult created = Svcctl.CreateService(
                    pipe, scm.Handle, serviceName, "DotNetPacket Lab Marker", binaryPath);
                Console.WriteLine($"  CreateService(\"{serviceName}\"): {Svcctl.DescribeWin32(created.ReturnCode)}");

                if (created.Success)
                {
                    // Clean up immediately — do not leave a service behind.
                    uint del = Svcctl.DeleteService(pipe, created.Handle);
                    Console.WriteLine($"  DeleteService (cleanup):    {Svcctl.DescribeWin32(del)}");
                    Svcctl.CloseServiceHandle(pipe, created.Handle);
                }
            }
            catch (DcerpcFaultException fault)
            {
                // e.g. Samba answers CreateServiceW with nca_op_rng_error (unimplemented) —
                // the request still went on the wire; that is the signature of interest.
                Console.WriteLine($"  CreateService(\"{serviceName}\"): DCERPC fault 0x{fault.Status:X8} (rejected/unsupported by server)");
            }

            uint closed = Svcctl.CloseServiceHandle(pipe, scm.Handle);
            Console.WriteLine($"  CloseServiceHandle:         {Svcctl.DescribeWin32(closed)}");
        }

        pipe.Close();
        client.TreeDisconnect(ipc.TreeId);
        return 0;
    }

    case "rpc-hostinfo":
    {
        // Host/OS recon via wkssvc NetrWkstaGetInfo + srvsvc NetrServerGetInfo.
        if (args.Length < 4)
        {
            Console.Error.WriteLine("usage: rpc-hostinfo <host> <user> <password> [domain] [port]");
            return 2;
        }

        string host = args[1];
        string user = args[2];
        string password = args[3];
        string domain = args.Length >= 5 ? args[4] : string.Empty;
        int port = args.Length >= 6 ? int.Parse(args[5]) : 445;

        using var client = new Smb2Client();
        client.Connect(host, port);
        client.Negotiate();
        Smb2LoginResult login = client.Login(domain, user, password);
        if (!login.Authenticated)
        {
            Console.Error.WriteLine($"Login failed: {NtStatus.Describe(login.Round2Status)}");
            return 1;
        }

        Smb2TreeConnectResult ipc = client.TreeConnect($@"\\{host}\IPC$");

        DcerpcPipe wkssvc = DcerpcPipe.Open(client, ipc.TreeId, DcerpcInterface.Wkssvc.Pipe);
        wkssvc.Bind(DcerpcInterface.Wkssvc);
        WkstaInfo100 wksta = Wkssvc.NetrWkstaGetInfo(wkssvc);
        wkssvc.Close();

        DcerpcPipe srvsvc = DcerpcPipe.Open(client, ipc.TreeId, DcerpcInterface.Srvsvc.Pipe);
        srvsvc.Bind(DcerpcInterface.Srvsvc);
        ServerInfo101 server = Srvsvc.NetrServerGetInfo(srvsvc);
        srvsvc.Close();

        client.TreeDisconnect(ipc.TreeId);

        Console.WriteLine($"Host info for {host}:");
        Console.WriteLine("  wkssvc NetrWkstaGetInfo(100):");
        Console.WriteLine($"    ComputerName: {wksta.ComputerName}");
        Console.WriteLine($"    Domain/Group: {wksta.LanGroup}");
        Console.WriteLine($"    OS version:   {wksta.VersionMajor}.{wksta.VersionMinor} (platform {wksta.PlatformId})");
        Console.WriteLine("  srvsvc NetrServerGetInfo(101):");
        Console.WriteLine($"    Name:         {server.Name}");
        Console.WriteLine($"    OS version:   {server.VersionMajor}.{server.VersionMinor}");
        Console.WriteLine($"    Server type:  0x{server.Type:x8}");
        Console.WriteLine($"    Comment:      {server.Comment}");
        return 0;
    }

    case "rpc-lsa":
    {
        // Domain recon via lsarpc: open the LSA policy and read the account domain + SID.
        if (args.Length < 4)
        {
            Console.Error.WriteLine("usage: rpc-lsa <host> <user> <password> [domain] [port]");
            return 2;
        }

        string host = args[1];
        string user = args[2];
        string password = args[3];
        string domain = args.Length >= 5 ? args[4] : string.Empty;
        int port = args.Length >= 6 ? int.Parse(args[5]) : 445;

        using var client = new Smb2Client();
        client.Connect(host, port);
        client.Negotiate();
        Smb2LoginResult login = client.Login(domain, user, password);
        if (!login.Authenticated)
        {
            Console.Error.WriteLine($"Login failed: {NtStatus.Describe(login.Round2Status)}");
            return 1;
        }

        Smb2TreeConnectResult ipc = client.TreeConnect($@"\\{host}\IPC$");
        DcerpcPipe pipe = DcerpcPipe.Open(client, ipc.TreeId, DcerpcInterface.Lsarpc.Pipe);
        pipe.Bind(DcerpcInterface.Lsarpc);

        ScHandleResult policy = Lsarpc.OpenPolicy2(pipe);
        Console.WriteLine($"LSA policy on {host}:");
        Console.WriteLine($"  OpenPolicy2: {(policy.Success ? "OK" : $"0x{policy.ReturnCode:X8}")}");
        if (policy.Success)
        {
            LsaAccountDomain account = Lsarpc.QueryAccountDomain(pipe, policy.Handle);
            Console.WriteLine($"  Account domain: {account.Name}");
            Console.WriteLine($"  Account SID:    {account.Sid}");

            // DNS/forest identity (QueryInformationPolicy2 level 12) — only a DC answers.
            try
            {
                LsaDnsDomain dns = Lsarpc.QueryDnsDomain(pipe, policy.Handle);
                if (dns.Success && !string.IsNullOrEmpty(dns.DnsDomainName))
                {
                    Console.WriteLine($"  DNS domain:     {dns.DnsDomainName}");
                    Console.WriteLine($"  DNS forest:     {dns.DnsForestName}");
                    Console.WriteLine($"  Domain GUID:    {dns.DomainGuid}");
                    Console.WriteLine($"  Domain SID:     {dns.Sid}");
                }
            }
            catch (DcerpcFaultException)
            {
                // Not a DC (standalone servers fault on level 12) — account-domain info stands.
            }

            Lsarpc.Close(pipe, policy.Handle);
        }

        pipe.Close();
        client.TreeDisconnect(ipc.TreeId);
        return 0;
    }

    case "rpc-privs":
    {
        // Enumerate the privileges the LSA knows via lsarpc LsarEnumeratePrivileges
        // (the enum4linux privilege-enumeration recon).
        if (args.Length < 4)
        {
            Console.Error.WriteLine("usage: rpc-privs <host> <user> <password> [domain] [port]");
            return 2;
        }

        string host = args[1];
        string user = args[2];
        string password = args[3];
        string domain = args.Length >= 5 ? args[4] : string.Empty;
        int port = args.Length >= 6 ? int.Parse(args[5]) : 445;

        using var client = new Smb2Client();
        client.Connect(host, port);
        client.Negotiate();
        Smb2LoginResult login = client.Login(domain, user, password);
        if (!login.Authenticated)
        {
            Console.Error.WriteLine($"Login failed: {NtStatus.Describe(login.Round2Status)}");
            return 1;
        }

        Smb2TreeConnectResult ipc = client.TreeConnect($@"\\{host}\IPC$");
        DcerpcPipe pipe = DcerpcPipe.Open(client, ipc.TreeId, DcerpcInterface.Lsarpc.Pipe);
        pipe.Bind(DcerpcInterface.Lsarpc);

        ScHandleResult policy = Lsarpc.OpenPolicy2(pipe);
        if (!policy.Success)
        {
            Console.Error.WriteLine($"OpenPolicy2 failed: 0x{policy.ReturnCode:X8}");
            return 1;
        }

        IReadOnlyList<LsaPrivilege> privs = Lsarpc.EnumeratePrivileges(pipe, policy.Handle);
        Lsarpc.Close(pipe, policy.Handle);
        pipe.Close();
        client.TreeDisconnect(ipc.TreeId);

        Console.WriteLine($"LSA privileges on {host} (via LsarEnumeratePrivileges, {privs.Count}):");
        foreach (LsaPrivilege p in privs)
        {
            Console.WriteLine($"  LUID {p.LuidHigh}:{p.LuidLow,-4} {p.Name}");
        }

        return 0;
    }

    case "rpc-accountrights":
    {
        // List the LSA rights/privileges granted to one account SID via lsarpc
        // LsarEnumerateAccountRights (the "who can do what" recon behind tools that
        // audit SeDebugPrivilege/SeBackupPrivilege holders).
        if (args.Length < 5)
        {
            Console.Error.WriteLine("usage: rpc-accountrights <host> <user> <password> <sid> [domain] [port]");
            Console.Error.WriteLine("  e.g. rpc-accountrights 127.0.0.1 Administrator 'pass' S-1-5-32-550 LAB");
            return 2;
        }

        string host = args[1];
        string user = args[2];
        string password = args[3];
        string sid = args[4];
        string domain = args.Length >= 6 ? args[5] : string.Empty;
        int port = args.Length >= 7 ? int.Parse(args[6]) : 445;

        using var client = new Smb2Client();
        client.Connect(host, port);
        client.Negotiate();
        Smb2LoginResult login = client.Login(domain, user, password);
        if (!login.Authenticated)
        {
            Console.Error.WriteLine($"Login failed: {NtStatus.Describe(login.Round2Status)}");
            return 1;
        }

        Smb2TreeConnectResult ipc = client.TreeConnect($@"\\{host}\IPC$");
        DcerpcPipe pipe = DcerpcPipe.Open(client, ipc.TreeId, DcerpcInterface.Lsarpc.Pipe);
        pipe.Bind(DcerpcInterface.Lsarpc);

        ScHandleResult policy = Lsarpc.OpenPolicy2(pipe);
        if (!policy.Success)
        {
            Console.Error.WriteLine($"OpenPolicy2 failed: 0x{policy.ReturnCode:X8}");
            return 1;
        }

        LsaAccountRights rights = Lsarpc.EnumerateAccountRights(pipe, policy.Handle, sid);
        Lsarpc.Close(pipe, policy.Handle);
        pipe.Close();
        client.TreeDisconnect(ipc.TreeId);

        if (rights.NotFound)
        {
            Console.WriteLine($"{sid}: no LSA account object (no rights directly assigned).");
            return 0;
        }

        if (!rights.Success)
        {
            Console.Error.WriteLine($"LsarEnumerateAccountRights failed: 0x{rights.Status:X8}");
            return 1;
        }

        Console.WriteLine($"Account rights for {sid} on {host} ({rights.Rights.Count}):");
        foreach (string r in rights.Rights)
        {
            Console.WriteLine($"  {r}");
        }

        return 0;
    }

    case "rpc-lookupsid":
    {
        // SID->name recon via lsat LsarLookupSids (the lookupsid behavior).
        if (args.Length < 4)
        {
            Console.Error.WriteLine("usage: rpc-lookupsid <host> <user> <password> [domain] [port]");
            return 2;
        }

        string host = args[1];
        string user = args[2];
        string password = args[3];
        string domain = args.Length >= 5 ? args[4] : string.Empty;
        int port = args.Length >= 6 ? int.Parse(args[5]) : 445;

        using var client = new Smb2Client();
        client.Connect(host, port);
        client.Negotiate();
        Smb2LoginResult login = client.Login(domain, user, password);
        if (!login.Authenticated)
        {
            Console.Error.WriteLine($"Login failed: {NtStatus.Describe(login.Round2Status)}");
            return 1;
        }

        Smb2TreeConnectResult ipc = client.TreeConnect($@"\\{host}\IPC$");
        DcerpcPipe pipe = DcerpcPipe.Open(client, ipc.TreeId, DcerpcInterface.Lsarpc.Pipe);
        pipe.Bind(DcerpcInterface.Lsarpc);

        ScHandleResult policy = Lsarpc.OpenPolicy2(pipe);
        LsaAccountDomain account = Lsarpc.QueryAccountDomain(pipe, policy.Handle);

        // Well-known SIDs plus a few account-domain RIDs (classic lookupsid recon).
        var sids = new List<string> { "S-1-5-32-544", "S-1-5-32-545", "S-1-1-0", "S-1-5-18" };
        if (!string.IsNullOrEmpty(account.Sid))
        {
            foreach (int rid in new[] { 500, 501, 512, 513 })
            {
                sids.Add($"{account.Sid}-{rid}");
            }
        }

        IReadOnlyList<LsaResolvedSid> resolved = Lsat.LookupSids(pipe, policy.Handle, sids);
        Lsarpc.Close(pipe, policy.Handle);
        pipe.Close();
        client.TreeDisconnect(ipc.TreeId);

        Console.WriteLine($"SID lookups on {host} (account domain {account.Name} = {account.Sid}):");
        foreach (LsaResolvedSid r in resolved)
        {
            bool ok = r.Use != SidNameUse.Unknown && r.Use != SidNameUse.Invalid && !string.IsNullOrEmpty(r.Name);
            string label = ok ? $"{r.Display} ({r.Use})" : "(unresolved)";
            Console.WriteLine($"  {r.InputSid,-48} {label}");
        }

        return 0;
    }

    case "rpc-lookupsid2":
    {
        // SID->name recon via lsat LsarLookupSids2 (opnum 57) — the variant modern Windows
        // clients use (adds LookupOptions + ClientRevision; EX translated-name records).
        if (args.Length < 4)
        {
            Console.Error.WriteLine("usage: rpc-lookupsid2 <host> <user> <password> [domain] [port]");
            return 2;
        }

        string host = args[1];
        string user = args[2];
        string password = args[3];
        string domain = args.Length >= 5 ? args[4] : string.Empty;
        int port = args.Length >= 6 ? int.Parse(args[5]) : 445;

        using var client = new Smb2Client();
        client.Connect(host, port);
        client.Negotiate();
        Smb2LoginResult login = client.Login(domain, user, password);
        if (!login.Authenticated)
        {
            Console.Error.WriteLine($"Login failed: {NtStatus.Describe(login.Round2Status)}");
            return 1;
        }

        Smb2TreeConnectResult ipc = client.TreeConnect($@"\\{host}\IPC$");
        DcerpcPipe pipe = DcerpcPipe.Open(client, ipc.TreeId, DcerpcInterface.Lsarpc.Pipe);
        pipe.Bind(DcerpcInterface.Lsarpc);

        ScHandleResult policy = Lsarpc.OpenPolicy2(pipe);
        LsaAccountDomain account = Lsarpc.QueryAccountDomain(pipe, policy.Handle);

        var sids = new List<string> { "S-1-5-32-544", "S-1-5-32-545", "S-1-1-0", "S-1-5-18" };
        if (!string.IsNullOrEmpty(account.Sid))
        {
            foreach (int rid in new[] { 500, 501, 512, 513 })
            {
                sids.Add($"{account.Sid}-{rid}");
            }
        }

        IReadOnlyList<LsaResolvedSid> resolved = Lsat.LookupSids2(pipe, policy.Handle, sids);
        Lsarpc.Close(pipe, policy.Handle);
        pipe.Close();
        client.TreeDisconnect(ipc.TreeId);

        Console.WriteLine($"SID lookups (LookupSids2) on {host} (account domain {account.Name} = {account.Sid}):");
        foreach (LsaResolvedSid r in resolved)
        {
            bool ok = r.Use != SidNameUse.Unknown && r.Use != SidNameUse.Invalid && !string.IsNullOrEmpty(r.Name);
            string label = ok ? $"{r.Display} ({r.Use})" : "(unresolved)";
            Console.WriteLine($"  {r.InputSid,-48} {label}");
        }

        return 0;
    }

    case "rpc-enumusers":
    {
        // Domain user enumeration via samr (the samrdump / enumdomusers behavior).
        if (args.Length < 4)
        {
            Console.Error.WriteLine("usage: rpc-enumusers <host> <user> <password> [domain] [port]");
            return 2;
        }

        string host = args[1];
        string user = args[2];
        string password = args[3];
        string domain = args.Length >= 5 ? args[4] : string.Empty;
        int port = args.Length >= 6 ? int.Parse(args[5]) : 445;

        using var client = new Smb2Client();
        client.Connect(host, port);
        client.Negotiate();
        Smb2LoginResult login = client.Login(domain, user, password);
        if (!login.Authenticated)
        {
            Console.Error.WriteLine($"Login failed: {NtStatus.Describe(login.Round2Status)}");
            return 1;
        }

        Smb2TreeConnectResult ipc = client.TreeConnect($@"\\{host}\IPC$");
        DcerpcPipe pipe = DcerpcPipe.Open(client, ipc.TreeId, DcerpcInterface.Samr.Pipe);
        pipe.Bind(DcerpcInterface.Samr);

        SamrHandleResult server = Samr.Connect(pipe);
        SamrEnumResult domains = Samr.EnumerateDomains(pipe, server.Handle);

        Console.WriteLine($"SAM on {host} — domains: {string.Join(", ", domains.Entries.Select(d => d.Name))}");

        // The first SAM domain is the account domain (the built-in domain is second).
        string accountDomain = domains.Entries.Count > 0 ? domains.Entries[0].Name : string.Empty;
        (SamrSid? sid, uint lookupRc) = Samr.LookupDomain(pipe, server.Handle, accountDomain);
        if (sid is not null)
        {
            SamrHandleResult dom = Samr.OpenDomain(pipe, server.Handle, sid);
            SamrEnumResult users = Samr.EnumerateUsers(pipe, dom.Handle);

            Console.WriteLine($"Users in {accountDomain} ({sid}), {users.Entries.Count}:");
            foreach (SamrRidEntry u in users.Entries)
            {
                SamrHandleResult uh = Samr.OpenUser(pipe, dom.Handle, u.Rid);
                if (uh.Success)
                {
                    SamrUserGeneral info = Samr.QueryUserGeneralInfo(pipe, uh.Handle);
                    string full = string.IsNullOrEmpty(info.FullName) ? "" : $" ({info.FullName})";
                    Console.WriteLine($"  RID {u.Rid,-6} {u.Name}{full}  primaryGroup={info.PrimaryGroupId}");
                    Samr.CloseHandle(pipe, uh.Handle);
                }
                else
                {
                    Console.WriteLine($"  RID {u.Rid,-6} {u.Name}");
                }
            }

            Samr.CloseHandle(pipe, dom.Handle);
        }
        else
        {
            Console.WriteLine($"LookupDomain failed: 0x{lookupRc:X8}");
        }

        Samr.CloseHandle(pipe, server.Handle);
        pipe.Close();
        client.TreeDisconnect(ipc.TreeId);
        return 0;
    }

    case "rpc-dispinfo":
    {
        // Domain user display enumeration via samr SamrQueryDisplayInformation level 1
        // (the samrdump display path): RID + account-control flags + name/description/full name
        // for every user in a single enumeration, no per-user OpenUser round-trips.
        if (args.Length < 4)
        {
            Console.Error.WriteLine("usage: rpc-dispinfo <host> <user> <password> [domain] [port]");
            return 2;
        }

        string host = args[1];
        string user = args[2];
        string password = args[3];
        string domain = args.Length >= 5 ? args[4] : string.Empty;
        int port = args.Length >= 6 ? int.Parse(args[5]) : 445;

        using var client = new Smb2Client();
        client.Connect(host, port);
        client.Negotiate();
        Smb2LoginResult login = client.Login(domain, user, password);
        if (!login.Authenticated)
        {
            Console.Error.WriteLine($"Login failed: {NtStatus.Describe(login.Round2Status)}");
            return 1;
        }

        Smb2TreeConnectResult ipc = client.TreeConnect($@"\\{host}\IPC$");
        DcerpcPipe pipe = DcerpcPipe.Open(client, ipc.TreeId, DcerpcInterface.Samr.Pipe);
        pipe.Bind(DcerpcInterface.Samr);

        SamrHandleResult server = Samr.Connect(pipe);
        SamrEnumResult domains = Samr.EnumerateDomains(pipe, server.Handle);
        string accountDomain = domains.Entries.Count > 0 ? domains.Entries[0].Name : string.Empty;
        (SamrSid? sid, uint lookupRc) = Samr.LookupDomain(pipe, server.Handle, accountDomain);
        if (sid is null)
        {
            Console.Error.WriteLine($"LookupDomain failed: 0x{lookupRc:X8}");
            Samr.CloseHandle(pipe, server.Handle);
            pipe.Close();
            client.TreeDisconnect(ipc.TreeId);
            return 1;
        }

        SamrHandleResult dom = Samr.OpenDomain(pipe, server.Handle, sid);
        IReadOnlyList<SamrDisplayUser> users = Samr.QueryDisplayUsers(pipe, dom.Handle);
        Samr.CloseHandle(pipe, dom.Handle);
        Samr.CloseHandle(pipe, server.Handle);
        pipe.Close();
        client.TreeDisconnect(ipc.TreeId);

        Console.WriteLine($"Display info for {accountDomain} ({sid}) on {host} — {users.Count} users:");
        foreach (SamrDisplayUser u in users)
        {
            string full = string.IsNullOrEmpty(u.FullName) ? string.Empty : $" \"{u.FullName}\"";
            Console.WriteLine($"  [{u.Index}] RID {u.Rid,-6} {u.AccountName}{full}");
            if (!string.IsNullOrEmpty(u.AdminComment))
            {
                Console.WriteLine($"          desc: {u.AdminComment}");
            }
            Console.WriteLine($"          flags: {u.AccountControlText}");
        }

        return 0;
    }

    case "rpc-userinfo":
    {
        // Per-user detail via samr SamrQueryInformationUser2 class 21 (SAMPR_USER_ALL_INFORMATION) —
        // the account record samrdump prints: timestamps, account-control flags, counters.
        if (args.Length < 5)
        {
            Console.Error.WriteLine("usage: rpc-userinfo <host> <user> <password> <target-user> [domain] [port]");
            return 2;
        }

        string host = args[1];
        string user = args[2];
        string password = args[3];
        string targetUser = args[4];
        string domain = args.Length >= 6 ? args[5] : string.Empty;
        int port = args.Length >= 7 ? int.Parse(args[6]) : 445;

        using var client = new Smb2Client();
        client.Connect(host, port);
        client.Negotiate();
        Smb2LoginResult login = client.Login(domain, user, password);
        if (!login.Authenticated)
        {
            Console.Error.WriteLine($"Login failed: {NtStatus.Describe(login.Round2Status)}");
            return 1;
        }

        Smb2TreeConnectResult ipc = client.TreeConnect($@"\\{host}\IPC$");
        DcerpcPipe pipe = DcerpcPipe.Open(client, ipc.TreeId, DcerpcInterface.Samr.Pipe);
        pipe.Bind(DcerpcInterface.Samr);

        SamrHandleResult server = Samr.Connect(pipe);
        SamrEnumResult domains = Samr.EnumerateDomains(pipe, server.Handle);
        string accountDomain = domains.Entries.Count > 0 ? domains.Entries[0].Name : string.Empty;
        (SamrSid? sid, uint lookupRc) = Samr.LookupDomain(pipe, server.Handle, accountDomain);
        if (sid is null)
        {
            Console.WriteLine($"LookupDomain failed: 0x{lookupRc:X8}");
            Samr.CloseHandle(pipe, server.Handle);
            pipe.Close();
            client.TreeDisconnect(ipc.TreeId);
            return 1;
        }

        SamrHandleResult dom = Samr.OpenDomain(pipe, server.Handle, sid);

        // Resolve the target name -> RID directly via SamrLookupNamesInDomain (one RPC)
        // instead of walking the whole user enumeration.
        SamrNameMapping resolved = Samr.LookupNames(pipe, dom.Handle, new[] { targetUser })[0];
        if (!resolved.Resolved)
        {
            Console.WriteLine($"User '{targetUser}' not found in {accountDomain} (SID_NAME_USE={resolved.UseName}).");
            Samr.CloseHandle(pipe, dom.Handle);
            Samr.CloseHandle(pipe, server.Handle);
            pipe.Close();
            client.TreeDisconnect(ipc.TreeId);
            return 1;
        }

        SamrHandleResult uh = Samr.OpenUser(pipe, dom.Handle, resolved.Rid);
        SamrUserAll d = Samr.QueryUserAllInfo(pipe, uh.Handle);

        static string Ft(DateTime? t) => t is null ? "(never)" : t.Value.ToString("yyyy-MM-dd HH:mm:ss 'UTC'");

        Console.WriteLine($"User detail for {accountDomain}\\{d.UserName} (RID {d.UserId}):");
        if (!string.IsNullOrEmpty(d.FullName))    Console.WriteLine($"  Full name          : {d.FullName}");
        if (!string.IsNullOrEmpty(d.AdminComment)) Console.WriteLine($"  Description        : {d.AdminComment}");
        Console.WriteLine($"  Primary group RID  : {d.PrimaryGroupId}");
        Console.WriteLine($"  Account control    : 0x{d.UserAccountControl:X8} [{d.AccountFlagsText}]");
        Console.WriteLine($"  Bad password count : {d.BadPasswordCount}");
        Console.WriteLine($"  Logon count        : {d.LogonCount}");
        Console.WriteLine($"  Password last set  : {Ft(Samr.FileTimeToUtc(d.PasswordLastSet))}");
        Console.WriteLine($"  Password must chg  : {Ft(Samr.FileTimeToUtc(d.PasswordMustChange))}");
        Console.WriteLine($"  Last logon         : {Ft(Samr.FileTimeToUtc(d.LastLogon))}");
        Console.WriteLine($"  Account expires    : {Ft(Samr.FileTimeToUtc(d.AccountExpires))}");

        // Group memberships via SamrGetGroupsForUser (opnum 39), with the group RIDs resolved
        // back to names via SamrLookupIdsInDomain (opnum 18) so custom groups show too.
        IReadOnlyList<SamrGroupMembership> groups = Samr.GetGroupsForUser(pipe, uh.Handle);
        Console.WriteLine($"  Group memberships  : {groups.Count}");
        if (groups.Count > 0)
        {
            uint[] groupRids = groups.Select(g => g.Rid).ToArray();
            IReadOnlyList<SamrNameMapping> names = Samr.LookupIds(pipe, dom.Handle, groupRids);
            for (int i = 0; i < groups.Count; i++)
            {
                string label = !string.IsNullOrEmpty(names[i].Name) ? names[i].Name : groups[i].GroupName;
                Console.WriteLine($"    - {label,-32} (RID {groups[i].Rid}, {groups[i].AttributesText})");
            }
        }

        Samr.CloseHandle(pipe, uh.Handle);
        Samr.CloseHandle(pipe, dom.Handle);
        Samr.CloseHandle(pipe, server.Handle);
        pipe.Close();
        client.TreeDisconnect(ipc.TreeId);
        return 0;
    }

    case "rpc-lookuprid":
    {
        // Name -> RID resolution via samr SamrLookupNamesInDomain (opnum 17): the reverse of
        // rpc-lookupsid, and how name-based tools map accounts to RIDs before opening them.
        if (args.Length < 5)
        {
            Console.Error.WriteLine("usage: rpc-lookuprid <host> <user> <password> <names-csv> [domain] [port]");
            return 2;
        }

        string host = args[1];
        string user = args[2];
        string password = args[3];
        string[] targets = args[4].Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        string domain = args.Length >= 6 ? args[5] : string.Empty;
        int port = args.Length >= 7 ? int.Parse(args[6]) : 445;

        using var client = new Smb2Client();
        client.Connect(host, port);
        client.Negotiate();
        Smb2LoginResult login = client.Login(domain, user, password);
        if (!login.Authenticated)
        {
            Console.Error.WriteLine($"Login failed: {NtStatus.Describe(login.Round2Status)}");
            return 1;
        }

        Smb2TreeConnectResult ipc = client.TreeConnect($@"\\{host}\IPC$");
        DcerpcPipe pipe = DcerpcPipe.Open(client, ipc.TreeId, DcerpcInterface.Samr.Pipe);
        pipe.Bind(DcerpcInterface.Samr);

        SamrHandleResult server = Samr.Connect(pipe);
        SamrEnumResult domains = Samr.EnumerateDomains(pipe, server.Handle);
        string accountDomain = domains.Entries.Count > 0 ? domains.Entries[0].Name : string.Empty;
        (SamrSid? sid, uint lookupRc) = Samr.LookupDomain(pipe, server.Handle, accountDomain);
        if (sid is null)
        {
            Console.WriteLine($"LookupDomain failed: 0x{lookupRc:X8}");
            Samr.CloseHandle(pipe, server.Handle);
            pipe.Close();
            client.TreeDisconnect(ipc.TreeId);
            return 1;
        }

        SamrHandleResult dom = Samr.OpenDomain(pipe, server.Handle, sid);
        IReadOnlyList<SamrNameMapping> rows = Samr.LookupNames(pipe, dom.Handle, targets);

        Console.WriteLine($"Name -> RID in {accountDomain} ({sid}):");
        foreach (SamrNameMapping row in rows)
        {
            Console.WriteLine(row.Resolved
                ? $"  {row.Name,-24} RID {row.Rid,-6} {row.UseName}"
                : $"  {row.Name,-24} (unresolved: {row.UseName})");
        }

        Samr.CloseHandle(pipe, dom.Handle);
        Samr.CloseHandle(pipe, server.Handle);
        pipe.Close();
        client.TreeDisconnect(ipc.TreeId);
        return 0;
    }

    case "rpc-lookupid":
    {
        // RID -> name resolution via samr SamrLookupIdsInDomain (opnum 18): the reverse of
        // rpc-lookuprid, and how a tool turns RIDs (e.g. from a group membership) into names.
        if (args.Length < 5)
        {
            Console.Error.WriteLine("usage: rpc-lookupid <host> <user> <password> <rids-csv> [domain] [port]");
            return 2;
        }

        string host = args[1];
        string user = args[2];
        string password = args[3];
        uint[] targetRids = args[4]
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(uint.Parse).ToArray();
        string domain = args.Length >= 6 ? args[5] : string.Empty;
        int port = args.Length >= 7 ? int.Parse(args[6]) : 445;

        using var client = new Smb2Client();
        client.Connect(host, port);
        client.Negotiate();
        Smb2LoginResult login = client.Login(domain, user, password);
        if (!login.Authenticated)
        {
            Console.Error.WriteLine($"Login failed: {NtStatus.Describe(login.Round2Status)}");
            return 1;
        }

        Smb2TreeConnectResult ipc = client.TreeConnect($@"\\{host}\IPC$");
        DcerpcPipe pipe = DcerpcPipe.Open(client, ipc.TreeId, DcerpcInterface.Samr.Pipe);
        pipe.Bind(DcerpcInterface.Samr);

        SamrHandleResult server = Samr.Connect(pipe);
        SamrEnumResult domains = Samr.EnumerateDomains(pipe, server.Handle);
        string accountDomain = domains.Entries.Count > 0 ? domains.Entries[0].Name : string.Empty;
        (SamrSid? sid, uint lookupRc) = Samr.LookupDomain(pipe, server.Handle, accountDomain);
        if (sid is null)
        {
            Console.WriteLine($"LookupDomain failed: 0x{lookupRc:X8}");
            Samr.CloseHandle(pipe, server.Handle);
            pipe.Close();
            client.TreeDisconnect(ipc.TreeId);
            return 1;
        }

        SamrHandleResult dom = Samr.OpenDomain(pipe, server.Handle, sid);
        IReadOnlyList<SamrNameMapping> rows = Samr.LookupIds(pipe, dom.Handle, targetRids);

        Console.WriteLine($"RID -> name in {accountDomain} ({sid}):");
        foreach (SamrNameMapping row in rows)
        {
            Console.WriteLine(row.Resolved
                ? $"  RID {row.Rid,-6} {row.Name,-28} {row.UseName}"
                : $"  RID {row.Rid,-6} (unresolved: {row.UseName})");
        }

        Samr.CloseHandle(pipe, dom.Handle);
        Samr.CloseHandle(pipe, server.Handle);
        pipe.Close();
        client.TreeDisconnect(ipc.TreeId);
        return 0;
    }

    case "rpc-enumgroups":
    {
        // Domain group + alias enumeration via samr (the samrdump groups behavior):
        // SamrEnumerateGroupsInDomain (opnum 11) + SamrEnumerateAliasesInDomain (15).
        if (args.Length < 4)
        {
            Console.Error.WriteLine("usage: rpc-enumgroups <host> <user> <password> [domain] [port]");
            return 2;
        }

        string host = args[1];
        string user = args[2];
        string password = args[3];
        string domain = args.Length >= 5 ? args[4] : string.Empty;
        int port = args.Length >= 6 ? int.Parse(args[5]) : 445;

        using var client = new Smb2Client();
        client.Connect(host, port);
        client.Negotiate();
        Smb2LoginResult login = client.Login(domain, user, password);
        if (!login.Authenticated)
        {
            Console.Error.WriteLine($"Login failed: {NtStatus.Describe(login.Round2Status)}");
            return 1;
        }

        Smb2TreeConnectResult ipc = client.TreeConnect($@"\\{host}\IPC$");
        DcerpcPipe pipe = DcerpcPipe.Open(client, ipc.TreeId, DcerpcInterface.Samr.Pipe);
        pipe.Bind(DcerpcInterface.Samr);

        SamrHandleResult server = Samr.Connect(pipe);
        SamrEnumResult domains = Samr.EnumerateDomains(pipe, server.Handle);
        string accountDomain = domains.Entries.Count > 0 ? domains.Entries[0].Name : string.Empty;
        (SamrSid? sid, uint lookupRc) = Samr.LookupDomain(pipe, server.Handle, accountDomain);

        if (sid is not null)
        {
            SamrHandleResult dom = Samr.OpenDomain(pipe, server.Handle, sid);
            SamrEnumResult groups = Samr.EnumerateGroups(pipe, dom.Handle);
            SamrEnumResult aliases = Samr.EnumerateAliases(pipe, dom.Handle);

            Console.WriteLine($"Groups in {accountDomain} ({sid}), {groups.Entries.Count}:");
            foreach (SamrRidEntry g in groups.Entries)
            {
                Console.WriteLine($"  RID {g.Rid,-6} {g.Name}");
            }

            Console.WriteLine($"Aliases in {accountDomain}, {aliases.Entries.Count}:");
            foreach (SamrRidEntry a in aliases.Entries)
            {
                Console.WriteLine($"  RID {a.Rid,-6} {a.Name}");
            }

            Samr.CloseHandle(pipe, dom.Handle);
        }
        else
        {
            Console.WriteLine($"LookupDomain failed: 0x{lookupRc:X8}");
        }

        Samr.CloseHandle(pipe, server.Handle);
        pipe.Close();
        client.TreeDisconnect(ipc.TreeId);
        return 0;
    }

    case "rpc-passpol":
    {
        // Domain password + lockout policy via samr SamrQueryInformationDomain
        // (the enum4linux / samrdump password-policy dump).
        if (args.Length < 4)
        {
            Console.Error.WriteLine("usage: rpc-passpol <host> <user> <password> [domain] [port]");
            return 2;
        }

        string host = args[1];
        string user = args[2];
        string password = args[3];
        string domain = args.Length >= 5 ? args[4] : string.Empty;
        int port = args.Length >= 6 ? int.Parse(args[5]) : 445;

        using var client = new Smb2Client();
        client.Connect(host, port);
        client.Negotiate();
        Smb2LoginResult login = client.Login(domain, user, password);
        if (!login.Authenticated)
        {
            Console.Error.WriteLine($"Login failed: {NtStatus.Describe(login.Round2Status)}");
            return 1;
        }

        Smb2TreeConnectResult ipc = client.TreeConnect($@"\\{host}\IPC$");
        DcerpcPipe pipe = DcerpcPipe.Open(client, ipc.TreeId, DcerpcInterface.Samr.Pipe);
        pipe.Bind(DcerpcInterface.Samr);

        SamrHandleResult server = Samr.Connect(pipe);
        SamrEnumResult domains = Samr.EnumerateDomains(pipe, server.Handle);
        string accountDomain = domains.Entries.Count > 0 ? domains.Entries[0].Name : string.Empty;
        (SamrSid? sid, uint lookupRc) = Samr.LookupDomain(pipe, server.Handle, accountDomain);

        if (sid is not null)
        {
            SamrHandleResult dom = Samr.OpenDomain(pipe, server.Handle, sid);
            SamrPasswordPolicy pw = Samr.QueryPasswordPolicy(pipe, dom.Handle);
            SamrLockoutPolicy lk = Samr.QueryLockoutPolicy(pipe, dom.Handle);

            static string Days(double? d) => d is null ? "none" : $"{d.Value:0.##} days";
            bool complex = (pw.PasswordProperties & 0x1) != 0; // DOMAIN_PASSWORD_COMPLEX

            Console.WriteLine($"Password policy for {accountDomain} ({sid}) on {host}:");
            Console.WriteLine($"  Minimum password length: {pw.MinPasswordLength}");
            Console.WriteLine($"  Password history length: {pw.PasswordHistoryLength}");
            Console.WriteLine($"  Maximum password age:    {Days(Samr.RelativeTimeToDays(pw.MaxPasswordAge))}");
            Console.WriteLine($"  Minimum password age:    {Days(Samr.RelativeTimeToDays(pw.MinPasswordAge))}");
            Console.WriteLine($"  Complexity required:     {complex} (properties 0x{pw.PasswordProperties:x8})");
            Console.WriteLine($"  Lockout threshold:       {(lk.LockoutThreshold == 0 ? "none" : lk.LockoutThreshold.ToString())}");
            Console.WriteLine($"  Lockout duration:        {Days(Samr.RelativeTimeToDays(lk.LockoutDuration))}");
            Console.WriteLine($"  Lockout observation:     {Days(Samr.RelativeTimeToDays(lk.LockoutObservationWindow))}");

            Samr.CloseHandle(pipe, dom.Handle);
        }
        else
        {
            Console.WriteLine($"LookupDomain failed: 0x{lookupRc:X8}");
        }

        Samr.CloseHandle(pipe, server.Handle);
        pipe.Close();
        client.TreeDisconnect(ipc.TreeId);
        return 0;
    }

    case "rpc-lookupnames":
    {
        // Name->SID recon via lsat LsarLookupNames (inverse of lookupsid).
        if (args.Length < 4)
        {
            Console.Error.WriteLine("usage: rpc-lookupnames <host> <user> <password> [names csv] [domain] [port]");
            return 2;
        }

        string host = args[1];
        string user = args[2];
        string password = args[3];
        string[] names = args.Length >= 5 ? args[4].Split(',') : new[] { "labuser", "Everyone", "Administrator" };
        string domain = args.Length >= 6 ? args[5] : string.Empty;
        int port = args.Length >= 7 ? int.Parse(args[6]) : 445;

        using var client = new Smb2Client();
        client.Connect(host, port);
        client.Negotiate();
        Smb2LoginResult login = client.Login(domain, user, password);
        if (!login.Authenticated)
        {
            Console.Error.WriteLine($"Login failed: {NtStatus.Describe(login.Round2Status)}");
            return 1;
        }

        Smb2TreeConnectResult ipc = client.TreeConnect($@"\\{host}\IPC$");
        DcerpcPipe pipe = DcerpcPipe.Open(client, ipc.TreeId, DcerpcInterface.Lsarpc.Pipe);
        pipe.Bind(DcerpcInterface.Lsarpc);

        ScHandleResult policy = Lsarpc.OpenPolicy2(pipe);
        IReadOnlyList<LsaResolvedName> resolved = Lsat.LookupNames(pipe, policy.Handle, names);
        Lsarpc.Close(pipe, policy.Handle);
        pipe.Close();
        client.TreeDisconnect(ipc.TreeId);

        Console.WriteLine($"Name lookups on {host}:");
        foreach (LsaResolvedName r in resolved)
        {
            bool ok = r.Use != SidNameUse.Unknown && r.Use != SidNameUse.Invalid && !string.IsNullOrEmpty(r.Sid);
            Console.WriteLine($"  {r.InputName,-20} {(ok ? $"{r.Sid} ({r.Use})" : "(unresolved)")}");
        }

        return 0;
    }

    case "rpc-lookupnames2":
    {
        // Name->SID recon via lsat LsarLookupNames2 (opnum 58) — the variant modern Windows
        // clients use (adds LookupOptions + ClientRevision; EX translated-SID records).
        if (args.Length < 4)
        {
            Console.Error.WriteLine("usage: rpc-lookupnames2 <host> <user> <password> [names csv] [domain] [port]");
            return 2;
        }

        string host = args[1];
        string user = args[2];
        string password = args[3];
        string[] names = args.Length >= 5 ? args[4].Split(',') : new[] { "Administrator", "Guest", "Domain Admins" };
        string domain = args.Length >= 6 ? args[5] : string.Empty;
        int port = args.Length >= 7 ? int.Parse(args[6]) : 445;

        using var client = new Smb2Client();
        client.Connect(host, port);
        client.Negotiate();
        Smb2LoginResult login = client.Login(domain, user, password);
        if (!login.Authenticated)
        {
            Console.Error.WriteLine($"Login failed: {NtStatus.Describe(login.Round2Status)}");
            return 1;
        }

        Smb2TreeConnectResult ipc = client.TreeConnect($@"\\{host}\IPC$");
        DcerpcPipe pipe = DcerpcPipe.Open(client, ipc.TreeId, DcerpcInterface.Lsarpc.Pipe);
        pipe.Bind(DcerpcInterface.Lsarpc);

        ScHandleResult policy = Lsarpc.OpenPolicy2(pipe);
        IReadOnlyList<LsaResolvedName> resolved = Lsat.LookupNames2(pipe, policy.Handle, names);
        Lsarpc.Close(pipe, policy.Handle);
        pipe.Close();
        client.TreeDisconnect(ipc.TreeId);

        Console.WriteLine($"Name lookups (LookupNames2) on {host}:");
        foreach (LsaResolvedName r in resolved)
        {
            bool ok = r.Use != SidNameUse.Unknown && r.Use != SidNameUse.Invalid && !string.IsNullOrEmpty(r.Sid);
            Console.WriteLine($"  {r.InputName,-20} {(ok ? $"{r.Sid} ({r.Use})" : "(unresolved)")}");
        }

        return 0;
    }

    case "rpc-reg":
    {
        // Remote-registry recon via winreg (MS-RRP): open HKLM, read its version,
        // open a subkey, then release the handles. The impacket reg.py surface.
        if (args.Length < 4)
        {
            Console.Error.WriteLine("usage: rpc-reg <host> <user> <password> [subkey] [domain] [port]");
            return 2;
        }

        string host = args[1];
        string user = args[2];
        string password = args[3];
        string subKey = args.Length >= 5 ? args[4] : @"SOFTWARE\Microsoft\Windows NT\CurrentVersion";
        string domain = args.Length >= 6 ? args[5] : string.Empty;
        int port = args.Length >= 7 ? int.Parse(args[6]) : 445;

        using var client = new Smb2Client();
        client.Connect(host, port);
        client.Negotiate();
        Smb2LoginResult login = client.Login(domain, user, password);
        if (!login.Authenticated)
        {
            Console.Error.WriteLine($"Login failed: {NtStatus.Describe(login.Round2Status)}");
            return 1;
        }

        Smb2TreeConnectResult ipc = client.TreeConnect($@"\\{host}\IPC$");
        DcerpcPipe pipe = DcerpcPipe.Open(client, ipc.TreeId, DcerpcInterface.Winreg.Pipe);
        pipe.Bind(DcerpcInterface.Winreg);

        Console.WriteLine($"Remote registry on {host}:");
        ScHandleResult hklm = Winreg.OpenHklm(pipe);
        Console.WriteLine($"  OpenHKLM:   {(hklm.Success ? "OK" : $"0x{hklm.ReturnCode:X8}")}");
        if (hklm.Success)
        {
            (uint version, uint vStatus) = Winreg.GetVersion(pipe, hklm.Handle);
            Console.WriteLine($"  GetVersion: {(vStatus == 0 ? version.ToString() : $"0x{vStatus:X8}")}");

            ScHandleResult key = Winreg.OpenKey(pipe, hklm.Handle, subKey);
            Console.WriteLine($"  OpenKey {subKey}: {(key.Success ? "OK" : $"0x{key.ReturnCode:X8}")}");
            if (key.Success)
            {
                Winreg.CloseKey(pipe, key.Handle);
            }

            Winreg.CloseKey(pipe, hklm.Handle);
        }

        pipe.Close();
        client.TreeDisconnect(ipc.TreeId);
        return 0;
    }

    case "rpc-regquery":
    {
        // Read a named registry value via winreg: OpenHKLM -> OpenKey(subkey) ->
        // BaseRegQueryValue(value). The reg.py "reg query KEY -v VALUE" recon.
        if (args.Length < 6)
        {
            Console.Error.WriteLine("usage: rpc-regquery <host> <user> <password> <subkey> <value> [domain] [port]");
            return 2;
        }

        string host = args[1];
        string user = args[2];
        string password = args[3];
        string subKey = args[4];
        string valueName = args[5];
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

        Smb2TreeConnectResult ipc = client.TreeConnect($@"\\{host}\IPC$");
        DcerpcPipe pipe = DcerpcPipe.Open(client, ipc.TreeId, DcerpcInterface.Winreg.Pipe);
        pipe.Bind(DcerpcInterface.Winreg);

        ScHandleResult hklm = Winreg.OpenHklm(pipe);
        if (!hklm.Success)
        {
            Console.Error.WriteLine($"OpenHKLM failed: 0x{hklm.ReturnCode:X8}");
            return 1;
        }

        ScHandleResult key = Winreg.OpenKey(pipe, hklm.Handle, subKey);
        if (!key.Success)
        {
            Console.Error.WriteLine($"OpenKey {subKey} failed: 0x{key.ReturnCode:X8}");
            return 1;
        }

        Winreg.RegValue value = Winreg.QueryValue(pipe, key.Handle, valueName);
        Winreg.CloseKey(pipe, key.Handle);
        Winreg.CloseKey(pipe, hklm.Handle);
        pipe.Close();
        client.TreeDisconnect(ipc.TreeId);

        if (!value.Success)
        {
            Console.WriteLine($"HKLM\\{subKey} : {valueName} -> query failed 0x{value.ReturnCode:X8}");
            return 0;
        }

        Console.WriteLine($"HKLM\\{subKey}");
        Console.WriteLine($"  {valueName}  ({value.TypeName})  =  {value.AsText}");
        return 0;
    }

    case "rpc-regenum":
    {
        // Enumerate all values under a registry key via winreg BaseRegEnumValue
        // (reg.py "reg query KEY" — list the key's values). OpenHKLM -> OpenKey -> loop.
        if (args.Length < 4)
        {
            Console.Error.WriteLine("usage: rpc-regenum <host> <user> <password> [subkey] [domain] [port]");
            return 2;
        }

        string host = args[1];
        string user = args[2];
        string password = args[3];
        string subKey = args.Length >= 5 ? args[4] : @"SOFTWARE\Microsoft\Windows NT\CurrentVersion";
        string domain = args.Length >= 6 ? args[5] : string.Empty;
        int port = args.Length >= 7 ? int.Parse(args[6]) : 445;

        using var client = new Smb2Client();
        client.Connect(host, port);
        client.Negotiate();
        Smb2LoginResult login = client.Login(domain, user, password);
        if (!login.Authenticated)
        {
            Console.Error.WriteLine($"Login failed: {NtStatus.Describe(login.Round2Status)}");
            return 1;
        }

        Smb2TreeConnectResult ipc = client.TreeConnect($@"\\{host}\IPC$");
        DcerpcPipe pipe = DcerpcPipe.Open(client, ipc.TreeId, DcerpcInterface.Winreg.Pipe);
        pipe.Bind(DcerpcInterface.Winreg);

        ScHandleResult hklm = Winreg.OpenHklm(pipe);
        if (!hklm.Success)
        {
            Console.Error.WriteLine($"OpenHKLM failed: 0x{hklm.ReturnCode:X8}");
            return 1;
        }

        ScHandleResult key = Winreg.OpenKey(pipe, hklm.Handle, subKey);
        if (!key.Success)
        {
            Console.Error.WriteLine($"OpenKey {subKey} failed: 0x{key.ReturnCode:X8}");
            return 1;
        }

        IReadOnlyList<Winreg.RegNamedValue> values = Winreg.EnumerateValues(pipe, key.Handle);
        Winreg.CloseKey(pipe, key.Handle);
        Winreg.CloseKey(pipe, hklm.Handle);
        pipe.Close();
        client.TreeDisconnect(ipc.TreeId);

        Console.WriteLine($"HKLM\\{subKey}  ({values.Count} values):");
        foreach (Winreg.RegNamedValue v in values)
        {
            Console.WriteLine($"  {v.Name,-20} ({v.TypeName})  =  {v.AsText}");
        }

        return 0;
    }

    case "rpc-regkeys":
    {
        // Enumerate a registry key's subkeys via winreg BaseRegEnumKey (reg.py key walk):
        // OpenHKLM -> OpenKey -> loop dwIndex until ERROR_NO_MORE_ITEMS.
        if (args.Length < 4)
        {
            Console.Error.WriteLine("usage: rpc-regkeys <host> <user> <password> [subkey] [domain] [port]");
            return 2;
        }

        string host = args[1];
        string user = args[2];
        string password = args[3];
        string subKey = args.Length >= 5 ? args[4] : @"SOFTWARE\Microsoft";
        string domain = args.Length >= 6 ? args[5] : string.Empty;
        int port = args.Length >= 7 ? int.Parse(args[6]) : 445;

        using var client = new Smb2Client();
        client.Connect(host, port);
        client.Negotiate();
        Smb2LoginResult login = client.Login(domain, user, password);
        if (!login.Authenticated)
        {
            Console.Error.WriteLine($"Login failed: {NtStatus.Describe(login.Round2Status)}");
            return 1;
        }

        Smb2TreeConnectResult ipc = client.TreeConnect($@"\\{host}\IPC$");
        DcerpcPipe pipe = DcerpcPipe.Open(client, ipc.TreeId, DcerpcInterface.Winreg.Pipe);
        pipe.Bind(DcerpcInterface.Winreg);

        ScHandleResult hklm = Winreg.OpenHklm(pipe);
        if (!hklm.Success)
        {
            Console.Error.WriteLine($"OpenHKLM failed: 0x{hklm.ReturnCode:X8}");
            return 1;
        }

        ScHandleResult key = Winreg.OpenKey(pipe, hklm.Handle, subKey);
        if (!key.Success)
        {
            Console.Error.WriteLine($"OpenKey {subKey} failed: 0x{key.ReturnCode:X8}");
            return 1;
        }

        IReadOnlyList<string> subkeys = Winreg.EnumerateKeys(pipe, key.Handle);
        Winreg.CloseKey(pipe, key.Handle);
        Winreg.CloseKey(pipe, hklm.Handle);
        pipe.Close();
        client.TreeDisconnect(ipc.TreeId);

        Console.WriteLine($"HKLM\\{subKey}  ({subkeys.Count} subkeys):");
        foreach (string k in subkeys)
        {
            Console.WriteLine($"  {k}");
        }

        return 0;
    }

    case "smb2-ls":
    {
        // Directory listing over SMB2: TREE_CONNECT + CREATE(dir) + QUERY_DIRECTORY + CLOSE.
        if (args.Length < 5)
        {
            Console.Error.WriteLine("usage: smb2-ls <host> <share> <user> <password> [path] [domain] [port]");
            return 2;
        }

        string host = args[1];
        string share = args[2];
        string user = args[3];
        string password = args[4];
        string path = args.Length >= 6 ? args[5] : string.Empty;
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

        IReadOnlyList<Smb2DirectoryEntry> entries = client.ListDirectory(tree.TreeId, path);
        client.TreeDisconnect(tree.TreeId);

        string display = string.IsNullOrEmpty(path) ? $@"\\{host}\{share}" : $@"\\{host}\{share}\{path}";
        Console.WriteLine($"Listing {display} ({entries.Count} entries):");
        foreach (Smb2DirectoryEntry e in entries)
        {
            Console.WriteLine($"  {(e.IsDirectory ? "<DIR>" : "     ")} {e.EndOfFile,12} {e.Name}");
        }

        return 0;
    }

    case "smb2-info":
    {
        // File-system info over SMB2: CREATE(root) + QUERY_INFO (volume + size).
        if (args.Length < 5)
        {
            Console.Error.WriteLine("usage: smb2-info <host> <share> <user> <password> [domain] [port]");
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
        client.Negotiate();
        Smb2LoginResult login = client.Login(domain, user, password);
        if (!login.Authenticated)
        {
            Console.Error.WriteLine($"Login failed: {NtStatus.Describe(login.Round2Status)}");
            return 1;
        }

        Smb2TreeConnectResult tree = client.TreeConnect($@"\\{host}\{share}");
        (Smb2VolumeInfo volume, Smb2FsSizeInfo size) = client.QueryFileSystemInfo(tree.TreeId);
        client.TreeDisconnect(tree.TreeId);

        Console.WriteLine($@"Filesystem info for \\{host}\{share}:");
        Console.WriteLine($"  Volume label:  {(string.IsNullOrEmpty(volume.Label) ? "(none)" : volume.Label)}");
        Console.WriteLine($"  Volume serial: 0x{volume.SerialNumber:x8}");
        Console.WriteLine($"  Total space:   {size.TotalBytes / (1024 * 1024)} MiB");
        Console.WriteLine($"  Free space:    {size.AvailableBytes / (1024 * 1024)} MiB");
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
    Console.WriteLine("DotNetPacket examples (SOC lab harness)");
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
    Console.WriteLine("  smb2-ls <host> <share> <user> <password> [path] [domain] [port]");
    Console.WriteLine("                   List a directory over SMB2: CREATE(dir) + QUERY_DIRECTORY.");
    Console.WriteLine("  smb2-info <host> <share> <user> <password> [domain] [port]");
    Console.WriteLine("                   Filesystem info over SMB2: QUERY_INFO (volume label/serial, size).");
    Console.WriteLine("  dcerpc-bind <host> <user> <password> [interface] [domain] [port]");
    Console.WriteLine("                   Open a named pipe on IPC$ and DCERPC BIND (srvsvc/wkssvc/lsarpc/samr/svcctl).");
    Console.WriteLine("  rpc-shares <host> <user> <password> [domain] [port]");
    Console.WriteLine("                   Enumerate shares via srvsvc NetrShareEnum (DCERPC REQUEST/RESPONSE + NDR).");
    Console.WriteLine("  rpc-shares-sealed <host> <user> <password> [seal|sign] [domain] [port]");
    Console.WriteLine("                   NetrShareEnum over an NTLMSSP-authenticated bind with packet privacy/integrity.");
    Console.WriteLine("  rpc-dump <host> <user> <password> [domain] [port]");
    Console.WriteLine("                   Enumerate registered RPC interfaces via mgmt inq_if_ids (rpcdump, over SMB).");
    Console.WriteLine("  rpc-dump-tcp <host> [port]");
    Console.WriteLine("                   Same, but DCERPC directly over TCP (ncacn_ip_tcp) to the endpoint mapper.");
    Console.WriteLine("  rpc-getarch <host> [port]");
    Console.WriteLine("                   Detect target architecture via an NDR+NDR64 two-context bind (getarch).");
    Console.WriteLine("  rpc-epm-map <host> [interface=samr] [port]");
    Console.WriteLine("                   Resolve an interface's dynamic TCP port via the endpoint mapper (ept_map).");
    Console.WriteLine("  rpc-samr-tcp <host> <user> <password> [domain] [epm-port]");
    Console.WriteLine("                   Full RPC-over-TCP flow: ept_map samr -> connect -> sealed bind -> enum (no SMB).");
    Console.WriteLine("  rpc-services <host> <user> <password> [domain] [port]");
    Console.WriteLine("                   List installed services via svcctl REnumServicesStatusW (services.py list).");
    Console.WriteLine("  rpc-svcconfig <host> <user> <password> <service> [domain] [port]");
    Console.WriteLine("                   Query one service's config (binary path, start type, account) via QueryServiceConfigW.");
    Console.WriteLine("  rpc-svcstatus <host> <user> <password> <service> [domain] [port]");
    Console.WriteLine("                   Query one service's live SERVICE_STATUS (run state, controls) via RQueryServiceStatus.");
    Console.WriteLine("  rpc-svcctl <host> <user> <password> [domain] [port]");
    Console.WriteLine("                   Lab demo of svcctl service creation (psexec wire signature; benign marker).");
    Console.WriteLine("  rpc-hostinfo <host> <user> <password> [domain] [port]");
    Console.WriteLine("                   Host/OS recon via wkssvc NetrWkstaGetInfo + srvsvc NetrServerGetInfo.");
    Console.WriteLine("  rpc-lsa <host> <user> <password> [domain] [port]");
    Console.WriteLine("                   Domain recon via lsarpc: account domain name + SID.");
    Console.WriteLine("  rpc-privs <host> <user> <password> [domain] [port]");
    Console.WriteLine("  rpc-accountrights <host> <user> <password> <sid> [domain] [port]");
    Console.WriteLine("                   Enumerate LSA privileges via lsarpc LsarEnumeratePrivileges.");
    Console.WriteLine("  rpc-lookupsid <host> <user> <password> [domain] [port]");
    Console.WriteLine("                   SID->name recon via lsat LsarLookupSids (well-known SIDs + domain RIDs).");
    Console.WriteLine("  rpc-lookupsid2 <host> <user> <password> [domain] [port]");
    Console.WriteLine("                   SID->name via lsat LsarLookupSids2 (opnum 57) — the modern-Windows variant.");
    Console.WriteLine("  rpc-enumusers <host> <user> <password> [domain] [port]");
    Console.WriteLine("  rpc-dispinfo <host> <user> <password> [domain] [port]");
    Console.WriteLine("                   Domain user enumeration via samr (samrdump / enumdomusers behavior).");
    Console.WriteLine("  rpc-userinfo <host> <user> <password> <target-user> [domain] [port]");
    Console.WriteLine("                   Per-user detail via samr QueryInformationUser2 level 21 (flags, timestamps).");
    Console.WriteLine("  rpc-lookuprid <host> <user> <password> <names-csv> [domain] [port]");
    Console.WriteLine("                   Name->RID resolution via samr SamrLookupNamesInDomain (opnum 17).");
    Console.WriteLine("  rpc-lookupid <host> <user> <password> <rids-csv> [domain] [port]");
    Console.WriteLine("                   RID->name resolution via samr SamrLookupIdsInDomain (opnum 18).");
    Console.WriteLine("  rpc-enumgroups <host> <user> <password> [domain] [port]");
    Console.WriteLine("                   Domain group + alias enumeration via samr (samrdump groups).");
    Console.WriteLine("  rpc-passpol <host> <user> <password> [domain] [port]");
    Console.WriteLine("                   Domain password + lockout policy via samr SamrQueryInformationDomain.");
    Console.WriteLine("  rpc-lookupnames <host> <user> <password> [names csv] [domain] [port]");
    Console.WriteLine("                   Name->SID recon via lsat LsarLookupNames (inverse of lookupsid).");
    Console.WriteLine("  rpc-lookupnames2 <host> <user> <password> [names csv] [domain] [port]");
    Console.WriteLine("                   Name->SID via lsat LsarLookupNames2 (opnum 58) — the modern-Windows variant.");
    Console.WriteLine("  rpc-reg <host> <user> <password> [subkey] [domain] [port]");
    Console.WriteLine("                   Remote-registry recon via winreg (MS-RRP): OpenHKLM + GetVersion + OpenKey.");
    Console.WriteLine("  rpc-regquery <host> <user> <password> <subkey> <value> [domain] [port]");
    Console.WriteLine("                   Read a registry value via winreg BaseRegQueryValue (reg query KEY -v VALUE).");
    Console.WriteLine("  rpc-regenum <host> <user> <password> [subkey] [domain] [port]");
    Console.WriteLine("                   Enumerate a key's values via winreg BaseRegEnumValue (reg query KEY).");
    Console.WriteLine("  rpc-regkeys <host> <user> <password> [subkey] [domain] [port]");
    Console.WriteLine("                   Enumerate a key's subkeys via winreg BaseRegEnumKey (reg query KEY).");
    Console.WriteLine("  help             Show this help.");
}
