using NetPacket.Core;
using NetPacket.Protocols.Dcerpc;
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
            const string serviceName = "NetPacketLab";
            const string binaryPath = @"%SystemRoot%\System32\cmd.exe /c echo netpacket-lab-marker";
            try
            {
                ScHandleResult created = Svcctl.CreateService(
                    pipe, scm.Handle, serviceName, "NetPacket Lab Marker", binaryPath);
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
            Lsarpc.Close(pipe, policy.Handle);
        }

        pipe.Close();
        client.TreeDisconnect(ipc.TreeId);
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
    Console.WriteLine("  smb2-ls <host> <share> <user> <password> [path] [domain] [port]");
    Console.WriteLine("                   List a directory over SMB2: CREATE(dir) + QUERY_DIRECTORY.");
    Console.WriteLine("  smb2-info <host> <share> <user> <password> [domain] [port]");
    Console.WriteLine("                   Filesystem info over SMB2: QUERY_INFO (volume label/serial, size).");
    Console.WriteLine("  dcerpc-bind <host> <user> <password> [interface] [domain] [port]");
    Console.WriteLine("                   Open a named pipe on IPC$ and DCERPC BIND (srvsvc/wkssvc/lsarpc/samr/svcctl).");
    Console.WriteLine("  rpc-shares <host> <user> <password> [domain] [port]");
    Console.WriteLine("                   Enumerate shares via srvsvc NetrShareEnum (DCERPC REQUEST/RESPONSE + NDR).");
    Console.WriteLine("  rpc-svcctl <host> <user> <password> [domain] [port]");
    Console.WriteLine("                   Lab demo of svcctl service creation (psexec wire signature; benign marker).");
    Console.WriteLine("  rpc-hostinfo <host> <user> <password> [domain] [port]");
    Console.WriteLine("                   Host/OS recon via wkssvc NetrWkstaGetInfo + srvsvc NetrServerGetInfo.");
    Console.WriteLine("  rpc-lsa <host> <user> <password> [domain] [port]");
    Console.WriteLine("                   Domain recon via lsarpc: account domain name + SID.");
    Console.WriteLine("  rpc-lookupsid <host> <user> <password> [domain] [port]");
    Console.WriteLine("                   SID->name recon via lsat LsarLookupSids (well-known SIDs + domain RIDs).");
    Console.WriteLine("  rpc-enumusers <host> <user> <password> [domain] [port]");
    Console.WriteLine("                   Domain user enumeration via samr (samrdump / enumdomusers behavior).");
    Console.WriteLine("  rpc-lookupnames <host> <user> <password> [names csv] [domain] [port]");
    Console.WriteLine("                   Name->SID recon via lsat LsarLookupNames (inverse of lookupsid).");
    Console.WriteLine("  rpc-reg <host> <user> <password> [subkey] [domain] [port]");
    Console.WriteLine("                   Remote-registry recon via winreg (MS-RRP): OpenHKLM + GetVersion + OpenKey.");
    Console.WriteLine("  help             Show this help.");
}
