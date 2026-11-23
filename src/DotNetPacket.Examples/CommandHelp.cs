namespace DotNetPacket.Examples;

/// <summary>
/// One command's help entry: the single source of truth for both the top-level listing
/// (<see cref="CommandHelp.PrintOverview"/>) and the per-command detail view
/// (<c>help &lt;command&gt;</c>, <see cref="CommandHelp.PrintCommand"/>). Keeping the two in one
/// place is deliberate — the old hand-maintained usage block drifted out of sync with the
/// actual argument parsing, which is exactly what this replaces.
/// </summary>
/// <param name="Name">The command token, e.g. <c>rpc-shares</c>.</param>
/// <param name="Category">Grouping header in the overview.</param>
/// <param name="Args">Argument synopsis shown after the command name (ground-truth form).</param>
/// <param name="Summary">One-line description.</param>
/// <param name="Notes">Per-parameter / behaviour notes for the detail view.</param>
/// <param name="Examples">Concrete invocations for the detail view.</param>
internal sealed record CommandDoc(
    string Name,
    string Category,
    string Args,
    string Summary,
    string[]? Notes = null,
    string[]? Examples = null);

internal static class CommandHelp
{
    // Documented throwaway lab values (see tools/lab-addc.sh) — safe to show in examples.
    private const string SmbTarget = "LAB/Administrator:'LabAdm1n!Pass'@127.0.0.1";
    private const string AdTarget = "lab.local/Administrator:'LabAdm1n!Pass'@127.0.0.1";

    private const string CatDemo = "Protocol structure demos (offline, no network)";
    private const string CatSmb = "SMB2 — session & files";
    private const string CatRpc = "DCERPC — bind & interface recon";
    private const string CatSamr = "SAMR — users, groups, domain policy";
    private const string CatLsa = "LSA / LSAT — SIDs, names, privileges";
    private const string CatReg = "WINREG — remote registry (MS-RRP)";
    private const string CatSvc = "SVCCTL / Task Scheduler — services & command exec";
    private const string CatTcp = "DCERPC over TCP — endpoint mapper (ncacn_ip_tcp)";
    private const string CatKrb = "Kerberos (MS-KILE)";
    private const string CatLdap = "LDAP / Active Directory";
    private const string CatSync = "DCSync — secretsdump (MS-DRSR replication)";
    private const string CatAcl = "AD object ACLs & delegation";
    private const string CatRelay = "NTLM relay (ntlmrelayx)";
    private const string CatSql = "MSSQL (MS-TDS)";

    // Category order for the overview.
    private static readonly string[] CategoryOrder =
    {
        CatDemo, CatSmb, CatRpc, CatSamr, CatLsa, CatReg, CatSvc, CatTcp,
        CatKrb, CatLdap, CatSync, CatAcl, CatRelay, CatSql,
    };

    internal static readonly CommandDoc[] All =
    {
        // ---- Protocol structure demos -------------------------------------------------
        new("smb-header", CatDemo, "",
            "Build a sample SMBv1 header (smb.SMB.SMBHeader) and hex-dump its 32 wire bytes.",
            Examples: new[] { "smb-header" }),
        new("ntlm-negotiate", CatDemo, "",
            "Build a sample NTLMSSP NEGOTIATE message (ntlm.NTLMAuthNegotiate) and hex-dump it.",
            Examples: new[] { "ntlm-negotiate" }),

        // ---- SMB2 --------------------------------------------------------------------
        new("smb2-negotiate", CatSmb, "<host> [port]",
            "Live SMB2 NEGOTIATE against a host; dump the request and response both ways.",
            Notes: new[] { "<host>  target host or IP (no credentials — NEGOTIATE is anonymous).",
                           "[port]  SMB port, default 445." },
            Examples: new[] { "smb2-negotiate 127.0.0.1" }),
        new("smb2-login", CatSmb, "<[domain/]user[:password]@host> [port]",
            "Live SMB2 NEGOTIATE + NTLMv2 SESSION_SETUP; dump both handshake rounds.",
            Examples: new[] { "smb2-login " + SmbTarget,
                              "smb2-login LAB/Administrator@127.0.0.1 -hashes :ac8d0d3c9858659864b8493a51050efd" }),
        new("smb2-connect", CatSmb, "<[domain/]user[:password]@host> <share> [port]",
            "Full session: NEGOTIATE + SESSION_SETUP + signed TREE_CONNECT to a share.",
            Notes: new[] { "<share>  share name, e.g. C$ or SYSVOL (no UNC backslashes)." },
            Examples: new[] { "smb2-connect " + SmbTarget + " C$" }),
        new("smb2-cat", CatSmb, "<[domain/]user[:password]@host> <share> <path> [port]",
            "Read a file over SMB2: TREE_CONNECT + CREATE + READ + CLOSE.",
            Notes: new[] { "<path>  path within the share, backslash-separated, e.g. Windows\\win.ini." },
            Examples: new[] { "smb2-cat " + SmbTarget + " C$ Windows\\\\win.ini" }),
        new("smb2-ls", CatSmb, "<[domain/]user[:password]@host> <share> [path] [port]",
            "List a directory over SMB2: CREATE(dir) + QUERY_DIRECTORY.",
            Notes: new[] { "[path]  sub-directory to list; default is the share root." },
            Examples: new[] { "smb2-ls " + SmbTarget + " C$",
                              "smb2-ls " + SmbTarget + " C$ Windows" }),
        new("smb2-info", CatSmb, "<[domain/]user[:password]@host> <share> [port]",
            "Filesystem info over SMB2: QUERY_INFO (volume label/serial, size).",
            Examples: new[] { "smb2-info " + SmbTarget + " C$" }),
        new("smb-attrib", CatSmb, "<[domain/]user[:password]@host> <share> <path> [port]",
            "Query a file's DOS attributes (attrib) via SMB2 QUERY_INFO.",
            Examples: new[] { "smb-attrib " + SmbTarget + " C$ Windows\\\\win.ini" }),
        new("smb-attrib-set", CatSmb, "<[domain/]user[:password]@host> <share> <path> <attrs> [port]",
            "Set a file's DOS attributes via SMB2 SET_INFO.",
            Notes: new[] { "<attrs>  letters from R H S A N T (readonly/hidden/system/archive/normal/temporary); 'N' clears all." },
            Examples: new[] { "smb-attrib-set " + SmbTarget + " C$ secret.txt RH" }),
        new("smb-ntlminfo", CatSmb, "<host> [port]",
            "DumpNTLMInfo: host / OS / DNS names from the NTLM CHALLENGE (no credentials).",
            Examples: new[] { "smb-ntlminfo 127.0.0.1" }),
        new("gpp-passwords", CatSmb, "<[domain/]user[:password]@host> [share=SYSVOL] [port]",
            "Get-GPPPassword: crawl a share for GPP XML, carve cpasswords, decrypt them (MS14-025).",
            Notes: new[] { "[share]  share to crawl, default SYSVOL." },
            Examples: new[] { "gpp-passwords " + SmbTarget }),

        // ---- DCERPC bind / recon ------------------------------------------------------
        new("dcerpc-bind", CatRpc, "<[domain/]user[:password]@host> [interface] [port]",
            "Open a named pipe on IPC$ and DCERPC BIND to an interface.",
            Notes: new[] { "[interface]  srvsvc (default) | wkssvc | lsarpc | samr | svcctl." },
            Examples: new[] { "dcerpc-bind " + SmbTarget + " samr" }),
        new("rpc-shares", CatRpc, "<[domain/]user[:password]@host> [port]",
            "Enumerate shares via srvsvc NetrShareEnum (DCERPC REQUEST/RESPONSE + NDR).",
            Examples: new[] { "rpc-shares " + SmbTarget }),
        new("rpc-shares-sealed", CatRpc, "<[domain/]user[:password]@host> [seal|sign] [port]",
            "NetrShareEnum over an NTLMSSP-authenticated bind with packet privacy or integrity.",
            Notes: new[] { "[seal|sign]  seal = packet privacy (encrypt, default); sign = integrity only." },
            Examples: new[] { "rpc-shares-sealed " + SmbTarget + " seal" }),
        new("rpc-dump", CatRpc, "<[domain/]user[:password]@host> [port]",
            "Enumerate registered RPC interfaces via mgmt inq_if_ids (rpcdump, over SMB).",
            Examples: new[] { "rpc-dump " + SmbTarget }),
        new("rpc-hostinfo", CatRpc, "<[domain/]user[:password]@host> [port]",
            "Host / OS recon via wkssvc NetrWkstaGetInfo.",
            Examples: new[] { "rpc-hostinfo " + SmbTarget }),
        new("rpc-srvinfo", CatRpc, "<[domain/]user[:password]@host> [port]",
            "Server tunables via srvsvc NetrServerGetInfo level 102.",
            Examples: new[] { "rpc-srvinfo " + SmbTarget }),

        // ---- SAMR --------------------------------------------------------------------
        new("rpc-enumusers", CatSamr, "<[domain/]user[:password]@host> [port]",
            "Enumerate domain users via samr SamrEnumerateUsersInDomain.",
            Examples: new[] { "rpc-enumusers " + SmbTarget }),
        new("rpc-enumgroups", CatSamr, "<[domain/]user[:password]@host> [port]",
            "Enumerate domain groups + aliases via samr (samrdump groups).",
            Examples: new[] { "rpc-enumgroups " + SmbTarget }),
        new("rpc-dispinfo", CatSamr, "<[domain/]user[:password]@host> [port]",
            "SamrQueryDisplayInformation user display path (samrdump).",
            Examples: new[] { "rpc-dispinfo " + SmbTarget }),
        new("rpc-dispgroups", CatSamr, "<[domain/]user[:password]@host> [port]",
            "SamrQueryDisplayInformation level 3 (group display).",
            Examples: new[] { "rpc-dispgroups " + SmbTarget }),
        new("rpc-domaininfo", CatSamr, "<[domain/]user[:password]@host> [port]",
            "SamrQueryInformationDomain level 2: role + user/group/alias counts.",
            Examples: new[] { "rpc-domaininfo " + SmbTarget }),
        new("rpc-passpol", CatSamr, "<[domain/]user[:password]@host> [port]",
            "Domain password + lockout policy via samr SamrQueryInformationDomain.",
            Examples: new[] { "rpc-passpol " + SmbTarget }),
        new("rpc-samrdump", CatSamr, "<[domain/]user[:password]@host> [port]",
            "Full samrdump.py-style dump: domain info + policy + users + groups.",
            Examples: new[] { "rpc-samrdump " + SmbTarget }),
        new("rpc-aliasmem", CatSamr, "<[domain/]user[:password]@host> [alias-name|rid] [port]",
            "SamrOpenAlias + SamrGetMembersInAlias: list an alias's member SIDs.",
            Notes: new[] { "[alias-name|rid]  alias to open, by name or RID; default enumerates built-in aliases." },
            Examples: new[] { "rpc-aliasmem " + SmbTarget + " Administrators" }),
        new("rpc-userinfo", CatSamr, "<[domain/]user[:password]@host> <target-user> [port]",
            "Per-user detail via samr QueryInformationUser2 level 21 (flags, timestamps).",
            Notes: new[] { "<target-user>  the account to inspect (sAMAccountName)." },
            Examples: new[] { "rpc-userinfo " + SmbTarget + " Administrator" }),
        new("rpc-lookuprid", CatSamr, "<[domain/]user[:password]@host> <names-csv> [port]",
            "Name->RID resolution via samr SamrLookupNamesInDomain (opnum 17).",
            Notes: new[] { "<names-csv>  comma-separated sAMAccountNames, e.g. Administrator,Guest,krbtgt." },
            Examples: new[] { "rpc-lookuprid " + SmbTarget + " Administrator,Guest" }),
        new("rpc-lookupid", CatSamr, "<[domain/]user[:password]@host> <rids-csv> [port]",
            "RID->name resolution via samr SamrLookupIdsInDomain (opnum 18).",
            Notes: new[] { "<rids-csv>  comma-separated RIDs, e.g. 500,501,502." },
            Examples: new[] { "rpc-lookupid " + SmbTarget + " 500,501,512" }),
        new("rpc-addcomputer", CatSamr, "<[domain/]user[:password]@host> <computer-name> [port]",
            "addcomputer (SAMR): create then delete a machine account (lab round-trip).",
            Notes: new[] { "<computer-name>  new machine account name; a trailing $ is added if omitted." },
            Examples: new[] { "rpc-addcomputer " + SmbTarget + " LABPC01" }),
        new("rpc-changepw", CatSamr, "<[domain/]user[:oldpassword]@host> <newpassword> [port]",
            "changepasswd (SAMR): change your own password via SamrUnicodeChangePasswordUser2.",
            Notes: new[] { "The target's password field is the CURRENT password; <newpassword> is the new one." },
            Examples: new[] { "rpc-changepw LAB/alice:'OldP@ss1'@127.0.0.1 'NewP@ss2!'" }),
        new("lookupsid", CatSamr, "<[domain/]user[:password]@host> [maxRid=1100] [port]",
            "lookupsid: RID cycling via LsarLookupSids (account enumeration from the domain SID).",
            Notes: new[] { "[maxRid]  highest RID to probe, default 1100." },
            Examples: new[] { "lookupsid " + SmbTarget + " 1200" }),

        // ---- LSA / LSAT --------------------------------------------------------------
        new("rpc-lsa", CatLsa, "<[domain/]user[:password]@host> [port]",
            "Domain recon via lsarpc: account domain name + SID + DNS/forest info.",
            Examples: new[] { "rpc-lsa " + SmbTarget }),
        new("rpc-privs", CatLsa, "<[domain/]user[:password]@host> [port]",
            "Enumerate LSA privileges via lsarpc LsarEnumeratePrivileges.",
            Examples: new[] { "rpc-privs " + SmbTarget }),
        new("rpc-accountrights", CatLsa, "<[domain/]user[:password]@host> <sid> [port]",
            "LsarEnumerateAccountRights: rights granted to a SID.",
            Notes: new[] { "<sid>  the account SID, e.g. S-1-5-32-550." },
            Examples: new[] { "rpc-accountrights " + SmbTarget + " S-1-5-32-544" }),
        new("rpc-privlookup", CatLsa, "<[domain/]user[:password]@host> <privilege-name|luid> [port]",
            "LsarLookupPrivilegeValue/Name: resolve a privilege name <-> LUID.",
            Notes: new[] { "<privilege-name|luid>  e.g. SeDebugPrivilege, or a numeric LUID." },
            Examples: new[] { "rpc-privlookup " + SmbTarget + " SeDebugPrivilege" }),
        new("rpc-lookupsid", CatLsa, "<[domain/]user[:password]@host> [port]",
            "SID->name recon via lsat LsarLookupSids (well-known SIDs + domain RIDs).",
            Examples: new[] { "rpc-lookupsid " + SmbTarget }),
        new("rpc-lookupsid2", CatLsa, "<[domain/]user[:password]@host> [port]",
            "SID->name via lsat LsarLookupSids2 (opnum 57) — the modern-Windows variant.",
            Examples: new[] { "rpc-lookupsid2 " + SmbTarget }),
        new("rpc-lookupnames", CatLsa, "<[domain/]user[:password]@host> [names-csv] [port]",
            "Name->SID recon via lsat LsarLookupNames (inverse of lookupsid).",
            Notes: new[] { "[names-csv]  comma-separated names; default probes a well-known set." },
            Examples: new[] { "rpc-lookupnames " + SmbTarget + " Administrator,Domain Admins" }),
        new("rpc-lookupnames2", CatLsa, "<[domain/]user[:password]@host> [names-csv] [port]",
            "Name->SID via lsat LsarLookupNames2 (opnum 58) — the modern-Windows variant.",
            Examples: new[] { "rpc-lookupnames2 " + SmbTarget + " Administrator" }),

        // ---- WINREG ------------------------------------------------------------------
        new("rpc-reg", CatReg, "<[domain/]user[:password]@host> [subkey] [port]",
            "Remote-registry recon via winreg (MS-RRP): OpenHKLM + GetVersion + OpenKey.",
            Notes: new[] { "[subkey]  HKLM subkey path, e.g. SYSTEM\\\\CurrentControlSet\\\\Control." },
            Examples: new[] { "rpc-reg " + SmbTarget + " SYSTEM\\\\CurrentControlSet\\\\Control\\\\Lsa" }),
        new("rpc-regquery", CatReg, "<[domain/]user[:password]@host> <subkey> <value> [port]",
            "Read one registry value via winreg BaseRegQueryValue (reg query KEY -v VALUE).",
            Notes: new[] { "<subkey>  HKLM subkey path.", "<value>  value name within the key." },
            Examples: new[] { "rpc-regquery " + SmbTarget + " SYSTEM\\\\CurrentControlSet\\\\Control\\\\Lsa LmCompatibilityLevel" }),
        new("rpc-regenum", CatReg, "<[domain/]user[:password]@host> [subkey] [port]",
            "Enumerate a key's values via winreg BaseRegEnumValue (reg query KEY).",
            Examples: new[] { "rpc-regenum " + SmbTarget + " SYSTEM\\\\CurrentControlSet\\\\Control\\\\Lsa" }),
        new("rpc-regkeys", CatReg, "<[domain/]user[:password]@host> [subkey] [port]",
            "Enumerate a key's subkeys via winreg BaseRegEnumKey (reg query KEY).",
            Examples: new[] { "rpc-regkeys " + SmbTarget + " SOFTWARE\\\\Microsoft" }),

        // ---- SVCCTL / exec -----------------------------------------------------------
        new("rpc-services", CatSvc, "<[domain/]user[:password]@host> [port]",
            "List installed services via svcctl REnumServicesStatusW (services.py list).",
            Examples: new[] { "rpc-services " + SmbTarget }),
        new("rpc-svcconfig", CatSvc, "<[domain/]user[:password]@host> <service> [port]",
            "Query one service's config (binary path, start type, account) via QueryServiceConfigW.",
            Notes: new[] { "<service>  the service short name, e.g. Spooler." },
            Examples: new[] { "rpc-svcconfig " + SmbTarget + " Spooler" }),
        new("rpc-svcstatus", CatSvc, "<[domain/]user[:password]@host> <service> [port]",
            "Query one service's live SERVICE_STATUS via RQueryServiceStatus.",
            Examples: new[] { "rpc-svcstatus " + SmbTarget + " Spooler" }),
        new("rpc-svcctl", CatSvc, "<[domain/]user[:password]@host> [port]",
            "Lab demo of svcctl service creation (psexec wire signature; benign marker).",
            Examples: new[] { "rpc-svcctl " + SmbTarget }),
        new("smbexec", CatSvc, "<[domain/]user[:password]@host> <command> [share=C$] [port]",
            "smbexec: run a command via a one-shot svcctl service (lab-only exec).",
            Notes: new[] { "<command>  the command line to run as the service.",
                           "[share]  share for the output capture file, default C$." },
            Examples: new[] { "smbexec " + SmbTarget + " 'whoami'" }),
        new("atexec", CatSvc, "<[domain/]user[:password]@host> <command> [port]",
            "atexec: run a command via the Task Scheduler (MS-TSCH; Windows target).",
            Examples: new[] { "atexec " + SmbTarget + " 'whoami'" }),

        // ---- DCERPC over TCP ---------------------------------------------------------
        new("rpc-dump-tcp", CatTcp, "<host> [port]",
            "rpcdump directly over TCP (ncacn_ip_tcp) against the endpoint mapper.",
            Notes: new[] { "[port]  endpoint-mapper port, default 135." },
            Examples: new[] { "rpc-dump-tcp 127.0.0.1" }),
        new("rpc-getarch", CatTcp, "<host> [port]",
            "Detect target architecture via an NDR + NDR64 two-context bind (getarch).",
            Examples: new[] { "rpc-getarch 127.0.0.1" }),
        new("rpc-epm-map", CatTcp, "<host> [interface=samr] [port=135]",
            "Resolve an interface's dynamic TCP port via the endpoint mapper (ept_map).",
            Notes: new[] { "[interface]  samr (default) | lsarpc | drsuapi | ... | a UUID." },
            Examples: new[] { "rpc-epm-map 127.0.0.1 drsuapi" }),
        new("rpc-samr-tcp", CatTcp, "<[domain/]user[:password]@host> [epm-port=135]",
            "Full RPC-over-TCP flow: ept_map samr -> connect -> sealed bind -> enum (no SMB).",
            Examples: new[] { "rpc-samr-tcp " + SmbTarget }),

        // ---- Kerberos ----------------------------------------------------------------
        new("kerb-tgt", CatKrb, "<domain-fqdn/user[:password]@host> [port]",
            "getTGT: request a Kerberos TGT (RC4 PA-ENC-TIMESTAMP pre-auth). -save-ccache stores it.",
            Notes: new[] { "domain  must be the DNS realm (lab.local), not the NetBIOS name." },
            Examples: new[] { "kerb-tgt " + AdTarget + " -save-ccache admin.ccache" }),
        new("get-npusers", CatKrb, "<domain-fqdn/[user[:password]]@host> [target-user] [port]",
            "GetNPUsers: AS-REP roast accounts that do not require Kerberos pre-auth.",
            Notes: new[] { "[target-user]  roast a single named user without binding (use lab.local/@host).",
                           "Omit the user entirely (lab.local/@host) for the no-bind single-user path." },
            Examples: new[] { "get-npusers " + AdTarget,
                              "get-npusers lab.local/@127.0.0.1 roastme" }),
        new("get-userspns", CatKrb, "<domain-fqdn/user[:password]@host> [target-user] [port]",
            "GetUserSPNs: Kerberoast — request service tickets for SPN accounts and format the hashes.",
            Notes: new[] { "[target-user]  roast one named SPN account instead of all." },
            Examples: new[] { "get-userspns " + AdTarget }),
        new("get-st", CatKrb, "<domain-fqdn/service-user[:password]@dc-host> <impersonate> <target-spn> [port]",
            "getST (S4U): S4U2self + S4U2proxy to mint a constrained-delegation ticket (lab).",
            Notes: new[] { "<impersonate>  the user to impersonate, e.g. Administrator.",
                           "<target-spn>  the service to get a ticket for, e.g. cifs/target.lab.local." },
            Examples: new[] { "get-st lab.local/websvc:'Pass123!'@vm.lab.local Administrator cifs/target.lab.local" }),
        new("getpac", CatKrb, "<dc-host> <service-user> <domain-fqdn> <impersonate-user> <service-key-hex> [krbtgt-key-hex] [port]",
            "getPac: S4U2self + decrypt the ticket + parse its PAC (MS-PAC) and verify both signatures.",
            Notes: new[] { "This command takes positional args (not a target string).",
                           "<service-user>  account whose key decrypts the service ticket.",
                           "<service-key-hex>  that account's key (RC4 NT hash or AES key) as hex.",
                           "[krbtgt-key-hex]  krbtgt key to also verify the KDC signature (forged-PAC check)." },
            Examples: new[] { "getpac vm.lab.local svcroast lab.local Administrator 7cd13d90d3cb835ab9c08ac18edeea2b" }),
        new("ldap-signing", CatKrb, "<host> <domain> [port]",
            "CheckLDAPStatus: does the DC require LDAP signing, plus the LDAPS/TLS (636) posture — no credentials.",
            Notes: new[] { "Reports whether an unsigned bind is refused on 389, and whether LDAPS is reachable",
                           "(negotiated TLS version/cipher + the server certificate). Use -ldaps on the other",
                           "LDAP tools to bind over that TLS channel." },
            Examples: new[] { "ldap-signing 127.0.0.1 lab.local" }),

        // ---- LDAP / AD ---------------------------------------------------------------
        new("get-adcomputers", CatLdap, "<domain-fqdn/user[:password]@host> [port]",
            "GetADComputers: LDAP search for computer objects (name, DNS, OS).",
            Examples: new[] { "get-adcomputers " + AdTarget }),
        new("get-adusers", CatLdap, "<domain-fqdn/user[:password]@host> [all] [port]",
            "GetADUsers: LDAP search for user accounts (lastLogon, pwdLastSet).",
            Notes: new[] { "[all]  pass the literal 'all' to include accounts without a lastLogon." },
            Examples: new[] { "get-adusers " + AdTarget + " all" }),
        new("get-laps", CatLdap, "<domain-fqdn/user[:password]@host> [computer] [port]",
            "GetLAPSPassword: LDAP search for LAPS managed-password attributes.",
            Notes: new[] { "[computer]  limit to one computer; default reads all readable entries." },
            Examples: new[] { "get-laps " + AdTarget }),
        new("find-delegation", CatLdap, "<domain-fqdn/user[:password]@host> [target-user] [port]",
            "findDelegation: unconstrained / constrained / protocol-transition / RBCD accounts.",
            Examples: new[] { "find-delegation " + AdTarget }),

        // ---- DCSync ------------------------------------------------------------------
        new("dcsync", CatSync, "<domain-fqdn/user[:password]@dc-host> <target-user> [netbios-domain] [epm-port]",
            "secretsdump (DCSync): replicate one account's secrets via DRSUAPI (lab).",
            Notes: new[] { "<target-user>  the account whose secrets to replicate, e.g. Administrator or krbtgt.",
                           "[netbios-domain]  NetBIOS domain if it differs from the FQDN's first label.",
                           "[epm-port]  endpoint-mapper port, default 135." },
            Examples: new[] { "dcsync " + AdTarget + " krbtgt" }),
        new("dcsync-all", CatSync, "<domain-fqdn/user[:password]@dc-host> [netbios-domain] [epm-port]",
            "secretsdump (DCSync): enumerate every account by SID and replicate all secrets (lab).",
            Examples: new[] { "dcsync-all " + AdTarget }),
        new("dcsync-k", CatSync, "<domain-fqdn/user[:password]@dc-host> <target-user> <dc-fqdn> [netbios-domain] [epm-port]",
            "DCSync with Kerberos (-k): DCE-style GSS-authenticated sealed DRSUAPI (lab).",
            Notes: new[] { "<dc-fqdn>  the DC's full DNS name (the Kerberos SPN host).",
                           "Pass -k (and optionally -aesKey / -ccache) as a global option." },
            Examples: new[] { "dcsync-k " + AdTarget + " krbtgt vm.lab.local -k" }),
        new("dcsync-all-k", CatSync, "<domain-fqdn/user[:password]@dc-host> <dc-fqdn> [netbios-domain] [epm-port]",
            "Whole-domain DCSync with Kerberos (-k): sealed SAMR enum + DRSUAPI replication (lab).",
            Examples: new[] { "dcsync-all-k " + AdTarget + " vm.lab.local -k" }),

        // ---- ACLs & delegation -------------------------------------------------------
        new("dacledit", CatAcl, "<read|write|remove|backup|restore> <domain-fqdn/user[:password]@host> <target> [principal] [rights] [ace-type] [file]",
            "dacledit: read or edit an object's DACL (lab).",
            Notes: new[] { "action    read | write | remove | backup | restore.",
                           "<target>  the object whose DACL is edited (sAMAccountName).",
                           "[principal]  the trustee to grant/remove (for write/remove).",
                           "[rights]   FullControl (default) | ResetPassword | WriteMembers | DCSync | 0x<mask>.",
                           "[ace-type] allowed (default) | denied.",
                           "[file]     backup/restore DACL file." },
            Examples: new[] { "dacledit read " + AdTarget + " target1",
                              "dacledit write " + AdTarget + " target1 attacker DCSync" }),
        new("owneredit", CatAcl, "<read|write> <domain-fqdn/user[:password]@host> <target> [new-owner]",
            "owneredit: read or set an object's owner (lab).",
            Notes: new[] { "[new-owner]  the principal to set as owner (for write)." },
            Examples: new[] { "owneredit write " + AdTarget + " target1 attacker" }),
        new("rbcd", CatAcl, "<read|write|remove|flush> <domain-fqdn/user[:password]@host> <delegate-to> [delegate-from]",
            "rbcd: edit msDS-AllowedToActOnBehalfOfOtherIdentity (resource-based constrained delegation, lab).",
            Notes: new[] { "<delegate-to>    the account whose rbcd property is read/edited (a computer ends in $).",
                           "[delegate-from]  the attacker-controlled account to grant (write/remove)." },
            Examples: new[] { "rbcd write " + AdTarget + " 'VICTIM$' 'ATTACKER$'" }),
        new("badsuccessor", CatAcl, "<search|add|delete|modify> <domain-fqdn/user[:password]@host> [dmsa] [target-ou] [target]",
            "BadSuccessor: enumerate/abuse delegated managed service accounts (dMSA) (lab).",
            Notes: new[] { "action     search | add | delete | modify.",
                           "[dmsa]     the dMSA account name (add/delete/modify).",
                           "[target-ou] OU to create the dMSA in (add).",
                           "[target]   the account to succeed (modify)." },
            Examples: new[] { "badsuccessor search " + AdTarget }),

        // ---- NTLM relay --------------------------------------------------------------
        new("ntlmrelayx", CatRelay, "<target-host> [listen-port=4455] [victim-user victim-pass [domain]]",
            "ntlmrelayx: SMB->SMB NTLM relay core (lab, owner-authorised).",
            Notes: new[] { "<target-host>  where captured auth is relayed to.",
                           "[victim-*]  optional built-in lab victim that authenticates to the listener." },
            Examples: new[] { "ntlmrelayx 127.0.0.1 4455 Administrator 'LabAdm1n!Pass' LAB" }),
        new("ntlmrelayx-http", CatRelay, "<target-host> [listen-port=8080] [victim-user victim-pass [domain]]",
            "ntlmrelayx: HTTP->SMB NTLM relay (lab, owner-authorised).",
            Examples: new[] { "ntlmrelayx-http 127.0.0.1 8080 Administrator 'LabAdm1n!Pass' LAB" }),
        new("ntlmrelayx-ldap", CatRelay, "<dc-host> <listen-port> <victim-user> <victim-pass> <domain-fqdn>",
            "ntlmrelayx: SMB->LDAP relay / ldapattack (lab, owner-authorised).",
            Examples: new[] { "ntlmrelayx-ldap 127.0.0.1 4455 Administrator 'LabAdm1n!Pass' lab.local" }),

        // ---- MSSQL -------------------------------------------------------------------
        new("mssql-cbt", CatSql, "<host> [port]",
            "checkMSSQLStatus: TDS PRELOGIN encryption posture (channel-binding precondition).",
            Notes: new[] { "[port]  SQL Server port, default 1433." },
            Examples: new[] { "mssql-cbt 127.0.0.1" }),
    };

    private const string CredTargetBlock =
        "CREDENTIAL TARGET   <[domain/]username[:password]@host>   (impacket-style)\n" +
        "  domain     optional. NetBIOS name (LAB) for SMB/RPC; DNS FQDN (lab.local) for LDAP/Kerberos.\n" +
        "  username   the account to authenticate as. Omit it (domain/@host) only where a command allows anonymous.\n" +
        "  password   optional. Omit ':password' and supply -hashes / -aesKey / -k / -no-pass instead.\n" +
        "  host       target host or IP — everything after the LAST '@', so '@' is legal in a password.\n" +
        "  Quoting:   single-quote the whole target in your shell so / : @ ! $ in a password reach the parser:\n" +
        "               'LAB/alice:P@ss:w/rd!@127.0.0.1'   (/, :, @ inside the password are fine)\n" +
        "             'user@host' with no ':' and no credential flag is refused (this CLI never prompts);\n" +
        "             'user:@host' means an explicit empty password.";

    private const string GlobalOptionsBlock =
        "GLOBAL OPTIONS   (any command, anywhere on the line)\n" +
        "  -hashes [LM:]NT   pass-the-hash; NTLMv2 uses the NT hash and the password becomes optional.\n" +
        "  -aesKey HEX       Kerberos AES key (32 or 64 hex), overpass-the-hash; implies -k.\n" +
        "  -k                use Kerberos (AP-REQ). With a password the KDC's etypes are probed (prefers AES-256).\n" +
        "  -no-pass          do not require a password (use with -hashes / -k / a ccache).\n" +
        "  -ldaps            connect the LDAP tools over TLS (port 636); a simple bind then works on a\n" +
        "                    DC that refuses plaintext binds (LDAP signing / channel binding enforced).\n" +
        "  -ccache FILE      use a saved TGT (also honours $KRB5CCNAME).  -save-ccache FILE writes one.\n" +
        "  -dc-ip IP         KDC / DC address for Kerberos when it differs from the target host.\n" +
        "  -target-ip IP     connect here instead of resolving the target host name.\n" +
        "  -proxy URL        tunnel all TCP via socks5:// | socks4a:// | http:// [user:pass@]host:port.";

    /// <summary>Top-level listing: every command grouped by category, plus the shared blocks.</summary>
    public static void PrintOverview()
    {
        Console.WriteLine("DotNetPacket examples — a .NET 8 port of impacket's examples/ (SOC lab harness)");
        Console.WriteLine();
        Console.WriteLine("Usage: netpacket-examples <command> [arguments] [global-options]");
        Console.WriteLine("       netpacket-examples help <command>     # parameters + examples for one command");
        Console.WriteLine();

        foreach (string category in CategoryOrder)
        {
            Console.WriteLine(category);
            foreach (CommandDoc d in All)
            {
                if (d.Category != category)
                {
                    continue;
                }

                string head = d.Args.Length == 0 ? d.Name : d.Name + " " + d.Args;
                Console.WriteLine("  " + head);
                Console.WriteLine("      " + d.Summary);
            }

            Console.WriteLine();
        }

        Console.WriteLine(CredTargetBlock);
        Console.WriteLine();
        Console.WriteLine(GlobalOptionsBlock);
        Console.WriteLine();
        Console.WriteLine("Run 'netpacket-examples help <command>' for that command's parameters and examples.");
        Console.WriteLine("Lab use only — see CLAUDE.md, \"Scope and intended use\".");
    }

    /// <summary>Detail view for one command: synopsis, per-parameter notes, examples, shared blocks.</summary>
    /// <returns>Process exit code (0 if the command was found, 1 otherwise).</returns>
    public static int PrintCommand(string name)
    {
        CommandDoc? doc = Array.Find(All, d => d.Name == name);
        if (doc is null)
        {
            Console.Error.WriteLine($"Unknown command '{name}'. Run 'netpacket-examples help' for the full list.");
            return 1;
        }

        string head = doc.Args.Length == 0 ? doc.Name : doc.Name + " " + doc.Args;
        Console.WriteLine(doc.Name + " — " + doc.Summary);
        Console.WriteLine();
        Console.WriteLine("SYNOPSIS");
        Console.WriteLine("  netpacket-examples " + head);

        if (doc.Notes is { Length: > 0 })
        {
            Console.WriteLine();
            Console.WriteLine("PARAMETERS");
            foreach (string note in doc.Notes)
            {
                Console.WriteLine("  " + note);
            }
        }

        if (doc.Examples is { Length: > 0 })
        {
            Console.WriteLine();
            Console.WriteLine("EXAMPLES");
            foreach (string ex in doc.Examples)
            {
                Console.WriteLine("  netpacket-examples " + ex);
            }
        }

        // Only commands that actually take a credential target need the target/options primer.
        if (doc.Args.Contains("[:password]"))
        {
            Console.WriteLine();
            Console.WriteLine(CredTargetBlock);
        }

        if (doc.Category != CatDemo)
        {
            Console.WriteLine();
            Console.WriteLine(GlobalOptionsBlock);
        }

        return 0;
    }
}
