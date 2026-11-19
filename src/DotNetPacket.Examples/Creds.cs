namespace DotNetPacket.Examples;

/// <summary>
/// Resolves target + credentials from a command's positionals the impacket way, so a password is not
/// required when a ticket or hash is supplied. Two accepted forms, chosen by the host token:
/// <list type="bullet">
///   <item><description><b>impacket target</b> — <c>[[domain/]username[:password]@]host</c> in the host
///   slot. The separate <c>user</c>/<c>password</c> positionals are then dropped, and the password is
///   optional (omit it entirely when using <c>-hashes</c> / <c>-k</c> / <c>-aesKey</c> / a ccache).</description></item>
///   <item><description><b>legacy positionals</b> — <c>&lt;host&gt; &lt;user&gt; &lt;password&gt;</c>, exactly as
///   before. This path is byte-for-byte unchanged (same indices, password still positional), so existing
///   invocations keep working.</description></item>
/// </list>
/// <see cref="NextIndex"/> is where the command's remaining positionals start (host+1 for the target
/// form, host+3 for the legacy form), so trailing args rebase on it cleanly. <see cref="Password"/> is
/// null when authentication will use an override (hash/ticket) instead of a password.
/// </summary>
internal sealed record Creds(string Host, string User, string? Password, string? Domain, int NextIndex, bool IsTarget)
{
    /// <summary>The password to hand a login/bind call (empty when an override supplies the secret).</summary>
    public string PasswordOrEmpty => Password ?? string.Empty;

    /// <summary>
    /// Resolves the optional <c>[domain]</c> that follows the credentials. In the impacket target form the
    /// domain comes from the target (so it is not read positionally); in the legacy form it is the next
    /// positional. Advances <paramref name="index"/> past a consumed legacy domain slot.
    /// </summary>
    public string ResolveDomain(string[] args, ref int index)
    {
        if (IsTarget)
        {
            return Domain ?? string.Empty;
        }

        string domain = args.Length > index ? args[index] : string.Empty;
        index++;
        return domain;
    }

    /// <summary>
    /// Resolves credentials starting at <paramref name="hostIndex"/> (the host/target token). On the
    /// legacy path, user is at hostIndex+1 and password at hostIndex+2 — unless the password is optional
    /// (a hash/ticket override is active), in which case a missing password slot is allowed and the
    /// command's own trailing args are read from hostIndex+2. <paramref name="usage"/> is shown on error.
    /// </summary>
    /// <summary><see cref="Resolve"/>, but prints the usage and exits(2) instead of throwing.</summary>
    public static Creds ResolveOrExit(string[] args, int hostIndex, string usage)
    {
        try
        {
            return Resolve(args, hostIndex, usage);
        }
        catch (CredsUsageException ex)
        {
            Console.Error.WriteLine(ex.Message);
            Environment.Exit(2);
            throw; // unreachable
        }
    }

    public static Creds Resolve(string[] args, int hostIndex, string usage)
    {
        if (hostIndex >= args.Length)
        {
            throw new CredsUsageException(usage);
        }

        string token = args[hostIndex];
        int at = token.IndexOf('@');
        if (at >= 0)
        {
            // impacket target: [[domain/]username[:password]@]host
            string credPart = token[..at];
            string host = token[(at + 1)..];
            if (host.Length == 0)
            {
                throw new CredsUsageException(usage);
            }

            string? domain = null;
            int slash = credPart.IndexOf('/');
            if (slash >= 0)
            {
                domain = credPart[..slash];
                credPart = credPart[(slash + 1)..];
            }

            string user;
            string? password = null;
            int colon = credPart.IndexOf(':');
            if (colon >= 0)
            {
                user = credPart[..colon];
                password = credPart[(colon + 1)..];
            }
            else
            {
                user = credPart;
            }

            if (password is null && !GlobalOptions.PasswordOptional)
            {
                throw new CredsUsageException(
                    "No password in the target and no -hashes/-aesKey/-k/-ccache/-no-pass supplied.\n" + usage);
            }

            return new Creds(host, user, password,
                string.IsNullOrEmpty(domain) ? null : domain, hostIndex + 1, IsTarget: true);
        }

        // Legacy positionals: <host> <user> <password> — unchanged behaviour.
        if (hostIndex + 1 >= args.Length)
        {
            throw new CredsUsageException(usage);
        }

        string legacyHost = token;
        string legacyUser = args[hostIndex + 1];

        // Password present in its slot → legacy behaviour, byte-for-byte unchanged (it may be a
        // placeholder that an override ignores). Only when the slot is genuinely absent do we allow
        // omitting it, and only if a hash/ticket override is active. This keeps the legacy path free of
        // the positional ambiguity that would otherwise arise between "password" and a trailing arg.
        if (hostIndex + 2 < args.Length)
        {
            return new Creds(legacyHost, legacyUser, args[hostIndex + 2], null, hostIndex + 3, IsTarget: false);
        }

        if (GlobalOptions.PasswordOptional)
        {
            return new Creds(legacyHost, legacyUser, null, null, hostIndex + 2, IsTarget: false);
        }

        throw new CredsUsageException(usage);
    }
}

/// <summary>Thrown by <see cref="Creds.Resolve"/> when the credential arguments are missing/invalid.</summary>
internal sealed class CredsUsageException(string message) : Exception(message);
