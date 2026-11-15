using System.Net.Sockets;

namespace DotNetPacket.Core.Net;

/// <summary>The proxy protocol DotNetPacket dials an outbound TCP connection through.</summary>
public enum ProxyScheme
{
    /// <summary>SOCKS5 (RFC 1928), connecting to the target by domain name so it resolves on the far side.</summary>
    Socks5,

    /// <summary>SOCKS4a — like SOCKS4 but the hostname is sent to the proxy (resolved on the far side).</summary>
    Socks4a,

    /// <summary>SOCKS4 (RFC 1928 predecessor) — the client resolves the target to an IPv4 address first.</summary>
    Socks4,

    /// <summary>HTTP <c>CONNECT</c> tunnel (RFC 7231 §4.3.6), with optional Basic auth.</summary>
    Http,
}

/// <summary>
/// A parsed upstream proxy, the DotNetPacket equivalent of running impacket under
/// <c>proxychains</c> (or routing it through a transparent redirector such as a SOCKS pivot).
/// Built from a URL: <c>socks5://[user:pass@]host:port</c>, <c>socks4a://host:port</c>,
/// <c>socks4://host:port</c>, or <c>http://[user:pass@]host:port</c> (<c>socks://</c> ==
/// <c>socks5://</c>). The default port is 1080 for SOCKS and 8080 for HTTP.
/// </summary>
public sealed record ProxyEndpoint(ProxyScheme Scheme, string Host, int Port, string? Username = null, string? Password = null)
{
    /// <summary>
    /// Parses a proxy URL. Throws <see cref="FormatException"/> on an unrecognised scheme or a
    /// missing host.
    /// </summary>
    public static ProxyEndpoint Parse(string url)
    {
        if (string.IsNullOrWhiteSpace(url))
        {
            throw new FormatException("Empty proxy URL.");
        }

        int schemeSep = url.IndexOf("://", StringComparison.Ordinal);
        if (schemeSep < 0)
        {
            throw new FormatException($"Proxy URL '{url}' has no scheme (expected e.g. socks5://host:port).");
        }

        string schemeText = url[..schemeSep].ToLowerInvariant();
        ProxyScheme scheme = schemeText switch
        {
            "socks" or "socks5" or "socks5h" => ProxyScheme.Socks5,
            "socks4a" => ProxyScheme.Socks4a,
            "socks4" => ProxyScheme.Socks4,
            "http" or "https" => ProxyScheme.Http,
            _ => throw new FormatException($"Unknown proxy scheme '{schemeText}' (use socks5, socks4a, socks4 or http)."),
        };

        string rest = url[(schemeSep + 3)..];
        string? user = null, pass = null;
        int at = rest.LastIndexOf('@');
        if (at >= 0)
        {
            string creds = rest[..at];
            rest = rest[(at + 1)..];
            int colon = creds.IndexOf(':');
            if (colon >= 0)
            {
                user = creds[..colon];
                pass = creds[(colon + 1)..];
            }
            else
            {
                user = creds;
            }
        }

        // Strip any trailing path; keep host:port.
        int slash = rest.IndexOf('/');
        if (slash >= 0)
        {
            rest = rest[..slash];
        }

        int portSep = rest.LastIndexOf(':');
        string host;
        int port;
        if (portSep >= 0 && int.TryParse(rest[(portSep + 1)..], out port))
        {
            host = rest[..portSep];
        }
        else
        {
            host = rest;
            port = scheme == ProxyScheme.Http ? 8080 : 1080;
        }

        if (string.IsNullOrEmpty(host))
        {
            throw new FormatException($"Proxy URL '{url}' has no host.");
        }

        return new ProxyEndpoint(scheme, host, port, user, pass);
    }

    /// <summary>Opens a raw TCP connection to the proxy server itself (not yet tunnelled).</summary>
    internal TcpClient ConnectToProxy(int timeoutMs)
    {
        var tcp = new TcpClient();
        if (!tcp.ConnectAsync(Host, Port).Wait(timeoutMs))
        {
            tcp.Dispose();
            throw new TimeoutException($"Timed out connecting to proxy {Host}:{Port}.");
        }

        return tcp;
    }

    public override string ToString()
    {
        string scheme = Scheme switch
        {
            ProxyScheme.Socks5 => "socks5",
            ProxyScheme.Socks4a => "socks4a",
            ProxyScheme.Socks4 => "socks4",
            _ => "http",
        };
        string auth = Username is null ? string.Empty : "***@";
        return $"{scheme}://{auth}{Host}:{Port}";
    }
}
