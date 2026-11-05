using System.Xml;

namespace DotNetPacket.Protocols.Gpp;

/// <summary>A cpassword finding carved from a GPP XML file: its source, context, and the recovered plaintext.</summary>
public sealed record GppFinding(
    string Type,
    string File,
    string? Name,
    string? UserName,
    string? NewName,
    string? RunAs,
    string Cpassword,
    string Password,
    string? Changed);

/// <summary>
/// Parses Group Policy Preferences XML (Groups.xml, ScheduledTasks.xml, Services.xml, …) and
/// extracts every <c>cpassword</c> it carries, decrypting each with <see cref="GppCrypto"/>.
/// Port of the <c>parse_xmlfile_content</c> routine in impacket's
/// <c>examples/Get-GPPPassword.py</c>: it walks each <c>&lt;Properties&gt;</c> element that
/// has a <c>cpassword</c> attribute and reads the context attributes beside it.
/// </summary>
public static class GppPreferences
{
    /// <summary>Returns true if the raw text even mentions a cpassword (impacket's cheap pre-filter).</summary>
    public static bool ContainsCpassword(string content) => content.Contains("cpassword");

    /// <summary>Parses XML content and returns every cpassword finding (empty list if none / unparseable).</summary>
    public static IReadOnlyList<GppFinding> Parse(string filename, string xmlContent)
    {
        var findings = new List<GppFinding>();

        var doc = new XmlDocument { XmlResolver = null }; // never resolve external entities
        try
        {
            doc.LoadXml(xmlContent);
        }
        catch (XmlException)
        {
            return findings;
        }

        string type = doc.DocumentElement?.Name ?? string.Empty;

        // Every GPP item nests the credential in a <Properties cpassword="..."> element.
        foreach (XmlNode node in doc.GetElementsByTagName("Properties"))
        {
            if (node is not XmlElement props)
            {
                continue;
            }

            string? cpassword = Attr(props, "cpassword");
            if (cpassword is null)
            {
                continue; // only the Properties elements that actually carry a cpassword
            }

            string? changed = node.ParentNode is XmlElement parent ? Attr(parent, "changed") : null;

            findings.Add(new GppFinding(
                Type: type,
                File: filename,
                Name: node.ParentNode is XmlElement p ? Attr(p, "name") : null,
                UserName: Attr(props, "userName"),
                NewName: Attr(props, "newName"),
                RunAs: Attr(props, "runAs"),
                Cpassword: cpassword,
                Password: GppCrypto.DecryptCpassword(cpassword),
                Changed: changed));
        }

        return findings;
    }

    // Returns the attribute value, or null when the attribute is absent.
    private static string? Attr(XmlElement element, string name) =>
        element.HasAttribute(name) ? element.GetAttribute(name) : null;
}
