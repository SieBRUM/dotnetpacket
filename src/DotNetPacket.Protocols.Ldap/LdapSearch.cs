using System.Formats.Asn1;
using System.Text;

namespace DotNetPacket.Protocols.Ldap;

/// <summary>LDAP search scope (RFC 4511 4.5.1.2).</summary>
public enum LdapSearchScope
{
    BaseObject = 0,
    SingleLevel = 1,
    WholeSubtree = 2,
}

/// <summary>LDAP alias-dereferencing policy (RFC 4511 4.5.1.3).</summary>
public enum LdapDerefAliases
{
    NeverDerefAliases = 0,
    DerefInSearching = 1,
    DerefFindingBaseObj = 2,
    DerefAlways = 3,
}

/// <summary>
/// An LDAP search Filter (RFC 4511 4.5.1). Only the pieces the ported examples need are
/// implemented: conjunction/disjunction, equality match, and presence. Each node knows how to
/// BER-encode itself into the context-tagged CHOICE the protocol defines.
/// </summary>
public abstract class LdapFilter
{
    internal static readonly Asn1Tag And = new(TagClass.ContextSpecific, 0, isConstructed: true);
    internal static readonly Asn1Tag Or = new(TagClass.ContextSpecific, 1, isConstructed: true);
    internal static readonly Asn1Tag Not = new(TagClass.ContextSpecific, 2, isConstructed: true);
    internal static readonly Asn1Tag EqualityMatch = new(TagClass.ContextSpecific, 3, isConstructed: true);
    internal static readonly Asn1Tag Present = new(TagClass.ContextSpecific, 7, isConstructed: false);
    internal static readonly Asn1Tag ExtensibleMatchTag = new(TagClass.ContextSpecific, 9, isConstructed: true);
    internal static readonly Asn1Tag MatchingRuleTag = new(TagClass.ContextSpecific, 1, isConstructed: false);
    internal static readonly Asn1Tag MatchTypeTag = new(TagClass.ContextSpecific, 2, isConstructed: false);
    internal static readonly Asn1Tag MatchValueTag = new(TagClass.ContextSpecific, 3, isConstructed: false);
    internal static readonly Asn1Tag DnAttributesTag = new(TagClass.ContextSpecific, 4, isConstructed: false);

    internal abstract void Write(AsnWriter writer);

    /// <summary>An <c>(attr=value)</c> equality match.</summary>
    public static LdapFilter Equal(string attribute, string value) => new EqualityFilter(attribute, value);

    /// <summary>An <c>(attr=*)</c> presence test.</summary>
    public static LdapFilter PresentOf(string attribute) => new PresentFilter(attribute);

    /// <summary>An <c>(&amp;(…)(…))</c> conjunction.</summary>
    public static LdapFilter AllOf(params LdapFilter[] filters) => new JunctionFilter(And, filters);

    /// <summary>An <c>(|(…)(…))</c> disjunction.</summary>
    public static LdapFilter AnyOf(params LdapFilter[] filters) => new JunctionFilter(Or, filters);

    /// <summary>A <c>(!(…))</c> negation.</summary>
    public static LdapFilter Negate(LdapFilter inner) => new NotFilter(inner);

    /// <summary>
    /// An extensible match <c>(type:rule:=value)</c> (RFC 4511 4.5.1.7.7). Used e.g. for the
    /// AD "bit set" rule <c>userAccountControl:1.2.840.113556.1.4.803:=2</c>.
    /// </summary>
    public static LdapFilter Extensible(string? matchingRule, string? type, string value, bool dnAttributes = false) =>
        new ExtensibleFilter(matchingRule, type, value, dnAttributes);

    private sealed class EqualityFilter(string attribute, string value) : LdapFilter
    {
        internal override void Write(AsnWriter writer)
        {
            // equalityMatch [3] AttributeValueAssertion — [3] IMPLICIT SEQUENCE { attr, value }.
            using (writer.PushSequence(EqualityMatch))
            {
                writer.WriteOctetString(Encoding.UTF8.GetBytes(attribute));
                writer.WriteOctetString(Encoding.UTF8.GetBytes(value));
            }
        }
    }

    private sealed class PresentFilter(string attribute) : LdapFilter
    {
        internal override void Write(AsnWriter writer) =>
            writer.WriteOctetString(Encoding.UTF8.GetBytes(attribute), Present); // [7] IMPLICIT primitive
    }

    private sealed class JunctionFilter(Asn1Tag tag, LdapFilter[] filters) : LdapFilter
    {
        internal override void Write(AsnWriter writer)
        {
            using (writer.PushSetOf(tag)) // and [0] / or [1] IMPLICIT SET OF Filter
            {
                foreach (LdapFilter f in filters)
                {
                    f.Write(writer);
                }
            }
        }
    }

    private sealed class NotFilter(LdapFilter inner) : LdapFilter
    {
        internal override void Write(AsnWriter writer)
        {
            using (writer.PushSequence(Not)) // not [2] IMPLICIT Filter (single element)
            {
                inner.Write(writer);
            }
        }
    }

    private sealed class ExtensibleFilter(string? matchingRule, string? type, string value, bool dnAttributes)
        : LdapFilter
    {
        internal override void Write(AsnWriter writer)
        {
            using (writer.PushSequence(ExtensibleMatchTag)) // extensibleMatch [9] MatchingRuleAssertion
            {
                if (matchingRule is not null)
                {
                    writer.WriteOctetString(Encoding.UTF8.GetBytes(matchingRule), MatchingRuleTag); // [1]
                }

                if (type is not null)
                {
                    writer.WriteOctetString(Encoding.UTF8.GetBytes(type), MatchTypeTag); // [2]
                }

                writer.WriteOctetString(Encoding.UTF8.GetBytes(value), MatchValueTag); // [3] matchValue
                if (dnAttributes)
                {
                    writer.WriteBoolean(true, DnAttributesTag); // [4] dnAttributes (omit when default FALSE)
                }
            }
        }
    }
}

/// <summary>One attribute of a SearchResultEntry: its type and raw values (RFC 4511 4.5.2).</summary>
public sealed record SearchAttribute(string Type, IReadOnlyList<byte[]> Values)
{
    /// <summary>The first value decoded as UTF-8, or empty if the attribute has no value.</summary>
    public string FirstString => Values.Count == 0 ? string.Empty : Encoding.UTF8.GetString(Values[0]);
}

/// <summary>A SearchResultEntry (RFC 4511 4.5.2): the object's DN and its returned attributes.</summary>
public sealed record SearchEntry(string ObjectName, IReadOnlyList<SearchAttribute> Attributes)
{
    /// <summary>Returns the first UTF-8 value of <paramref name="type"/>, or empty if absent.</summary>
    public string Get(string type)
    {
        foreach (SearchAttribute a in Attributes)
        {
            if (string.Equals(a.Type, type, StringComparison.OrdinalIgnoreCase))
            {
                return a.FirstString;
            }
        }

        return string.Empty;
    }
}
