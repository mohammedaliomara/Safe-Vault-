using System.Text.RegularExpressions;
using System.Web;

namespace SafeVault.Helpers;

/// <summary>
/// Provides secure input validation and sanitisation to prevent
/// SQL Injection, XSS, and other injection attacks.
/// </summary>
public static class InputValidator
{
    // ── Username ──────────────────────────────────────────────────────────────
    private static readonly Regex UsernameRegex =
        new(@"^[a-zA-Z0-9_]{3,30}$", RegexOptions.Compiled);

    /// <summary>Validates a username: 3-30 alphanumeric/underscore characters.</summary>
    public static bool IsValidUsername(string? username)
    {
        if (string.IsNullOrWhiteSpace(username)) return false;
        return UsernameRegex.IsMatch(username);
    }

    // ── Password ──────────────────────────────────────────────────────────────
    /// <summary>
    /// Enforces a strong password policy:
    /// minimum 8 chars, at least one uppercase, one lowercase,
    /// one digit, and one special character.
    /// </summary>
    public static bool IsValidPassword(string? password)
    {
        if (string.IsNullOrWhiteSpace(password) || password.Length < 8) return false;

        bool hasUpper   = password.Any(char.IsUpper);
        bool hasLower   = password.Any(char.IsLower);
        bool hasDigit   = password.Any(char.IsDigit);
        bool hasSpecial = password.Any(c => !char.IsLetterOrDigit(c));

        return hasUpper && hasLower && hasDigit && hasSpecial;
    }

    // ── Email ─────────────────────────────────────────────────────────────────
    private static readonly Regex EmailRegex =
        new(@"^[^@\s]+@[^@\s]+\.[^@\s]+$", RegexOptions.Compiled);

    /// <summary>Basic RFC-compatible e-mail format check.</summary>
    public static bool IsValidEmail(string? email)
    {
        if (string.IsNullOrWhiteSpace(email)) return false;
        return EmailRegex.IsMatch(email) && email.Length <= 254;
    }

    // ── XSS Sanitisation ──────────────────────────────────────────────────────
    /// <summary>
    /// HTML-encodes user-supplied text so it cannot be interpreted as markup.
    /// Use this before rendering any user input in an HTML context.
    /// </summary>
    public static string SanitizeForHtml(string? input)
    {
        if (string.IsNullOrEmpty(input)) return string.Empty;
        return HttpUtility.HtmlEncode(input);
    }

    /// <summary>
    /// Strips characters that are dangerous in SQL LIKE clauses (%, _, \).
    /// Note: always prefer parameterised queries; this is a defence-in-depth measure.
    /// </summary>
    public static string SanitizeSqlLikeWildcards(string input)
    {
        return input.Replace("\\", "\\\\")
                    .Replace("%",  "\\%")
                    .Replace("_",  "\\_");
    }

    // ── General length guard ──────────────────────────────────────────────────
    /// <summary>Ensures a string does not exceed the permitted length.</summary>
    public static bool IsWithinLength(string? input, int maxLength)
    {
        return input is not null && input.Length <= maxLength;
    }

    // ── SQL Injection detection (defence-in-depth) ────────────────────────────
    private static readonly string[] SqlKeywords =
    {
        "--", ";", "/*", "*/", "xp_", "UNION", "SELECT", "INSERT",
        "UPDATE", "DELETE", "DROP", "EXEC", "EXECUTE", "CAST(", "CONVERT("
    };

    /// <summary>
    /// Heuristic check for common SQL-injection patterns.
    /// This supplements—never replaces—parameterised queries.
    /// </summary>
    public static bool ContainsSqlInjectionPatterns(string? input)
    {
        if (string.IsNullOrEmpty(input)) return false;
        var upper = input.ToUpperInvariant();
        return SqlKeywords.Any(k => upper.Contains(k.ToUpperInvariant()));
    }
}
