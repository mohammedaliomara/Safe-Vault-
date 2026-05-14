using SafeVault.Helpers;
using SafeVault.Models;

namespace SafeVault.Services;

/// <summary>
/// Business logic for SafeVault entries.
/// Enforces RBAC and input validation before touching the database.
/// </summary>
public class VaultService
{
    private readonly DatabaseService     _db;
    private readonly AuthService         _auth;

    public VaultService(DatabaseService db, AuthService auth)
    {
        _db   = db;
        _auth = auth;
    }

    // ── Add entry ─────────────────────────────────────────────────────────────
    public (bool Success, string Message) AddEntry(
        string token, string title, string secretValue)
    {
        var (valid, _, role, userId) = _auth.ValidateToken(token);
        if (!valid) return (false, "Unauthorized: invalid or expired token.");

        AuthorizationService.RequireRole(role, "Admin", "User");

        // Validate and sanitise inputs
        if (string.IsNullOrWhiteSpace(title) || !InputValidator.IsWithinLength(title, 200))
            return (false, "Title must be 1-200 characters.");

        if (string.IsNullOrWhiteSpace(secretValue))
            return (false, "Secret value cannot be empty.");

        if (InputValidator.ContainsSqlInjectionPatterns(title))
            return (false, "Title contains disallowed characters.");

        // Sanitise for HTML output (defence against stored XSS)
        string safeTitle  = InputValidator.SanitizeForHtml(title);
        string safeSecret = InputValidator.SanitizeForHtml(secretValue);

        var entry = new VaultEntry
        {
            OwnerId     = userId!.Value,
            Title       = safeTitle,
            SecretValue = safeSecret,
        };

        bool created = _db.CreateVaultEntry(entry);
        return created ? (true, "Entry created.") : (false, "Failed to create entry.");
    }

    // ── List entries ──────────────────────────────────────────────────────────
    public (bool Success, string Message, List<VaultEntry>? Entries)
        GetEntries(string token)
    {
        var (valid, _, role, userId) = _auth.ValidateToken(token);
        if (!valid) return (false, "Unauthorized.", null);

        AuthorizationService.RequireRole(role, "Admin", "User", "ReadOnly");

        // Admins see all; everyone else sees only their own
        var entries = role == "Admin"
            ? _db.GetVaultEntries()
            : _db.GetVaultEntries(userId);

        return (true, "OK", entries);
    }

    // ── Delete entry ──────────────────────────────────────────────────────────
    public (bool Success, string Message) DeleteEntry(string token, int entryId)
    {
        var (valid, _, role, userId) = _auth.ValidateToken(token);
        if (!valid) return (false, "Unauthorized.");

        AuthorizationService.RequireRole(role, "Admin", "User");

        bool deleted = _db.DeleteVaultEntry(entryId, userId!.Value, role!);
        return deleted
            ? (true, "Entry deleted.")
            : (false, "Entry not found or access denied.");
    }
}
