namespace SafeVault.Services;

/// <summary>
/// Role-Based Access Control (RBAC) service.
///
/// Roles hierarchy:
///   Admin    – full access: manage users, read/write/delete any vault entry.
///   User     – read/write/delete their own vault entries.
///   ReadOnly – read their own vault entries only.
/// </summary>
public static class AuthorizationService
{
    // ── Permission checks ─────────────────────────────────────────────────────

    public static bool CanReadOwnEntries(string role) =>
        role is "Admin" or "User" or "ReadOnly";

    public static bool CanReadAllEntries(string role) =>
        role == "Admin";

    public static bool CanCreateEntry(string role) =>
        role is "Admin" or "User";

    public static bool CanDeleteEntry(string role) =>
        role is "Admin" or "User";

    public static bool CanManageUsers(string role) =>
        role == "Admin";

    // ── Ownership enforcement ─────────────────────────────────────────────────

    /// <summary>
    /// Returns true when the requesting user is an Admin
    /// OR is the resource owner.
    /// </summary>
    public static bool CanAccessEntry(string role, int requestingUserId, int entryOwnerId) =>
        role == "Admin" || requestingUserId == entryOwnerId;

    // ── Convenience: assert or throw ─────────────────────────────────────────

    public static void RequireRole(string? actualRole, params string[] allowedRoles)
    {
        if (actualRole is null || !allowedRoles.Contains(actualRole))
            throw new UnauthorizedAccessException(
                $"Access denied. Required role(s): {string.Join(", ", allowedRoles)}.");
    }

    public static void RequireOwnershipOrAdmin(
        string role, int requestingUserId, int resourceOwnerId)
    {
        if (!CanAccessEntry(role, requestingUserId, resourceOwnerId))
            throw new UnauthorizedAccessException(
                "Access denied. You can only access your own resources.");
    }
}
