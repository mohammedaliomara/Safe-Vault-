using BCrypt.Net;
using SafeVault.Helpers;
using SafeVault.Models;

namespace SafeVault.Services;

/// <summary>
/// Handles registration, login, and token issuance.
/// Passwords are hashed with BCrypt (work-factor 12) – never stored in plain text.
/// The account lockout policy mitigates brute-force attacks.
/// </summary>
public class AuthService
{
    private readonly DatabaseService _db;

    public AuthService(DatabaseService db) => _db = db;

    // ── Registration ──────────────────────────────────────────────────────────
    public (bool Success, string Message) Register(
        string username, string password, string email, string role = "User")
    {
        // 1. Validate inputs
        if (!InputValidator.IsValidUsername(username))
            return (false, "Username must be 3-30 alphanumeric/underscore characters.");

        if (!InputValidator.IsValidPassword(password))
            return (false,
                "Password must be ≥8 characters and include uppercase, lowercase, digit, and special character.");

        if (!InputValidator.IsValidEmail(email))
            return (false, "Invalid e-mail address.");

        if (!new[] { "Admin", "User", "ReadOnly" }.Contains(role))
            return (false, "Invalid role.");

        // 2. Check for SQL-injection patterns (defence-in-depth)
        if (InputValidator.ContainsSqlInjectionPatterns(username) ||
            InputValidator.ContainsSqlInjectionPatterns(email))
            return (false, "Input contains disallowed characters.");

        // 3. Hash password with BCrypt (work-factor 12)
        string passwordHash = BCrypt.Net.BCrypt.HashPassword(password, workFactor: 12);

        var user = new User
        {
            Username     = username,
            PasswordHash = passwordHash,
            Email        = email,
            Role         = role,
        };

        bool created = _db.CreateUser(user);
        return created
            ? (true, "Registration successful.")
            : (false, "Username or e-mail already exists.");
    }

    // ── Login ─────────────────────────────────────────────────────────────────
    public (bool Success, string Message, string? Token) Login(
        string username, string password)
    {
        // 1. Basic validation
        if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(password))
            return (false, "Username and password are required.", null);

        // 2. Look up user (parameterised query inside)
        var user = _db.GetUserByUsername(username);
        if (user is null)
            return (false, "Invalid credentials.", null);   // Do NOT reveal "user not found"

        // 3. Account lockout check
        if (user.IsLocked)
            return (false, "Account is locked due to too many failed attempts. Contact an admin.", null);

        // 4. Verify password hash
        bool passwordValid = BCrypt.Net.BCrypt.Verify(password, user.PasswordHash);
        if (!passwordValid)
        {
            _db.RecordFailedLogin(user.Id);
            return (false, "Invalid credentials.", null);
        }

        // 5. Success – reset counter and issue JWT
        _db.ResetFailedLogin(user.Id);
        string token = JwtHelper.GenerateToken(user);
        return (true, "Login successful.", token);
    }

    // ── Token validation shortcut ─────────────────────────────────────────────
    public (bool Valid, string? Username, string? Role, int? UserId)
        ValidateToken(string token)
    {
        var principal = JwtHelper.ValidateToken(token);
        if (principal is null)
            return (false, null, null, null);

        string? username = principal.Identity?.Name;
        string? role     = JwtHelper.GetRole(principal);
        int?    userId   = JwtHelper.GetUserId(principal);

        return (true, username, role, userId);
    }
}
