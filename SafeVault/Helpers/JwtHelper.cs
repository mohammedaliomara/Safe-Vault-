using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using SafeVault.Models;

namespace SafeVault.Helpers;

/// <summary>
/// Issues and validates signed JWT tokens that carry the user's identity and role,
/// enabling stateless authentication and role-based access control.
/// </summary>
public static class JwtHelper
{
    // In production this must come from a secret store (e.g. Azure Key Vault).
    private const string SecretKey =
        "SafeVault$uper$ecretKey2024!MustBe256BitsLong!!";

    private const string Issuer   = "SafeVault";
    private const string Audience = "SafeVaultUsers";

    private static SymmetricSecurityKey GetKey() =>
        new(Encoding.UTF8.GetBytes(SecretKey));

    /// <summary>Generates a signed JWT valid for 60 minutes.</summary>
    public static string GenerateToken(User user)
    {
        var claims = new[]
        {
            new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new Claim(ClaimTypes.Name,           user.Username),
            new Claim(ClaimTypes.Email,          user.Email),
            new Claim(ClaimTypes.Role,           user.Role),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
        };

        var creds = new SigningCredentials(
            GetKey(), SecurityAlgorithms.HmacSha256);

        var token = new JwtSecurityToken(
            issuer:             Issuer,
            audience:           Audience,
            claims:             claims,
            notBefore:          DateTime.UtcNow,
            expires:            DateTime.UtcNow.AddMinutes(60),
            signingCredentials: creds);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    /// <summary>
    /// Validates a token and returns the principal on success,
    /// or null if the token is invalid / expired.
    /// </summary>
    public static ClaimsPrincipal? ValidateToken(string token)
    {
        var handler = new JwtSecurityTokenHandler();
        var parameters = new TokenValidationParameters
        {
            ValidateIssuer           = true,
            ValidateAudience         = true,
            ValidateLifetime         = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer              = Issuer,
            ValidAudience            = Audience,
            IssuerSigningKey         = GetKey(),
            ClockSkew                = TimeSpan.Zero,
        };

        try
        {
            return handler.ValidateToken(token, parameters, out _);
        }
        catch
        {
            return null;
        }
    }

    /// <summary>Extracts the role claim from a validated principal.</summary>
    public static string? GetRole(ClaimsPrincipal principal) =>
        principal.FindFirstValue(ClaimTypes.Role);

    /// <summary>Extracts the user-id claim from a validated principal.</summary>
    public static int? GetUserId(ClaimsPrincipal principal)
    {
        var val = principal.FindFirstValue(ClaimTypes.NameIdentifier);
        return int.TryParse(val, out var id) ? id : null;
    }
}
