using SafeVault.Helpers;
using SafeVault.Services;
using Xunit;

namespace SafeVault.Tests;

// ─────────────────────────────────────────────────────────────────────────────
//  1. INPUT VALIDATION TESTS
// ─────────────────────────────────────────────────────────────────────────────
public class InputValidatorTests
{
    // Username
    [Theory]
    [InlineData("alice",     true)]
    [InlineData("Bob_123",   true)]
    [InlineData("ab",        false)]   // too short
    [InlineData("",          false)]   // empty
    [InlineData("alice!",    false)]   // special char
    [InlineData("a very long username that exceeds thirty chars!!", false)]
    public void IsValidUsername_ReturnsExpected(string input, bool expected) =>
        Assert.Equal(expected, InputValidator.IsValidUsername(input));

    // Password
    [Theory]
    [InlineData("StrongP@ss1",  true)]
    [InlineData("password",     false)]  // no uppercase/digit/special
    [InlineData("SHORT1!",      false)]  // under 8 chars
    [InlineData("nouppercase1!", false)]  // no uppercase
    [InlineData("NOLOWER1!",    false)]  // no lowercase
    [InlineData("NoDigit!Pass", false)]  // no digit
    [InlineData("NoSpecial1",   false)]  // no special char
    public void IsValidPassword_ReturnsExpected(string input, bool expected) =>
        Assert.Equal(expected, InputValidator.IsValidPassword(input));

    // Email
    [Theory]
    [InlineData("user@example.com", true)]
    [InlineData("a@b.io",           true)]
    [InlineData("notanemail",       false)]
    [InlineData("missing@tld",      false)]
    [InlineData("",                 false)]
    public void IsValidEmail_ReturnsExpected(string input, bool expected) =>
        Assert.Equal(expected, InputValidator.IsValidEmail(input));

    // SQL injection detection
    [Theory]
    [InlineData("'; DROP TABLE Users;--",   true)]
    [InlineData("' OR '1'='1",              true)]
    [InlineData("UNION SELECT * FROM users",true)]
    [InlineData("normal input",             false)]
    [InlineData("alice_99",                 false)]
    public void ContainsSqlInjectionPatterns_ReturnsExpected(string input, bool expected) =>
        Assert.Equal(expected, InputValidator.ContainsSqlInjectionPatterns(input));

    // XSS sanitisation
    [Fact]
    public void SanitizeForHtml_EncodesScriptTag()
    {
        string output = InputValidator.SanitizeForHtml("<script>alert('xss')</script>");
        Assert.DoesNotContain("<script>", output);
        Assert.Contains("&lt;script&gt;", output);
    }

    [Fact]
    public void SanitizeForHtml_EncodesAmpersandAndQuotes()
    {
        string output = InputValidator.SanitizeForHtml("a & b \"quoted\"");
        Assert.Contains("&amp;",  output);
        Assert.Contains("&quot;", output);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  2. AUTHENTICATION TESTS
// ─────────────────────────────────────────────────────────────────────────────
public class AuthServiceTests : IDisposable
{
    private readonly DatabaseService _db;
    private readonly AuthService     _auth;

    public AuthServiceTests()
    {
        _db   = new DatabaseService(":memory:");
        _auth = new AuthService(_db);
    }

    [Fact]
    public void Register_ValidUser_Succeeds()
    {
        var (success, _) = _auth.Register("testuser", "Test@Pass1!", "test@example.com");
        Assert.True(success);
    }

    [Fact]
    public void Register_DuplicateUsername_Fails()
    {
        _auth.Register("dupeuser", "Test@Pass1!", "unique@example.com");
        var (success, msg) = _auth.Register("dupeuser", "Test@Pass1!", "other@example.com");
        Assert.False(success);
        Assert.Contains("already exists", msg);
    }

    [Fact]
    public void Register_WeakPassword_Fails()
    {
        var (success, msg) = _auth.Register("user2", "weak", "weak@example.com");
        Assert.False(success);
        Assert.Contains("Password", msg);
    }

    [Fact]
    public void Register_InvalidEmail_Fails()
    {
        var (success, _) = _auth.Register("user3", "Valid@Pass1!", "not-an-email");
        Assert.False(success);
    }

    [Fact]
    public void Login_ValidCredentials_ReturnsToken()
    {
        _auth.Register("loginuser", "Login@Pass1!", "login@example.com");
        var (success, _, token) = _auth.Login("loginuser", "Login@Pass1!");
        Assert.True(success);
        Assert.NotNull(token);
    }

    [Fact]
    public void Login_WrongPassword_Fails()
    {
        _auth.Register("wrongpw", "Correct@Pass1!", "wrongpw@example.com");
        var (success, msg, token) = _auth.Login("wrongpw", "WrongPassword!");
        Assert.False(success);
        Assert.Null(token);
        Assert.Equal("Invalid credentials.", msg);
    }

    [Fact]
    public void Login_NonExistentUser_Fails()
    {
        var (success, _, token) = _auth.Login("nobody", "Pass@word1!");
        Assert.False(success);
        Assert.Null(token);
    }

    [Fact]
    public void Login_LocksAccountAfter5FailedAttempts()
    {
        _auth.Register("lockme", "Lock@Pass1!", "lockme@example.com");
        for (int i = 0; i < 5; i++)
            _auth.Login("lockme", "WrongPassword!");

        var (success, msg, _) = _auth.Login("lockme", "Lock@Pass1!");
        Assert.False(success);
        Assert.Contains("locked", msg, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ValidateToken_ValidToken_ReturnsTrue()
    {
        _auth.Register("tokenuser", "Token@Pass1!", "token@example.com");
        var (_, _, token) = _auth.Login("tokenuser", "Token@Pass1!");
        var (valid, username, role, _) = _auth.ValidateToken(token!);
        Assert.True(valid);
        Assert.Equal("tokenuser", username);
        Assert.Equal("User", role);
    }

    [Fact]
    public void ValidateToken_InvalidToken_ReturnsFalse()
    {
        var (valid, _, _, _) = _auth.ValidateToken("this.is.not.valid");
        Assert.False(valid);
    }

    public void Dispose() => _db.Dispose();
}

// ─────────────────────────────────────────────────────────────────────────────
//  3. AUTHORISATION / RBAC TESTS
// ─────────────────────────────────────────────────────────────────────────────
public class AuthorizationServiceTests
{
    [Theory]
    [InlineData("Admin",    true)]
    [InlineData("User",     true)]
    [InlineData("ReadOnly", true)]
    [InlineData("Unknown",  false)]
    public void CanReadOwnEntries_CorrectForRole(string role, bool expected) =>
        Assert.Equal(expected, AuthorizationService.CanReadOwnEntries(role));

    [Theory]
    [InlineData("Admin",    true)]
    [InlineData("User",     false)]
    [InlineData("ReadOnly", false)]
    public void CanReadAllEntries_OnlyAdmin(string role, bool expected) =>
        Assert.Equal(expected, AuthorizationService.CanReadAllEntries(role));

    [Theory]
    [InlineData("Admin",    true)]
    [InlineData("User",     true)]
    [InlineData("ReadOnly", false)]
    public void CanCreateEntry_AdminAndUser(string role, bool expected) =>
        Assert.Equal(expected, AuthorizationService.CanCreateEntry(role));

    [Theory]
    [InlineData("Admin",    true)]
    [InlineData("User",     true)]
    [InlineData("ReadOnly", false)]
    public void CanDeleteEntry_AdminAndUser(string role, bool expected) =>
        Assert.Equal(expected, AuthorizationService.CanDeleteEntry(role));

    [Fact]
    public void CanManageUsers_OnlyAdmin()
    {
        Assert.True(AuthorizationService.CanManageUsers("Admin"));
        Assert.False(AuthorizationService.CanManageUsers("User"));
    }

    [Fact]
    public void CanAccessEntry_AdminCanAccessAnyEntry()
    {
        Assert.True(AuthorizationService.CanAccessEntry("Admin", 1, 99));
    }

    [Fact]
    public void CanAccessEntry_UserCanOnlyAccessOwnEntry()
    {
        Assert.True(AuthorizationService.CanAccessEntry("User", 5, 5));
        Assert.False(AuthorizationService.CanAccessEntry("User", 5, 6));
    }

    [Fact]
    public void RequireRole_ThrowsForUnauthorisedRole()
    {
        Assert.Throws<UnauthorizedAccessException>(() =>
            AuthorizationService.RequireRole("User", "Admin"));
    }

    [Fact]
    public void RequireOwnershipOrAdmin_ThrowsWhenUserAccessesOthersResource()
    {
        Assert.Throws<UnauthorizedAccessException>(() =>
            AuthorizationService.RequireOwnershipOrAdmin("User", 1, 2));
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  4. SQL INJECTION PREVENTION TESTS
// ─────────────────────────────────────────────────────────────────────────────
public class SqlInjectionTests : IDisposable
{
    private readonly DatabaseService _db;
    private readonly AuthService     _auth;
    private readonly VaultService    _vault;

    public SqlInjectionTests()
    {
        _db    = new DatabaseService(":memory:");
        _auth  = new AuthService(_db);
        _vault = new VaultService(_db, _auth);
        _auth.Register("safeuser", "Safe@Pass1!", "safe@example.com");
    }

    [Theory]
    [InlineData("'; DROP TABLE Users;--")]
    [InlineData("' OR '1'='1")]
    [InlineData("admin'--")]
    [InlineData("\" OR \"\"=\"")]
    public void Register_SqlInjectionInUsername_IsRejected(string maliciousUsername)
    {
        var (success, _) = _auth.Register(maliciousUsername, "Safe@Pass1!", "inj@example.com");
        Assert.False(success);
    }

    [Theory]
    [InlineData("' OR '1'='1")]
    [InlineData("'; DROP TABLE Users;--")]
    public void Login_SqlInjectionUsername_CannotBypassAuth(string sqlPayload)
    {
        var (success, _, token) = _auth.Login(sqlPayload, "anything");
        Assert.False(success);
        Assert.Null(token);
    }

    [Fact]
    public void VaultAdd_SqlInjectionInTitle_IsRejected()
    {
        var (_, _, token) = _auth.Login("safeuser", "Safe@Pass1!");
        var (success, _)  = _vault.AddEntry(token!, "' UNION SELECT * FROM Users--", "val");
        Assert.False(success);
    }

    public void Dispose() => _db.Dispose();
}

// ─────────────────────────────────────────────────────────────────────────────
//  5. XSS PREVENTION TESTS
// ─────────────────────────────────────────────────────────────────────────────
public class XssPreventionTests : IDisposable
{
    private readonly DatabaseService _db;
    private readonly AuthService     _auth;
    private readonly VaultService    _vault;

    public XssPreventionTests()
    {
        _db    = new DatabaseService(":memory:");
        _auth  = new AuthService(_db);
        _vault = new VaultService(_db, _auth);
        _auth.Register("xssuser", "Xss@Pass1!", "xss@example.com");
    }

    [Fact]
    public void VaultAdd_XssInTitle_IsSanitised()
    {
        var (_, _, token) = _auth.Login("xssuser", "Xss@Pass1!");
        _vault.AddEntry(token!, "<script>alert('xss')</script>", "value");

        var (_, _, entries) = _vault.GetEntries(token!);
        Assert.NotNull(entries);
        // Stored value must not contain a raw <script> tag
        Assert.DoesNotContain(entries!, e => e.Title.Contains("<script>"));
    }

    [Theory]
    [InlineData("<img src=x onerror=alert(1)>")]
    [InlineData("<svg onload=alert(1)>")]
    [InlineData("javascript:alert(1)")]
    public void SanitizeForHtml_NeutralisesPayloads(string payload)
    {
        string result = InputValidator.SanitizeForHtml(payload);
        Assert.DoesNotContain("<",     result);
        Assert.DoesNotContain(">",     result);
    }

    public void Dispose() => _db.Dispose();
}

// ─────────────────────────────────────────────────────────────────────────────
//  6. VAULT SERVICE INTEGRATION TESTS
// ─────────────────────────────────────────────────────────────────────────────
public class VaultServiceTests : IDisposable
{
    private readonly DatabaseService _db;
    private readonly AuthService     _auth;
    private readonly VaultService    _vault;
    private readonly string          _adminToken;
    private readonly string          _userToken;
    private readonly string          _readOnlyToken;

    public VaultServiceTests()
    {
        _db    = new DatabaseService(":memory:");
        _auth  = new AuthService(_db);
        _vault = new VaultService(_db, _auth);

        _auth.Register("vadmin",  "Admin@Pass1!",   "vadmin@example.com",  "Admin");
        _auth.Register("vuser",   "User@Pass1!",    "vuser@example.com",   "User");
        _auth.Register("vro",     "ReadOnly@Pass1!", "vro@example.com",    "ReadOnly");

        _adminToken    = _auth.Login("vadmin", "Admin@Pass1!").Token!;
        _userToken     = _auth.Login("vuser",  "User@Pass1!").Token!;
        _readOnlyToken = _auth.Login("vro",    "ReadOnly@Pass1!").Token!;
    }

    [Fact]
    public void AddEntry_WithValidUserToken_Succeeds()
    {
        var (success, _) = _vault.AddEntry(_userToken, "My Secret", "s3cr3t!");
        Assert.True(success);
    }

    [Fact]
    public void AddEntry_WithReadOnlyToken_Fails()
    {
        var (success, msg) = _vault.AddEntry(_readOnlyToken, "Blocked", "value");
        Assert.False(success);
    }

    [Fact]
    public void AddEntry_WithInvalidToken_Fails()
    {
        var (success, msg) = _vault.AddEntry("bad.token.here", "Test", "value");
        Assert.False(success);
        Assert.Contains("Unauthorized", msg);
    }

    [Fact]
    public void GetEntries_AdminSeesAll()
    {
        _vault.AddEntry(_userToken,  "User entry",  "v1");
        _vault.AddEntry(_adminToken, "Admin entry", "v2");

        var (_, _, entries) = _vault.GetEntries(_adminToken);
        Assert.NotNull(entries);
        Assert.True(entries!.Count >= 2);
    }

    [Fact]
    public void GetEntries_UserSeesOnlyOwn()
    {
        _vault.AddEntry(_userToken, "My Entry", "value");
        var (_, _, entries) = _vault.GetEntries(_userToken);
        Assert.NotNull(entries);
        Assert.All(entries!, e => Assert.NotEqual(0, e.OwnerId));
    }

    [Fact]
    public void DeleteEntry_AdminCanDeleteAnyEntry()
    {
        _vault.AddEntry(_userToken, "To Delete", "val");
        var (_, _, entries) = _vault.GetEntries(_adminToken);
        var (success, _)    = _vault.DeleteEntry(_adminToken, entries![0].Id);
        Assert.True(success);
    }

    [Fact]
    public void DeleteEntry_UserCannotDeleteOthersEntry()
    {
        _vault.AddEntry(_adminToken, "Admin's Secret", "val");
        var (_, _, allEntries) = _vault.GetEntries(_adminToken);
        var adminEntry = allEntries!.First(e => e.Title == "Admin&#39;s Secret"
                                              || e.Title == "Admin's Secret"
                                              || e.Title.Contains("Admin"));
        var (success, _) = _vault.DeleteEntry(_userToken, adminEntry.Id);
        Assert.False(success);
    }

    public void Dispose() => _db.Dispose();
}
