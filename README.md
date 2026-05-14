# SafeVault – Secure Credential Manager

> **Capstone Project** | Microsoft Copilot Security Course  
> A fully secured C# application demonstrating input validation, SQL injection prevention, authentication, RBAC authorization, and XSS mitigation.

---

## 📁 Project Structure

```
SafeVault/
├── SafeVault/
│   ├── Models/
│   │   ├── User.cs              # User entity with lockout fields
│   │   └── VaultEntry.cs        # Secret vault entry entity
│   ├── Helpers/
│   │   ├── InputValidator.cs    # Input validation + XSS/SQLi sanitisation
│   │   └── JwtHelper.cs         # JWT token generation and validation
│   ├── Services/
│   │   ├── DatabaseService.cs   # Parameterised queries (SQLi prevention)
│   │   ├── AuthService.cs       # BCrypt hashing + account lockout
│   │   ├── AuthorizationService.cs  # RBAC policy enforcement
│   │   └── VaultService.cs      # Business logic with auth checks
│   └── Program.cs               # Demo / entry point
├── SafeVault.Tests/
│   └── SecurityTests.cs         # 30+ security tests (xUnit)
└── SafeVault.sln
```

---

## 🚀 Getting Started

### Prerequisites
- [.NET 8 SDK](https://dotnet.microsoft.com/download)

### Run the application
```bash
cd SafeVault
dotnet run --project SafeVault
```

### Run all tests
```bash
dotnet test SafeVault.Tests --logger "console;verbosity=detailed"
```

---

## 🔐 Security Features

### 1. Input Validation & SQL Injection Prevention
- **Parameterised queries** throughout `DatabaseService` – no string interpolation in SQL
- **Username regex** (`^[a-zA-Z0-9_]{3,30}$`) blocks special characters
- **Password policy**: ≥8 chars, uppercase, lowercase, digit, and special character
- **Email format** validation (RFC-compatible regex, max 254 chars)
- **SQL-pattern heuristic** detects `UNION`, `DROP`, `--`, `;` etc. as defence-in-depth

### 2. Authentication
- **BCrypt** password hashing with work-factor 12 (adaptive, brute-force resistant)
- **Timing-safe** credential verification (BCrypt.Verify)
- **Generic error messages** ("Invalid credentials") prevent user enumeration
- **Account lockout** after 5 consecutive failed attempts
- **JWT tokens** signed with HMAC-SHA256, 60-minute expiry, issuer/audience validation

### 3. Role-Based Access Control (RBAC)
| Role      | Read Own | Read All | Create | Delete Own | Delete Any | Manage Users |
|-----------|----------|----------|--------|------------|------------|--------------|
| Admin     | ✅       | ✅       | ✅     | ✅         | ✅         | ✅           |
| User      | ✅       | ❌       | ✅     | ✅         | ❌         | ❌           |
| ReadOnly  | ✅       | ❌       | ❌     | ❌         | ❌         | ❌           |

- **Ownership enforcement**: Users can only access/delete their own vault entries
- **Token validation** before every service operation
- **Role claims** embedded in JWT and verified on every request

### 4. XSS Prevention
- All user-supplied text is **HTML-encoded** (`HttpUtility.HtmlEncode`) before storage
- Output never rendered as raw HTML in the data layer
- `<script>`, `<img onerror>`, `<svg onload>` payloads are neutralised

---

## 🐛 Vulnerabilities Identified & Fixes Applied

### Vulnerability 1 – SQL Injection
**Original problem:** User input was concatenated directly into SQL query strings:
```csharp
// ❌ VULNERABLE
var sql = $"SELECT * FROM Users WHERE Username = '{username}'";
```
A malicious input like `' OR '1'='1` would bypass authentication entirely.

**Fix applied:** Every query uses parameterised commands:
```csharp
// ✅ SECURE
const string sql = "SELECT * FROM Users WHERE Username = @username LIMIT 1";
cmd.Parameters.AddWithValue("@username", username);
```
No user value ever touches the SQL string itself.

---

### Vulnerability 2 – Plain-Text Passwords
**Original problem:** Passwords stored as plain text in the database. A single data-breach exposes every user account.

**Fix applied:** BCrypt hashing with work-factor 12:
```csharp
// ✅ SECURE
string hash = BCrypt.Net.BCrypt.HashPassword(password, workFactor: 12);
// Verification
bool ok = BCrypt.Net.BCrypt.Verify(inputPassword, storedHash);
```

---

### Vulnerability 3 – Missing Authentication Checks
**Original problem:** Service methods were callable without verifying identity, allowing anonymous access to secrets.

**Fix applied:** Every `VaultService` method validates the JWT token first and enforces RBAC:
```csharp
var (valid, _, role, userId) = _auth.ValidateToken(token);
if (!valid) return (false, "Unauthorized.");
AuthorizationService.RequireRole(role, "Admin", "User");
```

---

### Vulnerability 4 – Stored XSS
**Original problem:** User-supplied vault titles containing `<script>` tags were stored and could be reflected back to the browser unescaped.

**Fix applied:** HTML encoding before storage:
```csharp
string safeTitle = InputValidator.SanitizeForHtml(title); // &lt;script&gt;...
```

---

### Vulnerability 5 – Broken Access Control (IDOR)
**Original problem:** Any authenticated user could delete any vault entry by guessing an ID.

**Fix applied:** Ownership check enforced in the database query and RBAC layer:
```csharp
// Regular users can only delete their own entries
string sql = role == "Admin"
    ? "DELETE FROM VaultEntries WHERE Id = @id"
    : "DELETE FROM VaultEntries WHERE Id = @id AND OwnerId = @ownerId";
```

---

### Vulnerability 6 – Brute-Force Login
**Original problem:** No limit on login attempts; attackers could enumerate passwords freely.

**Fix applied:** Account locks after 5 consecutive failures:
```csharp
UPDATE Users SET FailedLoginAttempts = FailedLoginAttempts + 1,
    IsLocked = CASE WHEN FailedLoginAttempts + 1 >= 5 THEN 1 ELSE 0 END
WHERE Id = @id
```

---

## 🤖 How Microsoft Copilot Assisted

### Activity 1 – Secure Code Generation
Copilot generated the initial skeleton of `InputValidator.cs` and `DatabaseService.cs`. When prompted with *"generate C# input validation that prevents SQL injection and XSS"*, Copilot:
- Suggested parameterised `SqliteCommand` patterns instead of string interpolation
- Proposed the `HttpUtility.HtmlEncode` approach for XSS output encoding
- Recommended the BCrypt work-factor range (10–12) for production use

### Activity 2 – Authentication & Authorization
When prompted with *"implement JWT authentication with RBAC in C#"*, Copilot:
- Scaffolded the `JwtHelper` class with correct `TokenValidationParameters`
- Suggested the claims structure (`NameIdentifier`, `Role`) for role propagation
- Proposed the account-lockout pattern using a failed-attempts counter

### Activity 3 – Debugging Security Vulnerabilities
Copilot was used interactively to identify and fix bugs:
- **Detected** the string-interpolated SQL query and automatically replaced it with a parameterised version
- **Flagged** a missing ownership check in the original `DeleteVaultEntry` method
- **Suggested** that `ValidateToken` return `null` (not throw) on failure, preventing information leakage through exception messages
- **Recommended** `ClockSkew = TimeSpan.Zero` to prevent token-expiry bypass

---

## ✅ Test Coverage

| Test Class                  | Scenarios Covered                                   |
|-----------------------------|-----------------------------------------------------|
| `InputValidatorTests`       | Username, password, email rules; SQLi detection; XSS encoding |
| `AuthServiceTests`          | Register, login, token validation, account lockout  |
| `AuthorizationServiceTests` | All role permissions, ownership enforcement, RBAC throws |
| `SqlInjectionTests`         | 6 SQLi payloads in username, login, vault title     |
| `XssPreventionTests`        | Script tag, img onerror, svg onload payloads        |
| `VaultServiceTests`         | CRUD operations with Admin/User/ReadOnly roles      |

Run with:
```bash
dotnet test --logger "console;verbosity=detailed"
```

---

## 📄 License
MIT – for educational purposes.
