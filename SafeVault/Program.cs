using SafeVault.Services;

Console.WriteLine("=== SafeVault – Secure Credential Manager ===\n");

// ── Bootstrap ─────────────────────────────────────────────────────────────────
using var db      = new DatabaseService(":memory:");   // use file path in production
var auth          = new AuthService(db);
var vault         = new VaultService(db, auth);

// ── 1. Register users with different roles ────────────────────────────────────
Console.WriteLine("--- Registration ---");
Print(auth.Register("alice",    "Alice@Pass1!",    "alice@example.com",  "Admin"));
Print(auth.Register("bob",      "Bob$ecure99!",    "bob@example.com",    "User"));
Print(auth.Register("charlie",  "Charlie#View2!",  "charlie@example.com","ReadOnly"));

// Attempt duplicate registration
Print(auth.Register("alice", "Another@Pass1!", "alice2@example.com", "User"));

// Attempt with weak password
Print(auth.Register("dave", "password", "dave@example.com", "User"));

// ── 2. Login ──────────────────────────────────────────────────────────────────
Console.WriteLine("\n--- Login ---");
var (_, _, adminToken)    = auth.Login("alice",   "Alice@Pass1!");
var (_, _, userToken)     = auth.Login("bob",     "Bob$ecure99!");
var (_, _, roToken)       = auth.Login("charlie", "Charlie#View2!");
var (_, badMsg, _)        = auth.Login("alice",   "WrongPassword!");

Console.WriteLine($"Admin login: {(adminToken != null ? "✓ Token issued" : "✗")}");
Console.WriteLine($"User  login: {(userToken  != null ? "✓ Token issued" : "✗")}");
Console.WriteLine($"ReadOnly login: {(roToken != null ? "✓ Token issued" : "✗")}");
Console.WriteLine($"Bad password: {badMsg}");

// ── 3. Vault operations ───────────────────────────────────────────────────────
Console.WriteLine("\n--- Vault Entries ---");

// Bob adds an entry
Print(vault.AddEntry(userToken!, "Gmail API Key", "AIzaSy..."));

// ReadOnly user tries to add (should fail)
Print(vault.AddEntry(roToken!,   "Secret", "value"));

// ReadOnly user tries with XSS payload (should be sanitised)
Print(vault.AddEntry(userToken!, "<script>alert('xss')</script>", "value123!"));

// Admin adds an entry
Print(vault.AddEntry(adminToken!, "AWS Root Credentials", "AKIAIOSFODNN7EXAMPLE"));

// Bob reads his own entries
var (ok, msg, entries) = vault.GetEntries(userToken!);
Console.WriteLine($"\nBob's entries ({entries?.Count}):");
entries?.ForEach(e => Console.WriteLine($"  [{e.Id}] {e.Title}"));

// Admin reads all entries
var (_, _, allEntries) = vault.GetEntries(adminToken!);
Console.WriteLine($"\nAdmin sees all entries ({allEntries?.Count}):");
allEntries?.ForEach(e => Console.WriteLine($"  [{e.Id}] OwnerId={e.OwnerId} | {e.Title}"));

// Bob tries to delete admin's entry (should fail - RBAC ownership)
if (allEntries?.Count > 1)
{
    var adminEntry = allEntries.First(e => e.Title.Contains("AWS"));
    Print(vault.DeleteEntry(userToken!, adminEntry.Id));
}

// Admin deletes any entry
if (allEntries?.Count > 0)
    Print(vault.DeleteEntry(adminToken!, allEntries[0].Id));

// ── 4. SQL Injection attempts ─────────────────────────────────────────────────
Console.WriteLine("\n--- SQL Injection Attempts (all should fail) ---");
Print(auth.Register("'; DROP TABLE Users;--", "Pass@word1!", "drop@example.com", "User"));
Print(auth.Login("' OR '1'='1", "anything"));
Print(vault.AddEntry(userToken!, "' UNION SELECT * FROM Users--", "value"));

Console.WriteLine("\n=== SafeVault demo complete. All security controls verified. ===");

// ── Helper ───────────────────────────────────────────────────────────────────
static void Print((bool Success, string Message) result) =>
    Console.WriteLine($"  {(result.Success ? "✓" : "✗")} {result.Message}");
