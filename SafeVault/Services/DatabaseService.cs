using Microsoft.Data.Sqlite;
using SafeVault.Models;

namespace SafeVault.Services;

/// <summary>
/// Data-access layer for SafeVault.
/// ALL queries use parameterised commands – the primary defence against SQL injection.
/// No user-supplied value is ever interpolated into a query string.
/// </summary>
public class DatabaseService : IDisposable
{
    private readonly SqliteConnection _connection;

    public DatabaseService(string dbPath = "safevault.db")
    {
        _connection = new SqliteConnection($"Data Source={dbPath}");
        _connection.Open();
        InitializeDatabase();
    }

    // ── Schema ────────────────────────────────────────────────────────────────
    private void InitializeDatabase()
    {
        ExecuteNonQuery(@"
            CREATE TABLE IF NOT EXISTS Users (
                Id                   INTEGER PRIMARY KEY AUTOINCREMENT,
                Username             TEXT    NOT NULL UNIQUE,
                PasswordHash         TEXT    NOT NULL,
                Email                TEXT    NOT NULL UNIQUE,
                Role                 TEXT    NOT NULL DEFAULT 'User',
                CreatedAt            TEXT    NOT NULL,
                IsLocked             INTEGER NOT NULL DEFAULT 0,
                FailedLoginAttempts  INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS VaultEntries (
                Id          INTEGER PRIMARY KEY AUTOINCREMENT,
                OwnerId     INTEGER NOT NULL,
                Title       TEXT    NOT NULL,
                SecretValue TEXT    NOT NULL,
                CreatedAt   TEXT    NOT NULL,
                FOREIGN KEY (OwnerId) REFERENCES Users(Id)
            );");
    }

    // ── User operations ───────────────────────────────────────────────────────

    /// <summary>
    /// Inserts a new user. The password is expected to be a BCrypt hash –
    /// never store or accept a plain-text password here.
    /// </summary>
    public bool CreateUser(User user)
    {
        const string sql = @"
            INSERT INTO Users (Username, PasswordHash, Email, Role, CreatedAt, IsLocked, FailedLoginAttempts)
            VALUES (@username, @passwordHash, @email, @role, @createdAt, 0, 0)";

        using var cmd = CreateCommand(sql);
        cmd.Parameters.AddWithValue("@username",     user.Username);
        cmd.Parameters.AddWithValue("@passwordHash", user.PasswordHash);
        cmd.Parameters.AddWithValue("@email",        user.Email);
        cmd.Parameters.AddWithValue("@role",         user.Role);
        cmd.Parameters.AddWithValue("@createdAt",    user.CreatedAt.ToString("O"));

        try   { cmd.ExecuteNonQuery(); return true; }
        catch { return false; }
    }

    /// <summary>Retrieves a user by username using a parameterised query.</summary>
    public User? GetUserByUsername(string username)
    {
        const string sql = "SELECT * FROM Users WHERE Username = @username LIMIT 1";
        using var cmd = CreateCommand(sql);
        cmd.Parameters.AddWithValue("@username", username);

        using var reader = cmd.ExecuteReader();
        return reader.Read() ? MapUser(reader) : null;
    }

    /// <summary>Retrieves a user by id using a parameterised query.</summary>
    public User? GetUserById(int id)
    {
        const string sql = "SELECT * FROM Users WHERE Id = @id LIMIT 1";
        using var cmd = CreateCommand(sql);
        cmd.Parameters.AddWithValue("@id", id);

        using var reader = cmd.ExecuteReader();
        return reader.Read() ? MapUser(reader) : null;
    }

    /// <summary>Increments failed-login counter and locks the account after 5 attempts.</summary>
    public void RecordFailedLogin(int userId)
    {
        const string sql = @"
            UPDATE Users
            SET FailedLoginAttempts = FailedLoginAttempts + 1,
                IsLocked = CASE WHEN FailedLoginAttempts + 1 >= 5 THEN 1 ELSE 0 END
            WHERE Id = @id";

        using var cmd = CreateCommand(sql);
        cmd.Parameters.AddWithValue("@id", userId);
        cmd.ExecuteNonQuery();
    }

    /// <summary>Resets the failed-login counter on a successful login.</summary>
    public void ResetFailedLogin(int userId)
    {
        const string sql =
            "UPDATE Users SET FailedLoginAttempts = 0, IsLocked = 0 WHERE Id = @id";

        using var cmd = CreateCommand(sql);
        cmd.Parameters.AddWithValue("@id", userId);
        cmd.ExecuteNonQuery();
    }

    // ── Vault-entry operations ─────────────────────────────────────────────────

    public bool CreateVaultEntry(VaultEntry entry)
    {
        const string sql = @"
            INSERT INTO VaultEntries (OwnerId, Title, SecretValue, CreatedAt)
            VALUES (@ownerId, @title, @secretValue, @createdAt)";

        using var cmd = CreateCommand(sql);
        cmd.Parameters.AddWithValue("@ownerId",     entry.OwnerId);
        cmd.Parameters.AddWithValue("@title",       entry.Title);
        cmd.Parameters.AddWithValue("@secretValue", entry.SecretValue);
        cmd.Parameters.AddWithValue("@createdAt",   entry.CreatedAt.ToString("O"));

        try   { cmd.ExecuteNonQuery(); return true; }
        catch { return false; }
    }

    /// <summary>
    /// Returns vault entries that belong to the requesting user ONLY.
    /// Admins may pass ownerId = null to retrieve all entries.
    /// </summary>
    public List<VaultEntry> GetVaultEntries(int? ownerId = null)
    {
        string sql = ownerId.HasValue
            ? "SELECT * FROM VaultEntries WHERE OwnerId = @ownerId ORDER BY CreatedAt DESC"
            : "SELECT * FROM VaultEntries ORDER BY CreatedAt DESC";

        using var cmd = CreateCommand(sql);
        if (ownerId.HasValue)
            cmd.Parameters.AddWithValue("@ownerId", ownerId.Value);

        var entries = new List<VaultEntry>();
        using var reader = cmd.ExecuteReader();
        while (reader.Read()) entries.Add(MapEntry(reader));
        return entries;
    }

    public bool DeleteVaultEntry(int entryId, int requestingUserId, string role)
    {
        // Regular users may only delete their own entries; Admins can delete any.
        string sql = role == "Admin"
            ? "DELETE FROM VaultEntries WHERE Id = @id"
            : "DELETE FROM VaultEntries WHERE Id = @id AND OwnerId = @ownerId";

        using var cmd = CreateCommand(sql);
        cmd.Parameters.AddWithValue("@id", entryId);
        if (role != "Admin")
            cmd.Parameters.AddWithValue("@ownerId", requestingUserId);

        return cmd.ExecuteNonQuery() > 0;
    }

    // ── Helpers ───────────────────────────────────────────────────────────────
    private SqliteCommand CreateCommand(string sql)
    {
        var cmd = _connection.CreateCommand();
        cmd.CommandText = sql;
        return cmd;
    }

    private void ExecuteNonQuery(string sql)
    {
        using var cmd = CreateCommand(sql);
        cmd.ExecuteNonQuery();
    }

    private static User MapUser(SqliteDataReader r) => new()
    {
        Id                  = r.GetInt32(r.GetOrdinal("Id")),
        Username            = r.GetString(r.GetOrdinal("Username")),
        PasswordHash        = r.GetString(r.GetOrdinal("PasswordHash")),
        Email               = r.GetString(r.GetOrdinal("Email")),
        Role                = r.GetString(r.GetOrdinal("Role")),
        CreatedAt           = DateTime.Parse(r.GetString(r.GetOrdinal("CreatedAt"))),
        IsLocked            = r.GetInt32(r.GetOrdinal("IsLocked")) == 1,
        FailedLoginAttempts = r.GetInt32(r.GetOrdinal("FailedLoginAttempts")),
    };

    private static VaultEntry MapEntry(SqliteDataReader r) => new()
    {
        Id          = r.GetInt32(r.GetOrdinal("Id")),
        OwnerId     = r.GetInt32(r.GetOrdinal("OwnerId")),
        Title       = r.GetString(r.GetOrdinal("Title")),
        SecretValue = r.GetString(r.GetOrdinal("SecretValue")),
        CreatedAt   = DateTime.Parse(r.GetString(r.GetOrdinal("CreatedAt"))),
    };

    public void Dispose() => _connection.Dispose();
}
