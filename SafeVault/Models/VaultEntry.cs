namespace SafeVault.Models;

public class VaultEntry
{
    public int Id { get; set; }
    public int OwnerId { get; set; }
    public string Title { get; set; } = string.Empty;
    public string SecretValue { get; set; } = string.Empty;
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
}
