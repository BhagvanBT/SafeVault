using Microsoft.EntityFrameworkCore;

public class SafeVaultContext : DbContext
{
    public SafeVaultContext(DbContextOptions<SafeVaultContext> options) : base(options) { }
    public DbSet<User> Users { get; set; }
    public DbSet<UserSubmission> UserSubmissions { get; set; }
}

public class User
{
    public int UserID { get; set; }
    public string Username { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
}

public class UserSubmission
{
    public int Id { get; set; }
    public string Username { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
}
