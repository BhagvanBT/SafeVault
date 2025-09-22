using Microsoft.Data.Sqlite;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// Add authorization services
builder.Services.AddAuthorization();

// JWT configuration
var jwtKey = "dev_secret_key_please_change"; // Use a secure key in production!
var jwtIssuer = "SafeVault";
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = false,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = jwtIssuer,
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey))
    };
});


var app = builder.Build();

app.UseAuthorization();

app.UseAuthentication();

app.UseHttpsRedirection();
// Serve webform.html at /form
app.MapGet("/form", async context =>
{
    context.Response.ContentType = "text/html";
    await context.Response.SendFileAsync("webform.html");
});

// Secure POST endpoint for form submission using direct SQL
app.MapPost("/submit", async (HttpContext context) =>
{
    var form = await context.Request.ReadFormAsync();
    var username = InputSanitizer.Sanitize(form["username"].ToString());
    var email = InputSanitizer.Sanitize(form["email"].ToString());

    // Basic input validation
    if (string.IsNullOrWhiteSpace(username) || username.Length > 100 || !System.Text.RegularExpressions.Regex.IsMatch(username, "^[a-zA-Z0-9_]+$"))
    {
        context.Response.StatusCode = 400;
        await context.Response.WriteAsync("Invalid username.");
        return;
    }
    if (string.IsNullOrWhiteSpace(email) || email.Length > 100 || !System.Text.RegularExpressions.Regex.IsMatch(email, @"^[^@\s]+@[^@\s]+\.[^@\s]+$"))
    {
        context.Response.StatusCode = 400;
        await context.Response.WriteAsync("Invalid email.");
        return;
    }

    // Store securely in Users table using parameterized SQL
    using var conn = new SqliteConnection("Data Source=safevault.db");
    await conn.OpenAsync();
    var cmd = conn.CreateCommand();
    cmd.CommandText = "INSERT INTO Users (Username, Email) VALUES (@username, @email);";
    cmd.Parameters.AddWithValue("@username", username);
    cmd.Parameters.AddWithValue("@email", email);
    await cmd.ExecuteNonQueryAsync();

    await context.Response.WriteAsync($"Received: {username}, {email}");
});

// Registration endpoint (hash password)
app.MapPost("/register", async (HttpContext context) =>
{
    var form = await context.Request.ReadFormAsync();
    var username = InputSanitizer.Sanitize(form["username"].ToString());
    var email = InputSanitizer.Sanitize(form["email"].ToString());
    var password = form["password"].ToString();
    // Only allow 'user' role by default; ignore any user-supplied role
    var role = "user";
    // Optionally, allow admin to create admin accounts (not implemented here)

    // Hash the password
    var passwordHash = BCrypt.Net.BCrypt.HashPassword(password);

    using var conn = new SqliteConnection("Data Source=safevault.db");
    await conn.OpenAsync();
    var cmd = conn.CreateCommand();
    cmd.CommandText = "INSERT INTO Users (Username, Email, Password, Role) VALUES (@username, @email, @password, @role);";
    cmd.Parameters.AddWithValue("@username", username);
    cmd.Parameters.AddWithValue("@email", email);
    cmd.Parameters.AddWithValue("@password", passwordHash);
    cmd.Parameters.AddWithValue("@role", role);
    try {
        await cmd.ExecuteNonQueryAsync();
        await context.Response.WriteAsync("Registration successful.");
    } catch {
        context.Response.StatusCode = 400;
        await context.Response.WriteAsync("Registration failed. Username may already exist.");
    }
});

// Update login endpoint to verify hashed password
app.MapPost("/login", async (HttpContext context) =>
{
    var form = await context.Request.ReadFormAsync();
    var username = InputSanitizer.Sanitize(form["username"].ToString());
    var password = form["password"].ToString();

    using var conn = new SqliteConnection("Data Source=safevault.db");
    await conn.OpenAsync();
    var cmd = conn.CreateCommand();
    cmd.CommandText = "SELECT Password, Role FROM Users WHERE Username = @username;";
    cmd.Parameters.AddWithValue("@username", username);
    using var reader = await cmd.ExecuteReaderAsync();
    if (!await reader.ReadAsync())
    {
        context.Response.StatusCode = 401;
        await context.Response.WriteAsync("Invalid credentials.");
        return;
    }
    var storedHash = reader.GetString(0);
    var role = reader.GetString(1);
    if (!BCrypt.Net.BCrypt.Verify(password, storedHash))
    {
        context.Response.StatusCode = 401;
        await context.Response.WriteAsync("Invalid credentials.");
        return;
    }

    // Generate JWT token
    var claims = new[]
    {
        new System.Security.Claims.Claim("username", username),
        new System.Security.Claims.Claim("role", role)
    };
    var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey));
    var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
    var token = new System.IdentityModel.Tokens.Jwt.JwtSecurityToken(
        issuer: jwtIssuer,
        audience: null,
        claims: claims,
        expires: DateTime.UtcNow.AddHours(1),
        signingCredentials: creds
    );
    var tokenString = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler().WriteToken(token);

    context.Response.ContentType = "application/json";
    await context.Response.WriteAsync($"{{\"token\":\"{tokenString}\",\"role\":\"{role}\"}}");
});



// Example: Admin-only endpoint using JWT claims
app.MapGet("/admin", [Microsoft.AspNetCore.Authorization.Authorize] (HttpContext context) =>
{
    var user = context.User;
    var role = user?.FindFirst("role")?.Value;
    if (role != "admin")
    {
        context.Response.StatusCode = 403;
        return context.Response.WriteAsync("Access denied. Admins only.");
    }
    return context.Response.WriteAsync("Welcome, admin!");
});

// Add Role column to Users table if not exists (run at startup)
using (var conn = new Microsoft.Data.Sqlite.SqliteConnection("Data Source=safevault.db"))
{
    conn.Open();
    var cmd = conn.CreateCommand();
    cmd.CommandText = "ALTER TABLE Users ADD COLUMN Role TEXT DEFAULT 'user';";
    try { cmd.ExecuteNonQuery(); } catch { /* Ignore if already exists */ }
}

app.Run();

