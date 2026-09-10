using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.IdentityModel.Tokens;
using Npgsql;
using StackExchange.Redis;

namespace SecureVaultGateway.Services;

public sealed class DatabaseService(IConfiguration configuration)
{
    private readonly string _connectionString = configuration.GetConnectionString("Postgres") ?? throw new InvalidOperationException("Postgres connection string missing.");
    private readonly IConfiguration _configuration = configuration;
    private NpgsqlConnection Connection() => new(_connectionString);

    public async Task EnsureAdminAsync()
    {
        await using var connection = Connection(); await connection.OpenAsync();
        await using (var migration = new NpgsqlCommand("ALTER TABLE clients ADD COLUMN IF NOT EXISTS name TEXT; UPDATE clients SET name = client_id WHERE name IS NULL; ALTER TABLE clients ALTER COLUMN name SET NOT NULL; ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS duration_ms INTEGER NULL;", connection))
            await migration.ExecuteNonQueryAsync();
        const string sql = "INSERT INTO admin_users (email, password_hash, role) VALUES (@email, @hash, 'admin') ON CONFLICT (email) DO NOTHING";
        await using var command = new NpgsqlCommand(sql, connection);
        command.Parameters.AddWithValue("email", _configuration["Admin:Email"] ?? "admin@securevault.local");
        command.Parameters.AddWithValue("hash", BCrypt.Net.BCrypt.HashPassword(_configuration["Admin:Password"] ?? throw new InvalidOperationException("Admin:Password missing.")));
        await command.ExecuteNonQueryAsync();
    }

    public async Task<bool> ValidateAdminAsync(string email, string password)
    {
        await using var connection = Connection(); await connection.OpenAsync();
        await using var command = new NpgsqlCommand("SELECT password_hash FROM admin_users WHERE email = @email", connection);
        command.Parameters.AddWithValue("email", email);
        var hash = await command.ExecuteScalarAsync() as string;
        return hash is not null && BCrypt.Net.BCrypt.Verify(password, hash);
    }

    public async Task SaveTokenAsync(string token, string encryptedDek, string encryptedPayload, string type)
    {
        await using var connection = Connection(); await connection.OpenAsync();
        await using var command = new NpgsqlCommand("INSERT INTO vault_records (token_id, encrypted_dek, encrypted_payload, format_type) VALUES (@token, @dek, @payload, @type) ON CONFLICT (token_id) DO UPDATE SET encrypted_dek = EXCLUDED.encrypted_dek, encrypted_payload = EXCLUDED.encrypted_payload, format_type = EXCLUDED.format_type", connection);
        command.Parameters.AddWithValue("token", token); command.Parameters.AddWithValue("dek", encryptedDek); command.Parameters.AddWithValue("payload", encryptedPayload); command.Parameters.AddWithValue("type", type);
        await command.ExecuteNonQueryAsync();
    }

    public async Task<TokenRecord?> GetTokenAsync(string token)
    {
        await using var connection = Connection(); await connection.OpenAsync();
        await using var command = new NpgsqlCommand("SELECT encrypted_dek, encrypted_payload, format_type FROM vault_records WHERE token_id = @token", connection);
        command.Parameters.AddWithValue("token", token);
        await using var reader = await command.ExecuteReaderAsync();
        return await reader.ReadAsync() ? new TokenRecord(reader.GetString(0), reader.GetString(1), reader.GetString(2)) : null;
    }

    public async Task AuditAsync(string clientId, string action, string status, string ipAddress, long duration, string? error = null)
    {
        await using var connection = Connection(); await connection.OpenAsync();
        await using var command = new NpgsqlCommand("INSERT INTO audit_logs (client_id, action, status, ip_address, duration_ms, details) VALUES (@client, @action, @status, @ip, @duration, CAST(@details AS jsonb))", connection);
        command.Parameters.AddWithValue("client", clientId); command.Parameters.AddWithValue("action", action); command.Parameters.AddWithValue("status", status); command.Parameters.AddWithValue("ip", ipAddress); command.Parameters.AddWithValue("duration", duration); command.Parameters.AddWithValue("details", JsonSerializer.Serialize(new { error }));
        await command.ExecuteNonQueryAsync();
    }

    public async Task<IReadOnlyList<object>> GetClientsAsync()
    {
        var result = new List<object>(); await using var connection = Connection(); await connection.OpenAsync();
        await using var command = new NpgsqlCommand("SELECT client_id, name, scope, quota_per_minute, created_at, revoked FROM clients ORDER BY created_at DESC", connection); await using var reader = await command.ExecuteReaderAsync();
        while (await reader.ReadAsync()) result.Add(new { id = reader.GetString(0), name = reader.GetString(1), scope = reader.GetString(2), quotaPerMinute = reader.GetInt32(3), createdAt = reader.GetDateTime(4), revoked = reader.GetBoolean(5) });
        return result;
    }

    public async Task<object> GetMetricsAsync(DateTime? from, DateTime? to, string? clientId, string? action)
    {
        var filter = Filter(from, to, clientId, action);
        await using var connection = Connection(); await connection.OpenAsync();
        await using var command = new NpgsqlCommand($"SELECT COUNT(*), COALESCE(AVG(duration_ms)::double precision, 0), COUNT(*) FILTER (WHERE status = 'success') FROM audit_logs {filter.Sql}", connection); AddFilters(command, filter);
        await using var reader = await command.ExecuteReaderAsync(); await reader.ReadAsync();
        var total = reader.GetInt64(0);
        return new { totalTokens = await ScalarLongAsync(connection, "SELECT COUNT(*) FROM vault_records"), requests = total, avgLatencyMs = Math.Round(reader.GetDouble(1), 1), successRate = total == 0 ? 0 : Math.Round(reader.GetInt64(2) * 100d / total, 1) };
    }

    public async Task<object> GetAnalyticsAsync(DateTime? from, DateTime? to, string? clientId, string? action)
    {
        var filter = Filter(from, to, clientId, action); await using var connection = Connection(); await connection.OpenAsync();
        var volume = await QueryAsync(connection, $"SELECT to_char(date_trunc('hour', timestamp), 'YYYY-MM-DD\"T\"HH24:00:00\"Z\"'), COUNT(*) FROM audit_logs {filter.Sql} GROUP BY 1 ORDER BY 1", filter);
        var actions = await QueryAsync(connection, $"SELECT action, COUNT(*) FROM audit_logs {filter.Sql} GROUP BY action ORDER BY 2 DESC", filter);
        var statuses = await QueryAsync(connection, $"SELECT status, COUNT(*) FROM audit_logs {filter.Sql} GROUP BY status ORDER BY 2 DESC", filter);
        return new { volume, actions, statuses };
    }

    public async Task<IReadOnlyList<object>> GetAuditAsync(DateTime? from, DateTime? to, string? clientId, string? action)
    {
        var filter = Filter(from, to, clientId, action); var result = new List<object>(); await using var connection = Connection(); await connection.OpenAsync();
        await using var command = new NpgsqlCommand($"SELECT client_id, action, status, timestamp, duration_ms FROM audit_logs {filter.Sql} ORDER BY timestamp DESC LIMIT 100", connection); AddFilters(command, filter); await using var reader = await command.ExecuteReaderAsync();
        while (await reader.ReadAsync()) result.Add(new { clientId = reader.GetString(0), action = reader.GetString(1), status = reader.GetString(2), timestamp = reader.GetDateTime(3), durationMs = reader.IsDBNull(4) ? 0 : reader.GetInt32(4) }); return result;
    }

    public async Task<Client?> FindClientAsync(string hash, string requiredScope)
    {
        await using var connection = Connection(); await connection.OpenAsync(); await using var command = new NpgsqlCommand("SELECT client_id, scope, quota_per_minute FROM clients WHERE api_key_hash = @hash AND revoked = FALSE AND (expires_at IS NULL OR expires_at > NOW())", connection); command.Parameters.AddWithValue("hash", hash); await using var reader = await command.ExecuteReaderAsync();
        if (!await reader.ReadAsync()) return null; var scope = reader.GetString(1); return scope.Split(',', StringSplitOptions.TrimEntries).Contains(requiredScope, StringComparer.OrdinalIgnoreCase) ? new Client(reader.GetString(0), scope, reader.GetInt32(2)) : null;
    }

    public async Task CreateClientAsync(string id, string name, string hash, string scope, int quota) { await using var connection = Connection(); await connection.OpenAsync(); await using var command = new NpgsqlCommand("INSERT INTO clients (client_id, name, api_key_hash, scope, quota_per_minute, permissions) VALUES (@id, @name, @hash, @scope, @quota, @scope)", connection); command.Parameters.AddWithValue("id", id); command.Parameters.AddWithValue("name", name); command.Parameters.AddWithValue("hash", hash); command.Parameters.AddWithValue("scope", scope); command.Parameters.AddWithValue("quota", quota); await command.ExecuteNonQueryAsync(); }
    private async Task<long> ScalarLongAsync(NpgsqlConnection connection, string sql) { await using var command = new NpgsqlCommand(sql, connection); return (long)(await command.ExecuteScalarAsync() ?? 0L); }
    private async Task<List<object>> QueryAsync(NpgsqlConnection connection, string sql, QueryFilter filter) { var result = new List<object>(); await using var command = new NpgsqlCommand(sql, connection); AddFilters(command, filter); await using var reader = await command.ExecuteReaderAsync(); while (await reader.ReadAsync()) result.Add(new { label = reader.GetString(0), value = reader.GetInt64(1) }); return result; }
    private static QueryFilter Filter(DateTime? from, DateTime? to, string? client, string? action) { var parts = new List<string>(); if (from.HasValue) parts.Add("timestamp >= @from"); if (to.HasValue) parts.Add("timestamp <= @to"); if (!string.IsNullOrWhiteSpace(client)) parts.Add("client_id = @client"); if (!string.IsNullOrWhiteSpace(action)) parts.Add("action = @action"); return new QueryFilter(parts.Count == 0 ? "" : "WHERE " + string.Join(" AND ", parts), from, to, client, action); }
    private static void AddFilters(NpgsqlCommand command, QueryFilter filter) { if (filter.From.HasValue) command.Parameters.AddWithValue("from", filter.From.Value); if (filter.To.HasValue) command.Parameters.AddWithValue("to", filter.To.Value); if (filter.Client is not null) command.Parameters.AddWithValue("client", filter.Client); if (filter.Action is not null) command.Parameters.AddWithValue("action", filter.Action); }
    private record QueryFilter(string Sql, DateTime? From, DateTime? To, string? Client, string? Action);
}

public sealed class ApiKeyService(DatabaseService database)
{
    public async Task<Client?> ValidateAsync(string? key, string scope) => string.IsNullOrWhiteSpace(key) ? null : await database.FindClientAsync(Hash(key), scope);
    public async Task<CreatedApiKey> CreateAsync(string name, string scope, int quota) { var id = $"client_{Guid.NewGuid():N}"; var key = $"svt_{Convert.ToHexString(RandomNumberGenerator.GetBytes(24)).ToLowerInvariant()}"; await database.CreateClientAsync(id, name, Hash(key), scope, quota); return new CreatedApiKey(id, name, scope, quota, key); }
    private static string Hash(string value) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value))).ToLowerInvariant();
}

public sealed class RateLimitService(IConnectionMultiplexer redis)
{
    public async Task<bool> AllowAsync(Client client)
    {
        var key = $"rate-limit:{client.ClientId}:{DateTime.UtcNow:yyyyMMddHHmm}";
        var database = redis.GetDatabase();
        var count = await database.StringIncrementAsync(key);
        if (count == 1) await database.KeyExpireAsync(key, TimeSpan.FromMinutes(2));
        return count <= client.QuotaPerMinute;
    }
}

public sealed class VaultTransitService(IHttpClientFactory factory, IConfiguration configuration)
{
    private readonly string _url = configuration["Vault:Url"] ?? throw new InvalidOperationException("Vault URL missing."); private readonly string _token = configuration["Vault:Token"] ?? throw new InvalidOperationException("Vault token missing."); private readonly string _key = configuration["Vault:KeyName"] ?? "tokenizer";
    public async Task<DataKey> CreateDataKeyAsync() { var client = factory.CreateClient(); client.DefaultRequestHeaders.Add("X-Vault-Token", _token); var response = await client.PostAsync($"{_url.TrimEnd('/')}/v1/transit/datakey/plaintext/{_key}", null); response.EnsureSuccessStatusCode(); using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync()); var data = json.RootElement.GetProperty("data"); return new DataKey(data.GetProperty("plaintext").GetString()!, data.GetProperty("ciphertext").GetString()!); }
    public async Task<string> DecryptDataKeyAsync(string ciphertext) => await SendAsync("decrypt", ciphertext, "plaintext");
    private async Task<string> SendAsync(string action, string value, string field) { var client = factory.CreateClient(); client.DefaultRequestHeaders.Add("X-Vault-Token", _token); var response = await client.PostAsJsonAsync($"{_url.TrimEnd('/')}/v1/transit/{action}/{_key}", new Dictionary<string, string> { [action == "encrypt" ? "plaintext" : "ciphertext"] = value }); response.EnsureSuccessStatusCode(); using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync()); return json.RootElement.GetProperty("data").GetProperty(field).GetString() ?? throw new InvalidOperationException("Vault returned an empty value."); }
}

public sealed class TokenizerService(IHttpClientFactory factory, IConfiguration configuration)
{
    private readonly string _url = configuration["Tokenizer:BaseUrl"] ?? throw new InvalidOperationException("Tokenizer URL missing.");
    public async Task<string> TokenizeAsync(string type, string value) => await ReadAsync("/tokenize", new { type, value }, "token");
    public Task<string> EncryptAsync(string value, string dek, string type) => ReadAsync("/encrypt", new { value, dek, format_type = type }, "payload");
    public Task<string> DecryptAsync(string payload, string dek, string type) => ReadAsync("/decrypt", new { payload, dek, format_type = type }, "value");
    private async Task<string> ReadAsync(string path, object body, string field) { var response = await factory.CreateClient().PostAsJsonAsync($"{_url.TrimEnd('/')}{path}", body); if (!response.IsSuccessStatusCode) throw new ArgumentException("Tokenizer rejected the request."); using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync()); return json.RootElement.GetProperty(field).GetString() ?? throw new InvalidOperationException("Tokenizer returned an empty value."); }
}

public sealed class JwtTokenService(IConfiguration configuration)
{
    public int ExpiresMinutes => int.TryParse(configuration["Jwt:ExpiresMinutes"], out var minutes) ? minutes : 60;
    public string Create(string email) { var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration["Jwt:Key"]!)); var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256); return new JwtSecurityTokenHandler().WriteToken(new JwtSecurityToken(configuration["Jwt:Issuer"], configuration["Jwt:Audience"], [new Claim(ClaimTypes.Name, email), new Claim(ClaimTypes.Role, "admin")], expires: DateTime.UtcNow.AddMinutes(ExpiresMinutes), signingCredentials: credentials)); }
}

public record TokenRecord(string EncryptedDek, string EncryptedPayload, string FormatType);
public record DataKey(string Plaintext, string Ciphertext);
public record Client(string ClientId, string Scope, int QuotaPerMinute);
public record CreatedApiKey(string ClientId, string Name, string Scope, int QuotaPerMinute, string ApiKey);
