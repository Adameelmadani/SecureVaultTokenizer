using System.Diagnostics;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SecureVaultGateway.Services;

namespace SecureVaultGateway.Controllers;

[ApiController]
[Route("api/v1")]
public class VaultController : ControllerBase
{
    private readonly DatabaseService _database;
    private readonly ApiKeyService _apiKeys;
    private readonly VaultTransitService _vault;
    private readonly TokenizerService _tokenizer;
    private readonly RateLimitService _rateLimiter;

    public VaultController(DatabaseService database, ApiKeyService apiKeys, VaultTransitService vault, TokenizerService tokenizer, RateLimitService rateLimiter)
    {
        _database = database;
        _apiKeys = apiKeys;
        _vault = vault;
        _tokenizer = tokenizer;
        _rateLimiter = rateLimiter;
    }

    [AllowAnonymous]
    [HttpPost("auth/login")]
    public async Task<ActionResult<LoginResponse>> Login(LoginRequest request, [FromServices] JwtTokenService jwt)
    {
        if (!await _database.ValidateAdminAsync(request.Email, request.Password))
            return Unauthorized(new { error = "Invalid credentials" });

        return Ok(new LoginResponse(jwt.Create(request.Email), DateTime.UtcNow.AddMinutes(jwt.ExpiresMinutes)));
    }

    [Authorize]
    [HttpGet("metrics")]
    public async Task<IActionResult> Metrics([FromQuery] DateTime? from, [FromQuery] DateTime? to, [FromQuery] string? clientId, [FromQuery] string? action)
        => Ok(await _database.GetMetricsAsync(from, to, clientId, action));

    [Authorize]
    [HttpGet("analytics")]
    public async Task<IActionResult> Analytics([FromQuery] DateTime? from, [FromQuery] DateTime? to, [FromQuery] string? clientId, [FromQuery] string? action)
        => Ok(await _database.GetAnalyticsAsync(from, to, clientId, action));

    [Authorize]
    [HttpGet("keys")]
    public async Task<IActionResult> GetApiKeys() => Ok(await _database.GetClientsAsync());

    [Authorize]
    [HttpPost("keys")]
    public async Task<IActionResult> CreateApiKey(CreateKeyRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.Name) || request.QuotaPerMinute < 1)
            return BadRequest(new { error = "Name and a positive quota are required." });

        var created = await _apiKeys.CreateAsync(request.Name, request.Scope, request.QuotaPerMinute);
        return Created($"api/v1/keys/{created.ClientId}", created);
    }

    [Authorize]
    [HttpGet("audit")]
    public async Task<IActionResult> Audit([FromQuery] DateTime? from, [FromQuery] DateTime? to, [FromQuery] string? clientId, [FromQuery] string? action)
        => Ok(await _database.GetAuditAsync(from, to, clientId, action));

    [HttpPost("tokenize")]
    public async Task<IActionResult> Tokenize(TokenizeRequest request)
    {
        var client = await _apiKeys.ValidateAsync(Request.Headers["X-API-Key"], "TOKENIZE");
        if (client is null) return Unauthorized(new { error = "A valid X-API-Key with TOKENIZE scope is required." });
        if (!await _rateLimiter.AllowAsync(client)) return StatusCode(StatusCodes.Status429TooManyRequests, new { error = "API key quota exceeded. Try again next minute." });

        var watch = Stopwatch.StartNew();
        try
        {
            var token = await _tokenizer.TokenizeAsync(request.Type, request.Value);
            var dataKey = await _vault.CreateDataKeyAsync();
            var encrypted = await _tokenizer.EncryptAsync(request.Value, dataKey.Plaintext, request.Type);
            await _database.SaveTokenAsync(token, dataKey.Ciphertext, encrypted, request.Type);
            await _database.AuditAsync(client.ClientId, "TOKENIZE", "success", HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown", watch.ElapsedMilliseconds);
            return Ok(new { token, formatType = request.Type, status = "success" });
        }
        catch (Exception exception) when (exception is HttpRequestException or InvalidOperationException or ArgumentException)
        {
            await _database.AuditAsync(client.ClientId, "TOKENIZE", "failed", HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown", watch.ElapsedMilliseconds, exception.Message);
            return BadRequest(new { error = exception.Message });
        }
    }

    [HttpPost("detokenize")]
    public async Task<IActionResult> Detokenize(DetokenizeRequest request)
    {
        var client = await _apiKeys.ValidateAsync(Request.Headers["X-API-Key"], "DETOKENIZE");
        if (client is null) return Unauthorized(new { error = "A valid X-API-Key with DETOKENIZE scope is required." });
        if (!await _rateLimiter.AllowAsync(client)) return StatusCode(StatusCodes.Status429TooManyRequests, new { error = "API key quota exceeded. Try again next minute." });

        var watch = Stopwatch.StartNew();
        var record = await _database.GetTokenAsync(request.Token);
        if (record is null)
        {
            await _database.AuditAsync(client.ClientId, "DETOKENIZE", "not_found", HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown", watch.ElapsedMilliseconds);
            return NotFound(new { error = "Token not found." });
        }

        var dataKey = await _vault.DecryptDataKeyAsync(record.EncryptedDek);
        var value = await _tokenizer.DecryptAsync(record.EncryptedPayload, dataKey, record.FormatType);
        await _database.AuditAsync(client.ClientId, "DETOKENIZE", "success", HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown", watch.ElapsedMilliseconds);
        return Ok(new { token = request.Token, value, formatType = record.FormatType, status = "success" });
    }
}

public record LoginRequest(string Email, string Password);
public record LoginResponse(string AccessToken, DateTime ExpiresAt);
public record TokenizeRequest(string Type, string Value);
public record DetokenizeRequest(string Token);
public record CreateKeyRequest(string Name, string Scope = "TOKENIZE,DETOKENIZE", int QuotaPerMinute = 60);
