using System.Reflection;

using AcmeManager.Api.Contracts;
using AcmeManager.Core.Discovery;
using AcmeManager.Core.Engine;
using AcmeManager.Core.Logging;
using AcmeManager.Core.Plugins;
using AcmeManager.Core.Security;
using AcmeManager.Core.Storage;
using AcmeManager.Core.Storage.Entities;
using AcmeManager.Plugins.Contracts;
using AcmeManager.Service.Authentication;

using Microsoft.EntityFrameworkCore;

namespace AcmeManager.Service.Api.V1;

/// <summary>
/// The agent's remote management API consumed by the Unified Certificate
/// Manager console. Returns wire DTOs (never EF entities), is authorized by the
/// <see cref="ManagementApiAuth.Policy"/> (Negotiate or Basic + AllowedGroup),
/// and is backed by the same services the local Blazor UI uses. All ordering and
/// filtering over <see cref="DateTimeOffset"/> columns is done in memory because
/// the SQLite EF provider can't translate it.
/// </summary>
public static class ManagementApi
{
    public static void MapManagementApiV1(this WebApplication app)
    {
        var group = app.MapGroup(ApiV1.Base)
            .RequireAuthorization(ManagementApiAuth.Policy)
            .RequireRateLimiting(RateLimitPolicies.ManagementApi)
            .AddEndpointFilter<ManagementApiAuditFilter>();

        group.MapGet("/agent", GetAgentAsync);
        group.MapGet("/certificates", GetCertificatesAsync);
        group.MapGet("/accounts", GetAccountsAsync);
        group.MapGet("/secrets", GetSecretsAsync);
        group.MapGet("/plugins", GetPluginsAsync);
        group.MapGet("/iis-sites", GetIisSitesAsync);
        group.MapGet("/cert-stores", GetCertStoresAsync);
        group.MapGet("/renewals/{id:guid}", GetRenewalAsync);
        group.MapGet("/renewals/{id:guid}/config", GetRenewalConfigAsync);
        group.MapPost("/renewals/{id:guid}/renew", RenewNowAsync);
        group.MapPost("/renewals/{id:guid}/enable",
            (Guid id, IDbContextFactory<AcmeManagerDbContext> dbf, CancellationToken ct) =>
                SetEnabledAsync(id, enabled: true, dbf, ct));
        group.MapPost("/renewals/{id:guid}/disable",
            (Guid id, IDbContextFactory<AcmeManagerDbContext> dbf, CancellationToken ct) =>
                SetEnabledAsync(id, enabled: false, dbf, ct));
        group.MapPut("/renewals/{id:guid}", UpdateRenewalAsync);
        group.MapDelete("/renewals/{id:guid}", DeleteRenewalAsync);
        group.MapPost("/renewals", CreateRenewalAsync);
        group.MapGet("/history", GetHistoryAsync);
        group.MapDelete("/history", ClearHistoryAsync);
        group.MapGet("/logs", GetLogs);
        group.MapDelete("/logs", ClearLogs);
        group.MapGet("/dns-providers", GetDnsProvidersAsync);
        group.MapGet("/coverage", GetCoverageAsync);
        group.MapGet("/adcs-certificates", GetAdcsCertificatesAsync);
    }

    /// <summary>What this host serves and what renews it — the agent's coverage report, for the console's estate view.</summary>
    private static async Task<IResult> GetCoverageAsync(
        AcmeManager.Service.Coverage.CoverageService coverage, CancellationToken ct)
    {
        // Always the host's configured source; a caller-supplied path would be an
        // arbitrary-file read as the service account.
        var report = await coverage.ScanAsync(null, ct);
        return Results.Ok(new CoverageReportDto(
            report.Error,
            report.CertSources,
            report.Entries.Select(e => new CoverageEntryDto(
                e.Path, e.Domains, e.DaysUntilExpiry, e.Status.ToString(), e.Detail, e.Issuer, e.Thumbprint, e.NotAfter)).ToList()));
    }

    private static async Task<IResult> GetAdcsCertificatesAsync(
        AcmeManager.Service.Coverage.AdcsIssuedCertReader adcs, CancellationToken ct)
    {
        try
        {
            return Results.Ok(await adcs.ReadAsync(ct));
        }
        catch (Exception ex) when (ex is InvalidOperationException or TimeoutException)
        {
            return Results.Problem(title: "AD CS read failed", detail: ex.Message, statusCode: StatusCodes.Status502BadGateway);
        }
    }

    private static async Task<IResult> GetDnsProvidersAsync(
        PluginCatalog catalog, IDbContextFactory<AcmeManagerDbContext> dbf, CancellationToken ct)
    {
        await using var db = await dbf.CreateDbContextAsync(ct);
        var list = await db.DnsProviders.AsNoTracking().OrderBy(p => p.Name).ToListAsync(ct);
        return Results.Ok(list
            .Select(p => new DnsProviderDto(p.Id, p.Name, p.PluginId, RedactProviderOptions(catalog, p.PluginId, p.OptionsJson)))
            .ToList());
    }

    /// <summary>Provider profiles store bare options JSON; wrap as a step so the shared redaction applies.</summary>
    private static string RedactProviderOptions(PluginCatalog catalog, string pluginId, string optionsJson)
    {
        var step = SensitiveOptions.Redact(catalog,
            $"{{\"pluginId\":{System.Text.Json.JsonSerializer.Serialize(pluginId)},\"options\":{optionsJson}}}");
        try
        {
            using var doc = System.Text.Json.JsonDocument.Parse(step);
            return doc.RootElement.GetProperty("options").GetRawText();
        }
        catch (Exception ex) when (ex is System.Text.Json.JsonException or KeyNotFoundException)
        {
            return optionsJson;
        }
    }

    private static async Task<IResult> GetHistoryAsync(
        IDbContextFactory<AcmeManagerDbContext> dbf, int? take, CancellationToken ct)
    {
        await using var db = await dbf.CreateDbContextAsync(ct);
        // SQLite can't ORDER BY a DateTimeOffset, so sort + cap in memory.
        var list = await db.History.AsNoTracking().Include(h => h.Renewal).ToListAsync(ct);
        var rows = list
            .OrderByDescending(h => h.At)
            .Take(take is > 0 ? take.Value : 2000)
            .Select(h => new HistoryRowDto(
                h.Id, h.RenewalId, h.Renewal?.Name ?? "—", h.At, h.Status.ToString(), h.DurationMs, h.Message))
            .ToList();
        return Results.Ok(rows);
    }

    private static async Task<IResult> ClearHistoryAsync(
        IDbContextFactory<AcmeManagerDbContext> dbf, string? status, Guid? renewalId, CancellationToken ct)
    {
        HistoryStatus? statusFilter = null;
        if (!string.IsNullOrEmpty(status))
        {
            // An unknown status must NOT fall through to "no filter" — that would
            // turn a typo into deleting the entire audit trail.
            if (!Enum.TryParse<HistoryStatus>(status, ignoreCase: true, out var parsed))
            {
                return Results.BadRequest(new ApiError(ApiError.Invalid, $"Unknown history status '{status}'."));
            }
            statusFilter = parsed;
        }

        await using var db = await dbf.CreateDbContextAsync(ct);
        var query = db.History.AsQueryable();
        if (statusFilter is { } wanted)
        {
            query = query.Where(h => h.Status == wanted);
        }
        if (renewalId is { } rid)
        {
            query = query.Where(h => h.RenewalId == rid);
        }
        var cleared = await query.ExecuteDeleteAsync(ct);
        return Results.Ok(new { cleared });
    }

    private static IResult GetLogs(InMemoryLogStore logs, string? level)
    {
        var rows = logs.Snapshot()
            .Where(e => string.IsNullOrEmpty(level) || e.Level.Equals(level, StringComparison.OrdinalIgnoreCase))
            .Select(e => new LogEntryDto(e.At, e.Level, e.Message, e.Exception))
            .ToList();
        return Results.Ok(rows);
    }

    private static IResult ClearLogs(InMemoryLogStore logs)
    {
        logs.Clear();
        return Results.Ok(new { cleared = true });
    }

    private static async Task<IResult> CreateRenewalAsync(
        CreateRenewalRequest? request,
        PluginCatalog catalog,
        IDbContextFactory<AcmeManagerDbContext> dbf,
        SecretsService secrets,
        CancellationToken ct)
    {
        if (request is null)
        {
            return Results.BadRequest(new ApiError(ApiError.Invalid, "Request body is required."));
        }

        var name = request.Name?.Trim() ?? "";
        if (name.Length == 0)
        {
            return Results.BadRequest(new ApiError(ApiError.Invalid, "Name is required."));
        }

        var windowDays = request.RenewalWindowDays ?? 30;
        if (windowDays is < 1 or > 365)
        {
            return Results.BadRequest(new ApiError(ApiError.Invalid, "RenewalWindowDays must be between 1 and 365."));
        }

        var sourceJson = request.SourceJson ?? "";
        var validationJson = request.ValidationJson ?? "";
        var storesJson = string.IsNullOrWhiteSpace(request.StoresJson) ? "[]" : request.StoresJson;
        var installationsJson = string.IsNullOrWhiteSpace(request.InstallationsJson) ? "[]" : request.InstallationsJson;

        // Write-only credentials typed into the form become encrypted secrets here,
        // before anything is validated or persisted.
        ExtractedSecrets[] inline;
        try
        {
            inline =
            [
                InlineSecrets.Extract(catalog, sourceJson, name),
                InlineSecrets.Extract(catalog, validationJson, name),
                InlineSecrets.Extract(catalog, storesJson, name),
                InlineSecrets.Extract(catalog, installationsJson, name),
            ];
        }
        catch (InlineSecretException ex)
        {
            return Results.BadRequest(new ApiError(ApiError.Invalid, ex.Message));
        }
        (sourceJson, validationJson, storesJson, installationsJson) =
            (inline[0].Json, inline[1].Json, inline[2].Json, inline[3].Json);

        // A new renewal must reference credentials by secret name, never carry them
        // literally — a literal would be stored in plaintext and shipped back redacted.
        var literal = SensitiveOptions.FindLiteral(catalog, storesJson)
            ?? SensitiveOptions.FindLiteral(catalog, installationsJson)
            ?? SensitiveOptions.FindLiteral(catalog, validationJson)
            ?? SensitiveOptions.FindLiteral(catalog, sourceJson);
        if (literal is not null)
        {
            return Results.BadRequest(new ApiError(ApiError.Invalid,
                $"'{literal}' is a credential and cannot be set literally. Store it as a secret on the agent and reference it by name."));
        }

        // A redacted placeholder in a CREATE means the config was copied from
        // another agent (e.g. cross-server migrate); the credential didn't travel.
        var placeholder = SensitiveOptions.FindPlaceholder(catalog, storesJson)
            ?? SensitiveOptions.FindPlaceholder(catalog, installationsJson)
            ?? SensitiveOptions.FindPlaceholder(catalog, validationJson)
            ?? SensitiveOptions.FindPlaceholder(catalog, sourceJson);
        if (placeholder is not null)
        {
            return Results.BadRequest(new ApiError(ApiError.Invalid,
                $"'{placeholder}' is a credential that does not travel between agents. Create a secret for it on this agent and reference it by name."));
        }

        var stepError =
            ValidateSingleStep(catalog, sourceJson, PluginCategory.Source, "SourceJson")
            ?? ValidateSingleStep(catalog, validationJson, PluginCategory.Validation, "ValidationJson")
            ?? ValidateStepList(catalog, storesJson, PluginCategory.Store, "StoresJson")
            ?? ValidateStepList(catalog, installationsJson, PluginCategory.Installation, "InstallationsJson");
        if (stepError is not null)
        {
            return Results.BadRequest(new ApiError(ApiError.Invalid, stepError));
        }

        await using var db = await dbf.CreateDbContextAsync(ct);
        var account = await db.Accounts.AsNoTracking().FirstOrDefaultAsync(a => a.Id == request.AccountId, ct);
        if (account is null)
        {
            return Results.BadRequest(new ApiError(ApiError.Invalid, $"Account {request.AccountId} was not found."));
        }
        if (await db.Renewals.AnyAsync(r => r.Name == name, ct))
        {
            return Results.Conflict(new ApiError(ApiError.Conflict, $"A renewal named '{name}' already exists."));
        }

        string? maintenanceWindowJson;
        try
        {
            maintenanceWindowJson = MaintenanceWindow.Parse(request.MaintenanceWindowJson)?.ToJson();
        }
        catch (FormatException ex)
        {
            return Results.BadRequest(new ApiError(ApiError.Invalid, ex.Message));
        }

        var renewal = new Renewal
        {
            Name = name,
            AccountId = request.AccountId,
            MaintenanceWindowJson = maintenanceWindowJson,
            SourceJson = sourceJson,
            ValidationJson = validationJson,
            StoresJson = storesJson,
            InstallationsJson = installationsJson,
            RenewalWindowDays = windowDays,
            Enabled = request.Enabled ?? true,
        };
        await CommitInlineSecretsAsync(inline, secrets, ct); // only now that the save is valid
        db.Renewals.Add(renewal);
        await db.SaveChangesAsync(ct);

        renewal.Account = account; // for the response mapping only
        var dto = ManagementMappers.ToRenewalDetail(renewal, latest: null, history: [], DateTimeOffset.UtcNow);
        return Results.Created(ApiV1.Renewal(renewal.Id), dto);
    }

    /// <summary>Null when valid, otherwise a client-safe message. Checks the step
    /// parses, the plugin exists, it's the right category for the slot, and its
    /// options deserialize into the plugin's options type.</summary>
    private static string? ValidateSingleStep(PluginCatalog catalog, string? json, PluginCategory expected, string field)
    {
        if (string.IsNullOrWhiteSpace(json))
        {
            return $"{field} is required.";
        }
        try
        {
            return ValidateStep(catalog, PluginStepSerializer.DeserializeSingle(json), expected, field);
        }
        catch (Exception ex) when (ex is System.Text.Json.JsonException or InvalidOperationException)
        {
            return $"{field} is not a valid plugin step ({{\"pluginId\":\"...\",\"options\":{{...}}}}).";
        }
    }

    private static string? ValidateStepList(PluginCatalog catalog, string json, PluginCategory expected, string field)
    {
        try
        {
            foreach (var step in PluginStepSerializer.DeserializeList(json))
            {
                if (ValidateStep(catalog, step, expected, field) is string error)
                {
                    return error;
                }
            }
            return null;
        }
        catch (System.Text.Json.JsonException)
        {
            return $"{field} is not a valid plugin step array.";
        }
    }

    private static string? ValidateStep(PluginCatalog catalog, PluginStepWire step, PluginCategory expected, string field)
    {
        if (!catalog.TryGet(step.PluginId, out var registration))
        {
            return $"{field}: no plugin '{step.PluginId}' is registered on this agent.";
        }
        if (registration.Category != expected)
        {
            return $"{field}: plugin '{step.PluginId}' is a {registration.Category} plugin; expected {expected}.";
        }
        try
        {
            var options = catalog.DeserializeOptions(step.PluginId, step.Options?.GetRawText());
            if (options is not null && RequiredOptionMissing(options) is { } missing)
            {
                return $"{field}: '{missing}' is required for plugin '{step.PluginId}'.";
            }
            return null;
        }
        catch (System.Text.Json.JsonException)
        {
            return $"{field}: options for '{step.PluginId}' are invalid.";
        }
    }

    /// <summary>Name of the first [RequiredOption] property left null/blank, or null if all set.</summary>
    private static string? RequiredOptionMissing(object options)
    {
        foreach (var prop in options.GetType().GetProperties(BindingFlags.Public | BindingFlags.Instance))
        {
            if (prop.GetCustomAttribute<RequiredOptionAttribute>() is null)
            {
                continue;
            }
            var value = prop.GetValue(options);
            if (value is null || (value is string s && string.IsNullOrWhiteSpace(s)))
            {
                return prop.Name;
            }
        }
        return null;
    }

    private static async Task CommitInlineSecretsAsync(
        IEnumerable<ExtractedSecrets?> extracted, SecretsService secrets, CancellationToken ct)
    {
        foreach (var e in extracted)
        {
            if (e is not null)
            {
                await e.CommitAsync(secrets.CreateOrReplaceAsync, ct);
            }
        }
    }

    private static async Task<IResult> DeleteRenewalAsync(
        Guid id,
        IServiceScopeFactory scopeFactory,
        CancellationToken ct)
    {
        // Scoped service (it shares the engine's DbContext registration); store
        // cleanup is best-effort inside, so this either 204s or 404s.
        await using var scope = scopeFactory.CreateAsyncScope();
        var cleanup = scope.ServiceProvider.GetRequiredService<CertificateCleanupService>();
        return await cleanup.DeleteRenewalAsync(id, ct)
            ? Results.NoContent()
            : NotFound(id);
    }

    private static async Task<IResult> GetAgentAsync(
        INodeInfoProvider nodes,
        IDbContextFactory<AcmeManagerDbContext> dbf,
        CancellationToken ct)
    {
        var info = await nodes.GetAsync(ct);
        await using var db = await dbf.CreateDbContextAsync(ct);
        var renewals = await db.Renewals.AsNoTracking().ToListAsync(ct);
        var certs = await db.Certificates.AsNoTracking().ToListAsync(ct);

        var now = DateTimeOffset.UtcNow;
        var latest = LatestByRenewal(certs);
        var expiringSoon = renewals.Count(r =>
            CertificateStatusCalculator.Compute(
                r.Enabled, latest.GetValueOrDefault(r.Id)?.NotAfter, r.RenewalWindowDays, now, r.ConsecutiveFailures)
                == CertificateStatus.ExpiringSoon);

        var dto = new AgentInfoDto(
            info.Product, info.NodeId, info.Name, info.Hostname, info.Fqdn,
            info.Version, info.Os, info.ApiPort,
            renewals.Count, certs.Count, expiringSoon, ApiV1.Version);
        return Results.Ok(dto);
    }

    private static async Task<IResult> GetCertificatesAsync(
        IDbContextFactory<AcmeManagerDbContext> dbf,
        CancellationToken ct)
    {
        await using var db = await dbf.CreateDbContextAsync(ct);
        var renewals = await db.Renewals.AsNoTracking().Include(r => r.Account).ToListAsync(ct);
        var certs = await db.Certificates.AsNoTracking().ToListAsync(ct);

        var now = DateTimeOffset.UtcNow;
        var latest = LatestByRenewal(certs);
        var list = renewals
            .Select(r => ManagementMappers.ToCertificateSummary(r, latest.GetValueOrDefault(r.Id), now))
            .OrderBy(c => c.NotAfter ?? DateTimeOffset.MaxValue) // soonest expiry first; never-issued last
            .ToList();
        return Results.Ok(list);
    }

    private static async Task<IResult> GetAccountsAsync(
        IDbContextFactory<AcmeManagerDbContext> dbf,
        CancellationToken ct)
    {
        await using var db = await dbf.CreateDbContextAsync(ct);
        var accounts = await db.Accounts.AsNoTracking().OrderBy(a => a.Name).ToListAsync(ct);
        var list = accounts
            .Select(a => new AccountSummaryDto(a.Id, a.Name, a.DirectoryUrl, a.ContactEmail))
            .ToList();
        return Results.Ok(list);
    }

    private static async Task<IResult> GetSecretsAsync(
        IDbContextFactory<AcmeManagerDbContext> dbf,
        CancellationToken ct)
    {
        // Names only — secret values never leave the agent.
        await using var db = await dbf.CreateDbContextAsync(ct);
        var names = await db.Secrets.AsNoTracking().Select(s => s.Name).OrderBy(n => n).ToListAsync(ct);
        return Results.Ok(names);
    }

    private static IResult GetPluginsAsync(PluginCatalog catalog, IServiceProvider sp) =>
        Results.Ok(PluginCatalogMapper.Describe(catalog, sp));

    // IIS site names on THIS agent's host, for the console's iisSiteRef pickers.
    private static IResult GetIisSitesAsync(AcmeManager.Core.Plugins.IIisSiteCatalog sites) =>
        Results.Ok(sites.ListSiteNames().ToList());

    // Windows certificate store names on THIS agent's host, for certStoreRef pickers.
    private static IResult GetCertStoresAsync(AcmeManager.Core.Plugins.ICertStoreCatalog stores) =>
        Results.Ok(stores.ListStoreNames().ToList());

    private static async Task<IResult> GetRenewalConfigAsync(
        Guid id,
        PluginCatalog catalog,
        IDbContextFactory<AcmeManagerDbContext> dbf,
        CancellationToken ct)
    {
        await using var db = await dbf.CreateDbContextAsync(ct);
        var r = await db.Renewals.AsNoTracking().FirstOrDefaultAsync(x => x.Id == id, ct);
        if (r is null)
        {
            return NotFound(id);
        }
        // Credential-valued options (a literal PFX/keystore password) never leave
        // the agent: they go out as a placeholder that Update recognises and restores.
        return Results.Ok(new RenewalConfigDto(
            r.Id, r.Name, r.AccountId, r.RenewalWindowDays, r.Enabled,
            SensitiveOptions.Redact(catalog, r.SourceJson),
            SensitiveOptions.Redact(catalog, r.ValidationJson),
            SensitiveOptions.Redact(catalog, r.StoresJson),
            SensitiveOptions.Redact(catalog, r.InstallationsJson),
            r.MaintenanceWindowJson));
    }

    private static async Task<IResult> GetRenewalAsync(
        Guid id,
        IDbContextFactory<AcmeManagerDbContext> dbf,
        CancellationToken ct)
    {
        await using var db = await dbf.CreateDbContextAsync(ct);
        var renewal = await db.Renewals.AsNoTracking()
            .Include(r => r.Account)
            .FirstOrDefaultAsync(r => r.Id == id, ct);
        if (renewal is null)
        {
            return NotFound(id);
        }

        var certs = await db.Certificates.AsNoTracking().Where(c => c.RenewalId == id).ToListAsync(ct);
        var latest = certs.OrderByDescending(c => c.IssuedAt).FirstOrDefault();

        var historyRows = await db.History.AsNoTracking().Where(h => h.RenewalId == id).ToListAsync(ct);
        var history = historyRows.OrderByDescending(h => h.At).Take(50).ToList();

        var dto = ManagementMappers.ToRenewalDetail(renewal, latest, history, DateTimeOffset.UtcNow);
        return Results.Ok(dto);
    }

    private static async Task<IResult> RenewNowAsync(
        Guid id,
        IServiceScopeFactory scopeFactory,
        IDbContextFactory<AcmeManagerDbContext> dbf,
        CancellationToken ct)
    {
        await using (var db = await dbf.CreateDbContextAsync(ct))
        {
            if (!await db.Renewals.AsNoTracking().AnyAsync(r => r.Id == id, ct))
            {
                return NotFound(id);
            }
        }

        // Run in a fresh scope (RenewalEngine is scoped). Use CancellationToken.None
        // so a client disconnect can't abort a partially-placed ACME order — same
        // choice the local "Renew now" button makes.
        await using var scope = scopeFactory.CreateAsyncScope();
        var engine = scope.ServiceProvider.GetRequiredService<RenewalEngine>();
        var result = await engine.RunAsync(id, CancellationToken.None);

        return Results.Ok(new RenewNowResultDto(
            result.Success, result.IssuedNotAfter, result.ErrorMessage, result.DurationMs, result.Warning));
    }

    private static async Task<IResult> SetEnabledAsync(
        Guid id,
        bool enabled,
        IDbContextFactory<AcmeManagerDbContext> dbf,
        CancellationToken ct)
    {
        await using var db = await dbf.CreateDbContextAsync(ct);
        var renewal = await db.Renewals.FirstOrDefaultAsync(r => r.Id == id, ct);
        if (renewal is null)
        {
            return NotFound(id);
        }
        renewal.Enabled = enabled;
        await db.SaveChangesAsync(ct);
        return Results.NoContent();
    }

    private static async Task<IResult> UpdateRenewalAsync(
        Guid id,
        UpdateRenewalRequest? request,
        PluginCatalog catalog,
        IDbContextFactory<AcmeManagerDbContext> dbf,
        SecretsService secrets,
        CancellationToken ct)
    {
        if (request is null)
        {
            return Results.BadRequest(new ApiError(ApiError.Invalid, "Request body is required."));
        }

        await using var db = await dbf.CreateDbContextAsync(ct);
        var renewal = await db.Renewals.FirstOrDefaultAsync(r => r.Id == id, ct);
        if (renewal is null)
        {
            return NotFound(id);
        }

        // A client editing a redacted config sends the placeholder back; put the
        // stored credential behind it before validating or persisting anything. A
        // placeholder that can't be mapped to a stored step is an error, never a guess.
        string? sourceJson, validationJson, storesJson, installationsJson;
        try
        {
            sourceJson = request.SourceJson is null ? null : SensitiveOptions.Restore(catalog, request.SourceJson, renewal.SourceJson);
            validationJson = request.ValidationJson is null ? null : SensitiveOptions.Restore(catalog, request.ValidationJson, renewal.ValidationJson);
            storesJson = request.StoresJson is null ? null : SensitiveOptions.Restore(catalog, request.StoresJson, renewal.StoresJson);
            installationsJson = request.InstallationsJson is null ? null : SensitiveOptions.Restore(catalog, request.InstallationsJson, renewal.InstallationsJson);
        }
        catch (SensitiveOptionException ex)
        {
            return Results.BadRequest(new ApiError(ApiError.Invalid, ex.Message));
        }

        // Inline credentials are stripped now (so validation sees the cleaned JSON)
        // but only written once the update is known to be valid.
        var secretScope = request.Name?.Trim() is { Length: > 0 } newName ? newName : renewal.Name;
        ExtractedSecrets? inlineSource, inlineValidation, inlineStores, inlineInstallations;
        try
        {
            inlineSource = sourceJson is null ? null : InlineSecrets.Extract(catalog, sourceJson, secretScope, renewal.SourceJson);
            inlineValidation = validationJson is null ? null : InlineSecrets.Extract(catalog, validationJson, secretScope, renewal.ValidationJson);
            inlineStores = storesJson is null ? null : InlineSecrets.Extract(catalog, storesJson, secretScope, renewal.StoresJson);
            inlineInstallations = installationsJson is null ? null : InlineSecrets.Extract(catalog, installationsJson, secretScope, renewal.InstallationsJson);
        }
        catch (InlineSecretException ex)
        {
            return Results.BadRequest(new ApiError(ApiError.Invalid, ex.Message));
        }
        sourceJson = inlineSource?.Json ?? sourceJson;
        validationJson = inlineValidation?.Json ?? validationJson;
        storesJson = inlineStores?.Json ?? storesJson;
        installationsJson = inlineInstallations?.Json ?? installationsJson;

        // Same rule as create: credentials are referenced by secret name, not set
        // literally. Judged on what the client SENT (a restored placeholder is not a
        // new literal); echoing a legacy literal back unchanged is still allowed.
        var newLiteral = (request.StoresJson is null ? null : SensitiveOptions.FindLiteral(catalog, request.StoresJson))
            ?? (request.InstallationsJson is null ? null : SensitiveOptions.FindLiteral(catalog, request.InstallationsJson))
            ?? (request.ValidationJson is null ? null : SensitiveOptions.FindLiteral(catalog, request.ValidationJson))
            ?? (request.SourceJson is null ? null : SensitiveOptions.FindLiteral(catalog, request.SourceJson));
        if (newLiteral is not null && !ExistingLiteralUnchanged(catalog, renewal,
                request.SourceJson, request.ValidationJson, request.StoresJson, request.InstallationsJson))
        {
            return Results.BadRequest(new ApiError(ApiError.Invalid,
                $"'{newLiteral}' is a credential and cannot be set literally. Store it as a secret on the agent and reference it by name."));
        }

        var stepError =
            (sourceJson is not null ? ValidateSingleStep(catalog, sourceJson, PluginCategory.Source, "SourceJson") : null)
            ?? (validationJson is not null ? ValidateSingleStep(catalog, validationJson, PluginCategory.Validation, "ValidationJson") : null)
            ?? (storesJson is not null ? ValidateStepList(catalog, storesJson, PluginCategory.Store, "StoresJson") : null)
            ?? (installationsJson is not null ? ValidateStepList(catalog, installationsJson, PluginCategory.Installation, "InstallationsJson") : null);
        if (stepError is not null)
        {
            return Results.BadRequest(new ApiError(ApiError.Invalid, stepError));
        }

        if (request.Name is not null)
        {
            var name = request.Name.Trim();
            if (name.Length == 0)
            {
                return Results.BadRequest(new ApiError(ApiError.Invalid, "Name cannot be empty."));
            }
            if (await db.Renewals.AnyAsync(r => r.Id != id && r.Name == name, ct))
            {
                return Results.Conflict(new ApiError(ApiError.Conflict, $"A renewal named '{name}' already exists."));
            }
            renewal.Name = name;
        }

        if (request.RenewalWindowDays is int days)
        {
            if (days is < 1 or > 365)
            {
                return Results.BadRequest(new ApiError(ApiError.Invalid, "RenewalWindowDays must be between 1 and 365."));
            }
            renewal.RenewalWindowDays = days;
        }

        if (request.Enabled is bool enabled)
        {
            renewal.Enabled = enabled;
        }

        if (request.MaintenanceWindowJson is { } windowJson)
        {
            try
            {
                renewal.MaintenanceWindowJson = MaintenanceWindow.Parse(windowJson)?.ToJson();
            }
            catch (FormatException ex)
            {
                return Results.BadRequest(new ApiError(ApiError.Invalid, ex.Message));
            }
        }

        if (request.AccountId is Guid accountId)
        {
            if (!await db.Accounts.AnyAsync(a => a.Id == accountId, ct))
            {
                return Results.BadRequest(new ApiError(ApiError.Invalid, $"Account {accountId} was not found."));
            }
            renewal.AccountId = accountId;
        }

        if (sourceJson is not null) renewal.SourceJson = sourceJson;
        if (validationJson is not null) renewal.ValidationJson = validationJson;
        if (storesJson is not null) renewal.StoresJson = storesJson;
        if (installationsJson is not null) renewal.InstallationsJson = installationsJson;

        await CommitInlineSecretsAsync([inlineSource, inlineValidation, inlineStores, inlineInstallations], secrets, ct);
        await db.SaveChangesAsync(ct);
        return Results.NoContent();
    }

    /// <summary>
    /// True when every slot that carries a literal credential is byte-identical to
    /// what is already stored (a redacted round-trip restored it, or the client
    /// echoed a legacy literal unchanged). Only a NEW or changed literal is refused,
    /// so legacy configs keep working until they are migrated to a secret.
    /// </summary>
    private static bool ExistingLiteralUnchanged(
        PluginCatalog catalog, Renewal renewal,
        string? sourceJson, string? validationJson, string? storesJson, string? installationsJson)
    {
        var stored = new[] { renewal.SourceJson, renewal.ValidationJson, renewal.StoresJson, renewal.InstallationsJson };
        var incoming = new[] { sourceJson, validationJson, storesJson, installationsJson };
        for (var i = 0; i < stored.Length; i++)
        {
            if (incoming[i] is null || SensitiveOptions.FindLiteral(catalog, incoming[i]!) is null)
            {
                continue;
            }
            if (!string.Equals(incoming[i], stored[i], StringComparison.Ordinal))
            {
                return false;
            }
        }
        return true;
    }

    private static Dictionary<Guid, Certificate> LatestByRenewal(IEnumerable<Certificate> certs) =>
        certs.GroupBy(c => c.RenewalId)
            .ToDictionary(g => g.Key, g => g.OrderByDescending(c => c.IssuedAt).First());

    private static IResult NotFound(Guid id) =>
        Results.NotFound(new ApiError(ApiError.NotFound, $"Renewal {id} was not found."));
}