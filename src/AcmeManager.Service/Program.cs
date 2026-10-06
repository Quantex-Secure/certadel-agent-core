using System.Security.Claims;
using System.Security.Cryptography;
using System.Threading.RateLimiting;

using AcmeManager.Api.Contracts;
using AcmeManager.Core.Acme;
using AcmeManager.Core.Acme.Accounts;
using AcmeManager.Core.Acme.Orders;
using AcmeManager.Core.Authentication;
using AcmeManager.Core.Discovery;
using AcmeManager.Core.Engine;
using AcmeManager.Core.Storage;
using AcmeManager.Plugins.BuiltIn.Installation;
using AcmeManager.Plugins.BuiltIn.Sources;
using AcmeManager.Plugins.BuiltIn.Storage;
using AcmeManager.Plugins.BuiltIn.Validation;
using AcmeManager.Plugins.Dns.Azure;
using AcmeManager.Plugins.Iis;
using AcmeManager.Service;
using AcmeManager.Service.Api.V1;
using AcmeManager.Service.Authentication;
using AcmeManager.Service.Components;
using AcmeManager.Service.Discovery;
using AcmeManager.Service.Https;
using AcmeManager.Service.Logging;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.Negotiate;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;

using Serilog;

// CLI verbs (run before the web host). Migration tooling etc.
if (args.Length > 0 && string.Equals(args[0], "import-winacme", StringComparison.OrdinalIgnoreCase))
{
    return await AcmeManager.Service.Migration.WinAcme.WinAcmeImport.RunAsync(args);
}

if (args.Length > 0 && string.Equals(args[0], "import-acmesh", StringComparison.OrdinalIgnoreCase))
{
    return await AcmeManager.Service.Migration.AcmeSh.AcmeShImport.RunAsync(args);
}

if (args.Length > 0 && string.Equals(args[0], "coverage", StringComparison.OrdinalIgnoreCase))
{
    return await AcmeManager.Service.Coverage.CoverageCli.RunAsync(args);
}

if (args.Length > 0 && string.Equals(args[0], "handoff", StringComparison.OrdinalIgnoreCase))
{
    return await AcmeManager.Service.Handoff.HandoffCli.RunAsync(args);
}

var logStore = SerilogConfig.Configure();

try
{
    Log.Information("Starting AcmeManager.Service on {OS}", Environment.OSVersion);

    // Pin the content root to the binary's directory so appsettings*.json are found
    // regardless of the working directory (Windows Service, `dotnet run`, or a bare
    // `dotnet App.dll` from elsewhere all behave the same — incl. dev auto-sign-in).
    var builder = WebApplication.CreateBuilder(new WebApplicationOptions
    {
        Args = args,
        ContentRootPath = AppContext.BaseDirectory,
    });

    // Cross-platform service hosting.
    builder.Services.AddWindowsService(options => options.ServiceName = "AcmeManager");
    builder.Services.AddSystemd();

    // Kestrel — HTTPS-only on :9443. Serves a self-signed bootstrap cert until a
    // renewal issues a cert for this host (installer.acme-manager-endpoint), then
    // hot-swaps to it via the certificate selector — no restart needed.
    var endpointCert = new EndpointCertificateProvider(DataPaths.Root);
    builder.Services.AddSingleton(endpointCert);
    builder.Services.AddSingleton<AcmeManager.Core.Https.IEndpointCertificateState>(endpointCert);
    var uiPort = builder.Configuration.GetValue<int?>("Web:Port") ?? 9443;
    builder.WebHost.ConfigureKestrel(opts =>
        opts.ListenAnyIP(uiPort, listen => listen.UseHttps(https =>
            https.ServerCertificateSelector = (_, _) => endpointCert.Current)));

    // Logging — Serilog only.
    builder.Logging.ClearProviders();
    builder.Services.AddSerilog();
    builder.Services.AddSingleton(logStore);

    // Storage — factory for Blazor (per-operation contexts), plus a scoped
    // context derived from it so non-Blazor consumers can still inject DbContext directly.
    Directory.CreateDirectory(DataPaths.Root);
    // Lock the data directory to SYSTEM + Administrators (Windows) / 0700 (Unix) so a
    // low-privileged local account can't read the SQLite DB or the secret key and
    // decrypt stored ACME keys and provider credentials. Propagates to files created
    // inside; harden an already-created DB explicitly for upgrades from older versions.
    AcmeManager.Plugins.Contracts.SecureFileSystem.HardenDirectory(DataPaths.Root);
    var databaseFile = builder.Configuration["Storage:DatabaseFile"] ?? DataPaths.DatabaseFile;
    if (File.Exists(databaseFile))
    {
        AcmeManager.Plugins.Contracts.SecureFileSystem.HardenFile(databaseFile);
    }
    // The scheduler, the UI, the API and the secret resolver all write to one
    // SQLite file. A busy timeout makes lock contention a short wait instead of an
    // immediate "database is locked" failure; WAL mode (set by the migrator) lets
    // readers proceed while a writer holds the lock.
    builder.Services.AddDbContextFactory<AcmeManagerDbContext>(opts =>
        opts.UseSqlite($"Data Source={databaseFile};Default Timeout=30"));
    builder.Services.AddScoped(sp =>
        sp.GetRequiredService<IDbContextFactory<AcmeManagerDbContext>>().CreateDbContext());

    // Core services.
    builder.Services.AddAcmeManagerSecrets();
    builder.Services.AddSingleton<IAcmeClient, CertesAcmeClient>();
    builder.Services.AddSingleton<OrderRunner>();
    builder.Services.AddSingleton<RenewalRunGuard>();
    builder.Services.AddSingleton<AcmeManager.Core.Plugins.IIisSiteCatalog, AcmeManager.Service.Iis.WindowsIisSiteCatalog>();
    builder.Services.AddSingleton<AcmeManager.Core.Plugins.ICertStoreCatalog, AcmeManager.Service.Certificates.WindowsCertStoreCatalog>();
    builder.Services.AddScoped<AccountService>();
    builder.Services.AddScoped<DnsProvidersService>();
    builder.Services.AddScoped<RenewalEngine>();
    builder.Services.AddScoped<CertificateCleanupService>();

    // Failure alerting: after Notifications:FailureThreshold consecutive failures a
    // renewal raises a critical log line and every registered INotifier fires
    // (today: the webhook, when Notifications:WebhookUrl is set).
    builder.Services.Configure<AcmeManager.Core.Notifications.NotificationOptions>(
        builder.Configuration.GetSection(AcmeManager.Core.Notifications.NotificationOptions.Section));
    builder.Services.AddHttpClient();
    builder.Services.AddSingleton<AcmeManager.Plugins.Contracts.Notification.INotifier, AcmeManager.Core.Notifications.WebhookNotifier>();
    builder.Services.AddSingleton<RenewalAlertService>();

    // Post-install verification: prove the served certificate before recording a
    // renewal as successful; installers supply endpoints and rollbacks.
    builder.Services.Configure<AcmeManager.Core.Verification.TlsVerifierOptions>(
        builder.Configuration.GetSection(AcmeManager.Core.Verification.TlsVerifierOptions.Section));
    builder.Services.AddSingleton<AcmeManager.Core.Verification.IEndpointVerifier, AcmeManager.Core.Verification.TlsEndpointVerifier>();
    builder.Services.AddSingleton<AcmeManager.Core.Verification.InstallVerificationRunner>();
    // Drives the web UI's win-acme import page; the CLI verb above uses it too.
    builder.Services.AddScoped<AcmeManager.Service.Migration.WinAcme.WinAcmeImportService>();
    // Drives the Linux acme.sh import page.
    builder.Services.AddScoped<AcmeManager.Service.Migration.AcmeSh.AcmeShImportService>();
    // Drives the coverage report (reconciles HAProxy-served certs vs renewals).
    builder.Services.AddScoped<AcmeManager.Service.Coverage.CoverageService>();
    // Internal CA inventory for the console's estate view (Coverage:AdcsCaConfig).
    builder.Services.AddSingleton<AcmeManager.Service.Coverage.AdcsIssuedCertReader>();
    builder.Services.AddScoped<AcmeManager.Service.Handoff.HandoffService>();

    // Script/exec plugins run operator-supplied commands as the service account
    // (SYSTEM/root). Hosts that don't need them can switch them off so an
    // authenticated API caller can never turn "manage certificates" into "run code".
    var allowScriptPlugins = builder.Configuration.GetValue("Plugins:AllowScriptPlugins", defaultValue: true);

    // Plugin catalog.
    builder.Services.AddPluginCatalog(catalog =>
    {
        // Cross-platform plugins.
        catalog.AddSource<ManualSource, ManualSourceOptions>("source.manual");

        catalog.AddValidator<FileSystemHttp01Validator, FileSystemHttp01Options>("validation.http-01.filesystem");
        catalog.AddValidator<SelfHostedHttp01Validator, SelfHostedHttp01Options>("validation.http-01.selfhosted");
        catalog.AddValidator<ManualDns01Validator, ManualDns01Options>("validation.dns-01.manual");
        catalog.AddValidator<CloudflareDns01Validator, CloudflareDns01Options>("validation.dns-01.cloudflare");
        catalog.AddValidator<NamecheapDns01Validator, NamecheapDns01Options>("validation.dns-01.namecheap");
        catalog.AddValidator<AzureDns01Validator, AzureDns01Options>("validation.dns-01.azure");
        catalog.AddValidator<AcmeManager.Plugins.Dns.Google.GoogleDns01Validator, AcmeManager.Plugins.Dns.Google.GoogleDns01Options>("validation.dns-01.google");
        catalog.AddValidator<AcmeManager.Plugins.Dns.Aws.Route53Dns01Validator, AcmeManager.Plugins.Dns.Aws.Route53Dns01Options>("validation.dns-01.route53");

        catalog.AddStore<PfxFileStore, PfxFileStoreOptions>("store.pfx");
        catalog.AddStore<PemFileStore, PemFileStoreOptions>("store.pem");

        catalog.AddInstaller<SelfEndpointInstaller, SelfEndpointInstallerOptions>("installer.acme-manager-endpoint");

        if (allowScriptPlugins)
        {
            catalog.AddValidator<ScriptDns01Validator, ScriptDns01Options>("validation.dns-01.script");
            catalog.AddInstaller<ScriptInstaller, ScriptInstallerOptions>("installer.script");
        }

        // Windows-only plugins — not registered on Linux, so they never appear there.
        if (OperatingSystem.IsWindows())
        {
            catalog.AddSource<IisSource, IisSourceOptions>("source.iis");
            catalog.AddStore<WindowsCertStore, WindowsCertStoreOptions>("store.winstore");
            catalog.AddInstaller<IisInstaller, IisInstallerOptions>("installer.iis");
        }

        // Linux-only web-server installers — not registered on Windows, nor on
        // Synology DSM, where the agent runs unprivileged and cannot write system
        // cert paths or reload services.
        if (OperatingSystem.IsLinux() && !AcmeManager.Plugins.Linux.Synology.DsmPlatform.IsDsm)
        {
            catalog.AddInstaller<AcmeManager.Plugins.Linux.HaProxyInstaller, AcmeManager.Plugins.Linux.HaProxyInstallerOptions>("installer.haproxy");
            catalog.AddInstaller<AcmeManager.Plugins.Linux.ApacheInstaller, AcmeManager.Plugins.Linux.ApacheInstallerOptions>("installer.apache");
            catalog.AddInstaller<AcmeManager.Plugins.Linux.TomcatInstaller, AcmeManager.Plugins.Linux.TomcatInstallerOptions>("installer.tomcat");
        }

        // Synology DSM: certificates go into DSM through its Web API.
        if (AcmeManager.Plugins.Linux.Synology.DsmPlatform.IsDsm)
        {
            catalog.AddInstaller<AcmeManager.Plugins.Linux.Synology.DsmInstaller, AcmeManager.Plugins.Linux.Synology.DsmInstallerOptions>("installer.synology-dsm");
        }
    });

    // Shell command runner for the Linux installers' service reloads.
    builder.Services.AddSingleton<AcmeManager.Plugins.Linux.ICommandRunner, AcmeManager.Plugins.Linux.ShellCommandRunner>();

    // Auth — the Blazor UI uses an OS-integrated (LogonUser / PAM) cookie session;
    // the remote management API (/api/v1) additionally accepts Negotiate (Windows
    // Integrated Auth SSO) and Basic (username/password fallback), both authorized
    // by the same Auth:AllowedGroup membership test.
    builder.Services.AddOsAuthBackend();
    // On Synology DSM the backend only ever reports DSM's administrators (see
    // DsmAuthBackend), so that is the default there whenever none is configured.
    builder.Services.AddSingleton(sp =>
    {
        var allowedGroup = sp.GetRequiredService<IConfiguration>()["Auth:AllowedGroup"];
        if (string.IsNullOrWhiteSpace(allowedGroup) && AcmeManager.Plugins.Linux.Synology.DsmPlatform.IsDsm)
        {
            allowedGroup = DsmAuthBackend.AdministratorsGroup;
        }
        return new AllowedGroupAuthorizer(allowedGroup);
    });
    // Per-account brute-force lockout for Basic and the form login (the per-IP rate
    // limiter below is defeated by rotating source addresses).
    builder.Services.AddSingleton<AuthThrottle>();
    builder.Services.AddScoped<IAuthorizationHandler, ManagementApiAuthorizationHandler>();

    // Negotiate requires a server that supports it (Kestrel / HTTP.sys) and a
    // domain context; disable it (Auth:EnableNegotiate=false) for non-domain
    // agents or test hosts, leaving Basic as the only API scheme.
    var enableNegotiate = builder.Configuration.GetValue("Auth:EnableNegotiate", defaultValue: true);

    var authBuilder = builder.Services
        .AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
        .AddCookie(opts =>
        {
            opts.LoginPath = "/login";
            opts.LogoutPath = "/api/logout";
            opts.AccessDeniedPath = "/login";
            opts.ExpireTimeSpan = TimeSpan.FromHours(8);
            opts.SlidingExpiration = true;
        })
        .AddScheme<AuthenticationSchemeOptions, BasicAuthenticationHandler>(
            BasicAuthenticationHandler.SchemeName, _ => { });

    if (enableNegotiate)
    {
        authBuilder.AddNegotiate();
    }

    // Route management-API requests to Basic when they carry a Basic header,
    // otherwise to Negotiate (which challenges for SSO / NTLM) — or to Basic when
    // Negotiate is disabled, so the request still gets a Basic challenge.
    authBuilder.AddPolicyScheme(ManagementApiAuth.PolicyScheme, ManagementApiAuth.PolicyScheme, opts =>
    {
        opts.ForwardDefaultSelector = ctx =>
        {
            string? authorization = ctx.Request.Headers.Authorization;
            if (authorization is not null
                && authorization.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase))
            {
                return BasicAuthenticationHandler.SchemeName;
            }
            return enableNegotiate
                ? NegotiateDefaults.AuthenticationScheme
                : BasicAuthenticationHandler.SchemeName;
        };
    });

    builder.Services.AddAuthorization(opts =>
    {
        // The Blazor UI keeps the cookie fallback; the management API names its
        // own scheme explicitly so this fallback never applies to /api/v1.
        opts.FallbackPolicy = new AuthorizationPolicyBuilder()
            .RequireAuthenticatedUser()
            .Build();
        opts.AddPolicy(ManagementApiAuth.Policy, policy => policy
            .AddAuthenticationSchemes(ManagementApiAuth.PolicyScheme)
            .RequireAuthenticatedUser()
            .AddRequirements(new AllowedGroupRequirement()));
    });
    builder.Services.AddCascadingAuthenticationState();

    // Rate limiting — throttle credential brute-force against the auth endpoints,
    // partitioned by client IP. Values are generous enough for a real console/login
    // but trip a stuffing loop; QueueLimit 0 means excess requests are rejected (429),
    // not queued.
    builder.Services.AddRateLimiter(options =>
    {
        options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;

        options.AddPolicy(RateLimitPolicies.Login, ctx =>
            RateLimitPartition.GetFixedWindowLimiter(ClientPartition(ctx), _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 10,
                Window = TimeSpan.FromMinutes(5),
                QueueLimit = 0,
            }));

        options.AddPolicy(RateLimitPolicies.ManagementApi, ctx =>
            RateLimitPartition.GetFixedWindowLimiter(ClientPartition(ctx), _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 300,
                Window = TimeSpan.FromMinutes(1),
                QueueLimit = 0,
            }));
    });

    // Blazor Server.
    builder.Services.AddRazorComponents().AddInteractiveServerComponents();

    // Hosted services start in registration order: the migrator MUST stay first so
    // the database is ready before the workers run and before Kestrel (which starts
    // last) accepts requests.
    builder.Services.AddHostedService<DatabaseMigratorWorker>();

    // Renewal scheduler runs in the same process.
    builder.Services.AddHostedService<RenewalSchedulerWorker>();

    // Network discovery — stable node identity + mDNS advertisement so a central
    // management console can find and identify this node.
    builder.Services.AddSingleton<INodeInfoProvider, NodeInfoProvider>();
    // Long-lived node identity key: lets a console verify that a changed endpoint
    // certificate still belongs to the agent it enrolled (signed attestation).
    builder.Services.AddSingleton<INodeIdentityKey, NodeIdentityKeyProvider>();
    builder.Services.AddHostedService<MdnsAdvertiserWorker>();

    var app = builder.Build();

    if (!allowScriptPlugins)
    {
        Log.Warning("Plugins:AllowScriptPlugins=false — 'installer.script' and 'validation.dns-01.script' are not registered; renewals that use them will fail until re-enabled.");
    }

    // NOTE: no blocking work between Build() and RunAsync() — as a Windows Service,
    // everything here runs before the SCM dispatcher connects and counts against the
    // 30-second start timeout. Startup work belongs in DatabaseMigratorWorker (or a
    // later hosted service).

    if (!app.Environment.IsDevelopment())
    {
        app.UseExceptionHandler("/Error", createScopeForErrors: true);
        app.UseHsts();
    }
    // Re-execute error status codes through the Blazor "/not-found" UI page — but
    // only for the browser-facing app. The management API must return clean status
    // codes (401/403/404) to its clients, not an HTML page or a login redirect.
    app.UseWhen(
        ctx => !ctx.Request.Path.StartsWithSegments("/api"),
        branch => branch.UseStatusCodePagesWithReExecute("/not-found", createScopeForStatusCodePages: true));

    app.UseRateLimiter();
    app.UseAuthentication();

    // Dev-mode auto-signin so contributors can iterate the UI without OS creds.
    // Documented as INSECURE; only honored when Web:AllowAnonymous=true.
    if (app.Configuration.GetValue<bool>("Web:AllowAnonymous"))
    {
        Log.Warning("Web:AllowAnonymous=true — UI runs unauthenticated as 'dev-user'. Do NOT enable in production.");
        app.Use(async (ctx, next) =>
        {
            // Never let the dev bypass satisfy the management API — it authenticates
            // a role-less principal that must not pass the AllowedGroup policy.
            if (ctx.Request.Path.StartsWithSegments("/api/v1"))
            {
                await next();
                return;
            }
            if (ctx.User.Identity?.IsAuthenticated != true)
            {
                var identity = new ClaimsIdentity(
                    [new Claim(ClaimTypes.Name, "dev-user")],
                    "DevAnonymous");
                ctx.User = new ClaimsPrincipal(identity);
            }
            await next();
        });
    }

    app.UseAuthorization();
    app.UseAntiforgery();

    // Static assets (CSS, JS bundles, and the Blazor framework script — which is
    // itself a static web asset) must be reachable without authentication, or the
    // login page renders with no styling/scripts behind the fallback auth policy.
    app.MapStaticAssets().AllowAnonymous();
    // App (root/host page) lives here in the Service project so the host is a
    // Blazor app and emits the framework's blazor.web.js. Routable page
    // components live in the AcmeManager.Web RCL, so register that assembly for
    // endpoint discovery.
    app.MapRazorComponents<App>()
        .AddInteractiveServerRenderMode()
        .AddAdditionalAssemblies(typeof(AcmeManager.Web.Components.Routes).Assembly);

    // Remote management API for the Unified Certificate Manager console.
    app.MapManagementApiV1();

    // Discovery — anonymous, non-sensitive node identity for a management console
    // to find/identify this node (across subnets via direct probe; on the local
    // subnet the mDNS advertiser surfaces it automatically).
    app.MapGet("/.well-known/acme-manager", async (INodeInfoProvider nodes, INodeIdentityKey identity, CancellationToken ct) =>
    {
        var info = await nodes.GetAsync(ct);
        return Results.Json(new
        {
            product = info.Product,
            nodeId = info.NodeId,
            name = info.Name,
            hostname = info.Hostname,
            fqdn = info.Fqdn,
            version = info.Version,
            os = info.Os,
            apiPort = info.ApiPort,
            // Public half of the node identity key (base64 SubjectPublicKeyInfo).
            // A console captures it at enrollment and later verifies attestations.
            nodeKey = await identity.GetPublicKeyAsync(ct),
        });
    }).AllowAnonymous();

    // Identity attestation — anonymous, rate-limited. The console calls this when
    // an enrolled agent's endpoint certificate no longer matches its pin: the
    // agent signs (nodeId, the console's nonce, the SHA-256 of the cert it is
    // serving) with the node identity key, so the console can tell a routine
    // certificate renewal from someone else answering on the same address.
    app.MapGet(NodeAttestation.Path, async (
        string? nonce,
        INodeInfoProvider nodes,
        INodeIdentityKey identity,
        EndpointCertificateProvider endpoint,
        CancellationToken ct) =>
    {
        if (!NodeAttestation.IsValidNonce(nonce))
        {
            return Results.BadRequest(new ApiError(ApiError.Invalid, "nonce must be base64url and decode to 16-64 bytes."));
        }
        var info = await nodes.GetAsync(ct);
        var certSha256 = endpoint.Current.GetCertHashString(HashAlgorithmName.SHA256);
        var signedAt = DateTimeOffset.UtcNow;
        var signature = await identity.SignAsync(
            NodeAttestation.BuildMessage(info.NodeId, nonce!, certSha256, signedAt), ct);
        return Results.Ok(new NodeAttestationDto(info.NodeId, nonce!, certSha256, signedAt, Convert.ToBase64String(signature)));
    }).AllowAnonymous().RequireRateLimiting(RateLimitPolicies.ManagementApi);

    // Login / logout — plain HTTP endpoints so they can issue cookies outside any Blazor circuit.
    app.MapPost("/api/login", async (HttpContext ctx, IAuthBackend auth, AllowedGroupAuthorizer authorizer, AuthThrottle throttle) =>
    {
        // Login-CSRF guard: this endpoint issues a session cookie and disables the
        // Blazor antiforgery token, so reject cross-site form POSTs (which would let
        // an attacker page silently log a victim in as the attacker).
        if (!IsSameSiteRequest(ctx))
        {
            return Results.StatusCode(StatusCodes.Status403Forbidden);
        }

        var form = await ctx.Request.ReadFormAsync();
        var username = form["username"].ToString();
        var password = form["password"].ToString();
        var returnUrl = form["returnUrl"].ToString();
        if (string.IsNullOrEmpty(returnUrl) || !returnUrl.StartsWith('/')) returnUrl = "/";

        // One generic message for every failure so the login page can't be used
        // as an oracle for "valid password, wrong group" vs "wrong password". The
        // specific reason goes to the log.
        const string genericError =
            "Sign-in failed. Check the username and password, and that the account is permitted to manage this agent.";
        var failedRedirect = $"/login?error={Uri.EscapeDataString(genericError)}&returnUrl={Uri.EscapeDataString(returnUrl)}";

        AuthResult result;
        using (await throttle.EnterAsync(username, ctx.RequestAborted))
        {
            if (throttle.IsLockedOut(username, out var retryAfter))
            {
                Log.Warning("Login refused for '{User}' from {Client}: account throttled for another {Seconds:0}s",
                    username, ctx.Connection.RemoteIpAddress, retryAfter.TotalSeconds);
                return Results.Redirect(failedRedirect);
            }

            result = await auth.AuthenticateAsync(username, password, ctx.RequestAborted);
            if (!result.Success)
            {
                var lockout = throttle.RecordFailure(username);
                Log.Information("Login rejected for '{User}' from {Client}: {Reason}{Lockout}",
                    username, ctx.Connection.RemoteIpAddress, result.Reason,
                    lockout is { } l ? $" — account throttled for {l.TotalMinutes:0} min" : "");
                return Results.Redirect(failedRedirect);
            }
            throttle.RecordSuccess(username);
        }

        // Authorization is decided here — not inside the OS backend — so the rule
        // is the same one the management API enforces, on every OS.
        if (!authorizer.IsAuthorized(result.Groups))
        {
            Log.Warning("Login denied for '{User}' from {Client}: not a member of {Group}.",
                result.Username ?? username, ctx.Connection.RemoteIpAddress, authorizer.AllowedGroupDisplay);
            return Results.Redirect(failedRedirect);
        }
        Log.Information("Login succeeded for '{User}' from {Client}.", result.Username ?? username, ctx.Connection.RemoteIpAddress);

        var claims = new List<Claim>
        {
            new(ClaimTypes.Name, result.Username ?? username),
        };
        if (result.Groups is not null)
        {
            claims.AddRange(result.Groups.Select(g => new Claim(ClaimTypes.Role, g)));
        }
        var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
        await ctx.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(identity));
        return Results.Redirect(returnUrl);
    }).AllowAnonymous().DisableAntiforgery().RequireRateLimiting(RateLimitPolicies.Login);

    app.MapPost("/api/logout", async (HttpContext ctx) =>
    {
        await ctx.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        return Results.Redirect("/login");
    }).DisableAntiforgery();

    await app.RunAsync();
    return 0;
}
catch (Exception ex)
{
    Log.Fatal(ex, "Service terminated unexpectedly");
    return 1;
}
finally
{
    await Log.CloseAndFlushAsync();
}

// Exposed so integration tests can host the app via WebApplicationFactory<Program>.
public partial class Program
{
    /// <summary>
    /// True when the request is same-site (safe to accept a state-changing POST).
    /// Uses the browser's Fetch-Metadata signal when present, falling back to
    /// comparing the <c>Origin</c> host to the request host. A missing Origin (a
    /// non-browser client) is treated as same-site — the CSRF vector is a browser.
    /// </summary>
    private static bool IsSameSiteRequest(HttpContext ctx)
    {
        var fetchSite = ctx.Request.Headers["Sec-Fetch-Site"].ToString();
        if (!string.IsNullOrEmpty(fetchSite))
        {
            return fetchSite is "same-origin" or "same-site" or "none";
        }

        var origin = ctx.Request.Headers.Origin.ToString();
        if (string.IsNullOrEmpty(origin))
        {
            return true;
        }

        return Uri.TryCreate(origin, UriKind.Absolute, out var originUri)
            && string.Equals(originUri.Host, ctx.Request.Host.Host, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Rate-limiter partition key: the client IP, or a shared bucket if unknown.</summary>
    private static string ClientPartition(HttpContext ctx) =>
        ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";
}