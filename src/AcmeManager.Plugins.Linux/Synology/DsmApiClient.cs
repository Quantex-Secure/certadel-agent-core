using System.Globalization;
using System.Net;
using System.Net.Security;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace AcmeManager.Plugins.Linux.Synology;

/// <summary>A signed-in DSM Web API session.</summary>
public sealed record DsmSession(string Sid, string SynoToken, int AuthVersion);

/// <summary>A DSM service a certificate is bound to. <see cref="RawJson"/> is DSM's own
/// service object, which <c>SYNO.Core.Certificate.Service set</c> requires verbatim.</summary>
public sealed record DsmCertificateService(string DisplayName, string Service, string Subscriber, string RawJson);

/// <summary>PEM material for a DSM import: the key, the leaf alone, and its intermediates.</summary>
public sealed record DsmCertificateMaterial(string PrivateKeyPem, string CertificatePem, string IntermediatesPem);

public sealed record DsmCertificate(
    string Id,
    string Description,
    bool IsDefault,
    string? CommonName,
    IReadOnlyList<string> SubjectAltNames,
    DateTimeOffset? ValidTill,
    IReadOnlyList<DsmCertificateService> Services);

/// <summary>
/// Minimal client for the DSM Web API on the local NAS (<c>http://127.0.0.1:5000</c>
/// by default). Credentials travel in POST bodies, never query strings.
///
/// Trust model: the endpoint must be loopback (http or https) or a remote host over
/// https with normal certificate validation. On loopback, TLS certificate errors are
/// tolerated — DSM serves its own, often self-signed, certificate there, and the
/// traffic never leaves the box; DSM's web server permanently holds those ports, so
/// impersonating it requires a local process able to take them. When DSM forces
/// HTTPS, the first call's redirect is followed only to HTTPS on the same host and
/// DSM's HTTPS port (<see cref="DsmHttpsPort"/>); a custom HTTPS port must be
/// configured directly.
/// </summary>
public sealed partial class DsmApiClient : IDisposable
{
    public const int DsmHttpsPort = 5001;

    private const string SessionName = "Certadel";
    private const int MaxSupportedAuthVersion = 7;
    private const int FallbackAuthVersion = 6;
    private static readonly TimeSpan RequestTimeout = TimeSpan.FromSeconds(30);

    private readonly HttpClient _http;
    private readonly bool _ownsHttp;

    public DsmApiClient(Uri baseAddress)
        : this(baseAddress, CreateHttpClient(baseAddress), ownsHttp: true)
    {
    }

    internal DsmApiClient(Uri baseAddress, HttpClient http, bool ownsHttp)
    {
        BaseAddress = ValidateEndpoint(baseAddress);
        _http = http;
        _ownsHttp = ownsHttp;
    }

    /// <summary>The DSM endpoint in use; switches to HTTPS if DSM redirected there.</summary>
    public Uri BaseAddress { get; private set; }

    /// <summary>
    /// Checks a configured DSM endpoint and returns its normalized base address
    /// (<c>scheme://host:port/</c>). Throws <see cref="ArgumentException"/> unless it is
    /// http(s) without credentials, query or fragment, and — if not loopback — https.
    /// </summary>
    public static Uri ValidateEndpoint(Uri endpoint)
    {
        if (!endpoint.IsAbsoluteUri || (endpoint.Scheme != Uri.UriSchemeHttp && endpoint.Scheme != Uri.UriSchemeHttps))
        {
            throw new ArgumentException($"DSM endpoint must be an http(s) URL: {endpoint}", nameof(endpoint));
        }
        if (endpoint.UserInfo.Length > 0 || endpoint.Query.Length > 0 || endpoint.Fragment.Length > 0)
        {
            throw new ArgumentException("DSM endpoint must not contain credentials, a query or a fragment", nameof(endpoint));
        }
        if (!IsLoopback(endpoint) && endpoint.Scheme != Uri.UriSchemeHttps)
        {
            throw new ArgumentException(
                $"DSM endpoint {endpoint.Host} is not on this NAS; use https so the password is not sent in clear text",
                nameof(endpoint));
        }
        return BaseOf(endpoint);
    }

    public async Task<DsmSession> LoginAsync(string account, string password, CancellationToken ct)
    {
        var authVersion = await QueryAuthVersionAsync(ct);
        var data = await PostAsync("SYNO.API.Auth", new Dictionary<string, string>
        {
            ["api"] = "SYNO.API.Auth",
            ["version"] = authVersion.ToString(CultureInfo.InvariantCulture),
            ["method"] = "login",
            ["session"] = SessionName,
            ["format"] = "sid",
            ["enable_syno_token"] = "yes",
            ["account"] = account,
            ["passwd"] = password,
        }, session: null, ct);

        var sid = Str(data, "sid");
        if (sid.Length == 0)
        {
            throw new DsmApiException("DSM login succeeded but returned no session id");
        }
        return new DsmSession(sid, Str(data, "synotoken"), authVersion);
    }

    public async Task<IReadOnlyList<DsmCertificate>> ListCertificatesAsync(DsmSession session, CancellationToken ct)
    {
        var data = await PostAsync("SYNO.Core.Certificate.CRT", new Dictionary<string, string>
        {
            ["api"] = "SYNO.Core.Certificate.CRT",
            ["version"] = "1",
            ["method"] = "list",
        }, session, ct);

        return TryProp(data, "certificates", out var certs) && certs.ValueKind == JsonValueKind.Array
            ? certs.EnumerateArray().Where(c => c.ValueKind == JsonValueKind.Object).Select(ParseCertificate).ToList()
            : [];
    }

    /// <summary>
    /// Imports a certificate (<c>SYNO.Core.Certificate import</c>). With
    /// <paramref name="replaceId"/> DSM overwrites that certificate in place and keeps
    /// every service bound to it; without, it creates a new one. DSM restarts its web
    /// server afterwards, which can drop this connection — callers must verify.
    /// Returns the certificate's DSM id.
    /// </summary>
    public async Task<string> ImportCertificateAsync(
        DsmSession session,
        DsmCertificateMaterial material,
        string? replaceId,
        string description,
        bool asDefault,
        CancellationToken ct)
    {
        // DSM reads api/method/session for uploads from the query string (as acme.sh does);
        // the request never leaves the configured endpoint.
        var query = "webapi/entry.cgi?api=SYNO.Core.Certificate&method=import&version=1"
            + $"&_sid={Uri.EscapeDataString(session.Sid)}"
            + (session.SynoToken.Length > 0 ? $"&SynoToken={Uri.EscapeDataString(session.SynoToken)}" : "");

        using var response = await SendAsync(() =>
        {
            var content = ImportBody(material, replaceId, description, asDefault);
            var request = new HttpRequestMessage(HttpMethod.Post, new Uri(BaseAddress, query)) { Content = content };
            if (session.SynoToken.Length > 0)
            {
                request.Headers.Add("X-SYNO-TOKEN", session.SynoToken);
            }
            return request;
        }, ct);

        var id = Str(await ReadDataAsync(response, "SYNO.Core.Certificate", ct), "id");
        return id.Length > 0 ? id : replaceId ?? throw new DsmApiException("DSM import returned no certificate id");
    }

    /// <summary>
    /// Re-binds services to certificate <paramref name="newId"/>
    /// (<c>SYNO.Core.Certificate.Service set</c>). Each service object is DSM's own,
    /// echoed verbatim, with the certificate it is bound to now. Re-binding DSM's
    /// own web service restarts it and can drop this connection — callers must verify.
    /// </summary>
    public async Task SetServicesAsync(
        DsmSession session,
        IReadOnlyList<(DsmCertificateService Service, string CurrentCertId)> services,
        string newId,
        CancellationToken ct)
    {
        var settings = new JsonArray(services.Select(s => (JsonNode)new JsonObject
        {
            ["service"] = JsonNode.Parse(s.Service.RawJson),
            ["old_id"] = s.CurrentCertId,
            ["id"] = newId,
        }).ToArray());

        await PostAsync("SYNO.Core.Certificate.Service", new Dictionary<string, string>
        {
            ["api"] = "SYNO.Core.Certificate.Service",
            ["version"] = "1",
            ["method"] = "set",
            ["settings"] = settings.ToJsonString(),
        }, session, ct);
    }

    /// <summary>Ends the session. Best effort: a failed logout only leaves a session
    /// that DSM expires on its own, so errors are swallowed (cancellation is not).</summary>
    public async Task LogoutAsync(DsmSession session, CancellationToken ct)
    {
        try
        {
            await PostAsync("SYNO.API.Auth", new Dictionary<string, string>
            {
                ["api"] = "SYNO.API.Auth",
                ["version"] = session.AuthVersion.ToString(CultureInfo.InvariantCulture),
                ["method"] = "logout",
                ["session"] = SessionName,
            }, session, ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // Session will time out server-side.
        }
    }

    public void Dispose()
    {
        if (_ownsHttp)
        {
            _http.Dispose();
        }
    }

    internal static bool IsLoopback(Uri uri) =>
        uri.IsLoopback || (IPAddress.TryParse(uri.DnsSafeHost, out var ip) && IPAddress.IsLoopback(ip));

    private async Task<int> QueryAuthVersionAsync(CancellationToken ct)
    {
        const string query = "webapi/query.cgi?api=SYNO.API.Info&version=1&method=query&query=SYNO.API.Auth";
        using var response = await SendAsync(() => new HttpRequestMessage(HttpMethod.Get, new Uri(BaseAddress, query)), ct);

        if (IsRedirect(response.StatusCode))
        {
            FollowRedirect(response.Headers.Location);
            using var retried = await SendAsync(() => new HttpRequestMessage(HttpMethod.Get, new Uri(BaseAddress, query)), ct);
            return ParseAuthVersion(await ReadDataAsync(retried, "SYNO.API.Info", ct));
        }
        return ParseAuthVersion(await ReadDataAsync(response, "SYNO.API.Info", ct));
    }

    private static int ParseAuthVersion(JsonElement data)
    {
        var max = TryProp(data, "SYNO.API.Auth", out var auth) && TryProp(auth, "maxVersion", out var v)
            && v.ValueKind == JsonValueKind.Number && v.TryGetInt32(out var parsed) ? parsed : FallbackAuthVersion;
        return Math.Min(max, MaxSupportedAuthVersion);
    }

    private void FollowRedirect(Uri? location)
    {
        if (location is null)
        {
            throw new DsmApiException("DSM redirected without a location");
        }
        var target = location.IsAbsoluteUri ? location : new Uri(BaseAddress, location);
        if (target.Scheme != Uri.UriSchemeHttps
            || target.Port != DsmHttpsPort
            || !string.Equals(target.Host, BaseAddress.Host, StringComparison.OrdinalIgnoreCase))
        {
            throw new DsmApiException(
                $"DSM redirected to an unexpected address ({target.Scheme}://{target.Host}:{target.Port}); " +
                "configure Dsm:Url with DSM's HTTPS address instead");
        }
        BaseAddress = BaseOf(target);
    }

    private async Task<JsonElement> PostAsync(
        string api, Dictionary<string, string> form, DsmSession? session, CancellationToken ct)
    {
        if (session is not null)
        {
            form["_sid"] = session.Sid;
        }
        using var response = await SendAsync(() =>
        {
            var request = new HttpRequestMessage(HttpMethod.Post, new Uri(BaseAddress, "webapi/entry.cgi"))
            {
                Content = new FormUrlEncodedContent(form),
            };
            if (!string.IsNullOrEmpty(session?.SynoToken))
            {
                request.Headers.Add("X-SYNO-TOKEN", session.SynoToken);
            }
            return request;
        }, ct);
        return await ReadDataAsync(response, api, ct);
    }

    private async Task<HttpResponseMessage> SendAsync(Func<HttpRequestMessage> build, CancellationToken ct)
    {
        using var request = build();
        try
        {
            return await _http.SendAsync(request, ct);
        }
        catch (HttpRequestException ex)
        {
            throw new DsmApiException($"Could not reach DSM at {BaseAddress}: {ex.Message}", ex);
        }
        catch (TaskCanceledException ex) when (!ct.IsCancellationRequested)
        {
            throw new DsmApiException($"DSM at {BaseAddress} did not answer in time", ex);
        }
    }

    /// <summary>Reads DSM's <c>{"success":…,"data":…,"error":{"code":…}}</c> envelope.
    /// Returns <c>data</c> (an object, or <c>default</c> when absent).</summary>
    private static async Task<JsonElement> ReadDataAsync(HttpResponseMessage response, string api, CancellationToken ct)
    {
        if (!response.IsSuccessStatusCode)
        {
            throw new DsmApiException($"DSM API {api} returned HTTP {(int)response.StatusCode}");
        }
        JsonDocument doc;
        try
        {
            doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync(ct));
        }
        catch (JsonException ex)
        {
            throw new DsmApiException($"DSM API {api} returned an unreadable response", ex);
        }
        using (doc)
        {
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
            {
                throw new DsmApiException($"DSM API {api} returned an unreadable response");
            }
            if (!IsTrue(root, "success"))
            {
                var code = TryProp(root, "error", out var err) && TryProp(err, "code", out var c)
                    && c.ValueKind == JsonValueKind.Number && c.TryGetInt32(out var parsed) ? parsed : 0;
                throw new DsmApiException(code, api);
            }
            return TryProp(root, "data", out var data) && data.ValueKind == JsonValueKind.Object ? data.Clone() : default;
        }
    }

    private static DsmCertificate ParseCertificate(JsonElement cert)
    {
        TryProp(cert, "subject", out var subject);
        var services = TryProp(cert, "services", out var svc) && svc.ValueKind == JsonValueKind.Array
            ? svc.EnumerateArray()
                .Where(e => e.ValueKind == JsonValueKind.Object)
                .Select(e => new DsmCertificateService(
                    Str(e, "display_name"), Str(e, "service"), Str(e, "subscriber"), e.GetRawText()))
                .ToList()
            : [];
        var sans = TryProp(subject, "sub_alt_name", out var san) && san.ValueKind == JsonValueKind.Array
            ? san.EnumerateArray()
                .Where(x => x.ValueKind == JsonValueKind.String)
                .Select(x => x.GetString()!)
                .Where(x => x.Length > 0)
                .ToList()
            : [];
        var commonName = Str(subject, "common_name");

        return new DsmCertificate(
            Id: Str(cert, "id"),
            Description: Str(cert, "desc"),
            IsDefault: IsTrue(cert, "is_default"),
            CommonName: commonName.Length == 0 ? null : commonName,
            SubjectAltNames: sans,
            ValidTill: ParseOpenSslDate(Str(cert, "valid_till")),
            Services: services);
    }

    /// <summary>DSM reports dates as OpenSSL text: <c>Jan 30 23:59:59 2027 GMT</c>
    /// (single-digit days are space-padded).</summary>
    internal static DateTimeOffset? ParseOpenSslDate(string value)
    {
        var compact = Whitespace().Replace(value.Trim(), " ");
        return DateTimeOffset.TryParseExact(compact, "MMM d HH:mm:ss yyyy 'GMT'", CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal, out var parsed) ? parsed : null;
    }

    private static bool TryProp(JsonElement obj, string name, out JsonElement value)
    {
        if (obj.ValueKind == JsonValueKind.Object && obj.TryGetProperty(name, out value))
        {
            return true;
        }
        value = default;
        return false;
    }

    // DSM is loose with types: booleans arrive as true, "true" or 1.
    private static bool IsTrue(JsonElement obj, string name) =>
        TryProp(obj, name, out var v) && v.ValueKind switch
        {
            JsonValueKind.True => true,
            JsonValueKind.String => string.Equals(v.GetString(), "true", StringComparison.OrdinalIgnoreCase),
            JsonValueKind.Number => v.TryGetInt32(out var n) && n != 0,
            _ => false,
        };

    private static string Str(JsonElement obj, string name) =>
        !TryProp(obj, name, out var v) ? "" : v.ValueKind switch
        {
            JsonValueKind.String => v.GetString() ?? "",
            JsonValueKind.Number => v.GetRawText(),
            _ => "",
        };

    /// <summary>
    /// The import upload, byte for byte in the shape acme.sh sends and DSM's CGI
    /// parser accepts: an unquoted boundary, quoted name/filename without an RFC 5987
    /// <c>filename*</c>, file parts typed application/octet-stream and text parts
    /// untyped. DSM answers .NET's default <see cref="MultipartFormDataContent"/>
    /// encoding with error 108 ("failed to upload the file").
    /// </summary>
    private static ByteArrayContent ImportBody(
        DsmCertificateMaterial material, string? replaceId, string description, bool asDefault)
    {
        var boundary = "CertadelBoundary" + Guid.NewGuid().ToString("N");
        var body = new System.Text.StringBuilder();
        void File(string name, string fileName, string pem) => body
            .Append("--").Append(boundary).Append("\r\n")
            .Append("Content-Disposition: form-data; name=\"").Append(name)
            .Append("\"; filename=\"").Append(fileName).Append("\"\r\n")
            .Append("Content-Type: application/octet-stream\r\n\r\n")
            .Append(pem).Append("\r\n");
        void Field(string name, string value) => body
            .Append("--").Append(boundary).Append("\r\n")
            .Append("Content-Disposition: form-data; name=\"").Append(name).Append("\"\r\n\r\n")
            .Append(value).Append("\r\n");

        File("key", "privkey.pem", material.PrivateKeyPem);
        File("cert", "cert.pem", material.CertificatePem);
        if (material.IntermediatesPem.Length > 0)
        {
            File("inter_cert", "chain.pem", material.IntermediatesPem);
        }
        Field("id", replaceId ?? "");
        // A line break would end the field early and corrupt the upload.
        Field("desc", description.ReplaceLineEndings(" "));
        if (asDefault)
        {
            Field("as_default", "true");
        }
        body.Append("--").Append(boundary).Append("--\r\n");

        var content = new ByteArrayContent(System.Text.Encoding.UTF8.GetBytes(body.ToString()));
        content.Headers.TryAddWithoutValidation("Content-Type", $"multipart/form-data; boundary={boundary}");
        return content;
    }

    private static bool IsRedirect(HttpStatusCode status) => (int)status is >= 300 and < 400;

    // Rebuilt from parts so any user-info in the source never survives into the base address.
    private static Uri BaseOf(Uri uri) => new UriBuilder(uri.Scheme, uri.Host, uri.Port).Uri;

    private static HttpClient CreateHttpClient(Uri baseAddress)
    {
        var tolerateCertificateErrors = IsLoopback(baseAddress);
        var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            UseCookies = false,
            SslOptions = new SslClientAuthenticationOptions
            {
                RemoteCertificateValidationCallback = (_, _, _, errors) =>
                    errors == SslPolicyErrors.None || tolerateCertificateErrors,
            },
        };
        return new HttpClient(handler) { Timeout = RequestTimeout };
    }

    [GeneratedRegex(@"\s+")]
    private static partial Regex Whitespace();
}
