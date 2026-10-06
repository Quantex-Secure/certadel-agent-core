namespace AcmeManager.Service.Api.V1;

/// <summary>
/// Audit trail for the management API. Every mutating call (anything but
/// GET/HEAD/OPTIONS) is logged with the authenticated principal, its scheme, the
/// client address, the route, and the outcome — so "who created the renewal
/// that runs this script as SYSTEM" is always answerable. Runs after
/// authorization, so the principal is the one the policy admitted.
/// </summary>
public sealed class ManagementApiAuditFilter(ILogger<ManagementApiAuditFilter> logger) : IEndpointFilter
{
    public async ValueTask<object?> InvokeAsync(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
    {
        var http = context.HttpContext;
        var method = http.Request.Method;
        if (HttpMethods.IsGet(method) || HttpMethods.IsHead(method) || HttpMethods.IsOptions(method))
        {
            return await next(context);
        }

        var user = http.User.Identity?.Name ?? "(unknown)";
        var scheme = http.User.Identity?.AuthenticationType ?? "-";
        var client = http.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        var path = http.Request.Path + http.Request.QueryString;

        try
        {
            var result = await next(context);
            var status = (result as IStatusCodeHttpResult)?.StatusCode ?? http.Response.StatusCode;
            logger.LogInformation(
                "Management API audit: {User} ({Scheme}) from {Client} {Method} {Path} -> {Status}",
                user, scheme, client, method, path, status);
            return result;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogError(ex,
                "Management API audit: {User} ({Scheme}) from {Client} {Method} {Path} -> threw",
                user, scheme, client, method, path);
            throw;
        }
    }
}