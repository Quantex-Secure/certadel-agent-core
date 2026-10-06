using System.Net.Http.Json;

using AcmeManager.Plugins.Contracts;
using AcmeManager.Plugins.Contracts.Notification;

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace AcmeManager.Core.Notifications;

/// <summary>
/// The built-in <see cref="INotifier"/>: POSTs each alert as JSON to
/// <see cref="NotificationOptions.WebhookUrl"/>. A no-op while the URL is blank,
/// so it is always registered and switched on purely by configuration.
/// </summary>
public sealed class WebhookNotifier(
    IHttpClientFactory httpClientFactory,
    IOptions<NotificationOptions> options,
    ILogger<WebhookNotifier> logger) : INotifier
{
    public const string HttpClientName = "acme-manager-webhook";

    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(15);

    public PluginMetadata Metadata { get; } = new(
        Id: "notifier.webhook",
        Name: "Webhook",
        Description: "POSTs renewal alerts as JSON to Notifications:WebhookUrl.",
        Category: PluginCategory.Notification,
        Version: new Version(1, 0, 0));

    public async ValueTask NotifyAsync(NotificationEvent evt, CancellationToken ct)
    {
        var url = options.Value.WebhookUrl;
        if (string.IsNullOrWhiteSpace(url))
        {
            return;
        }
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri)
            || (uri.Scheme != Uri.UriSchemeHttps && uri.Scheme != Uri.UriSchemeHttp))
        {
            logger.LogWarning("Notifications:WebhookUrl '{Url}' is not an absolute http(s) URL; alert not sent.", url);
            return;
        }

        using var http = httpClientFactory.CreateClient(HttpClientName);
        http.Timeout = Timeout;

        var text = $"{evt.Subject}\n{evt.Body}";
        var payload = new
        {
            subject = evt.Subject,
            body = evt.Body,
            level = evt.Level.ToString(),
            at = evt.At,
            text,      // Slack / Mattermost / Rocket.Chat incoming webhooks
            content = text, // Discord
        };

        using var response = await http.PostAsJsonAsync(uri, payload, ct);
        response.EnsureSuccessStatusCode();
        logger.LogInformation("Webhook alert '{Subject}' delivered ({Status}).", evt.Subject, (int)response.StatusCode);
    }
}