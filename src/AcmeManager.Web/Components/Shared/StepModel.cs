namespace AcmeManager.Web.Components.Shared;

/// <summary>
/// Form-bound model for one plugin step in the new-renewal page: a plugin id
/// + raw JSON options the user can edit. Kept in <c>Components/Shared</c>
/// because both the form and the picker cards bind to it.
/// </summary>
public sealed class StepModel
{
    public string PluginId { get; set; } = "";

    public string OptionsJson { get; set; } = "{}";
}