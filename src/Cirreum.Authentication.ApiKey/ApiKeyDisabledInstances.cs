namespace Cirreum.Authentication.ApiKey;

/// <summary>
/// The configured ApiKey instance names that were bound but left disabled, captured during
/// composition for the boot-time advisory. Empty unless every declared instance is disabled.
/// </summary>
/// <param name="Names">The declared instance names, ordered.</param>
internal sealed record ApiKeyDisabledInstances(IReadOnlyList<string> Names);
