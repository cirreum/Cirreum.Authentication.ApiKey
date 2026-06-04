# Cirreum.Authentication.ApiKey 1.0.0 — Renamed home for the ApiKey scheme

## Why this release exists

`Cirreum.Authorization.ApiKey` ships an authentication scheme — every handler in it is named `ApiKey*AuthenticationHandler` — but the package name placed it in the Authorization pillar. The **Cirreum 1.0 Foundation Reset** corrects this by recognizing Authentication as a first-class security pillar and moving the scheme packages to their proper home.

This is the rename release. The package gains two new capabilities along the way while preserving the configuration shape and resolver family that consumers depend on.

## What's new

### `Authorization: Bearer` transport

ApiKey credentials accept `Authorization: Bearer {key}` in addition to the legacy custom-header transport. This is RFC 6750-aligned and lowers friction for partner tooling that already speaks Bearer for OAuth bearer flows. Custom-header transport remains supported for existing partners.

```csharp
// New: per-credential transport preference
public sealed record ApiKeyClient {
    public required string ClientId { get; init; }
    public required string Key { get; init; }
    public CredentialTransport AcceptedTransports { get; init; }
        = CredentialTransport.BearerAuthorizationHeader; // default
    public string? CustomHeaderName { get; init; }      // when CustomHeader transport accepted
    // ... existing properties
}
```

Token-shape disambiguation routes JWT-pattern values (three base64url segments separated by dots) to JWT-Bearer schemes; opaque values route to ApiKey selectors.

### Selector-based dispatch

The legacy `AuthorizationSchemeRegistry` header-to-scheme map is replaced by `ApiKeyAuthenticationSchemeSelector` — an `ISchemeSelector` implementation with `SchemeCategory.Machine`. The dynamic forward resolver picks ApiKey based on request inspection rather than a static registry lookup. New schemes register without touching existing resolver code.

## How it pairs with the rest of the Authentication pillar

| Package | Role |
|---|---|
| `Cirreum.Kernel` | Versioned-message primitive, `INotification` markers, auth event bus, `AuthenticationContextKeys` |
| `Cirreum.AuthenticationProvider` | Registrar bases, `ISchemeSelector`, `SchemeCategory`, `CredentialTransport` |
| **`Cirreum.Authentication.ApiKey`** *(this release)* | ApiKey scheme handler + resolvers + selector |
| `Cirreum.Runtime.AuthenticationProvider` | Dynamic forward resolver, selector iteration |
| `Cirreum.Runtime.Authentication` | App-facing `AddAuthentication(...)` builder |

Apps install via the umbrella package: `builder.AddAuthentication(auth => auth.AddApiKey(...))`.

## Compatibility

- **.NET 10.0** target.
- **Cirreum.Providers 1.2.0+** required (adds `ProviderType.Authentication` enum value).
- **Cirreum.AuthenticationProvider 1.0.0+** required.
- Apps migrating from `Cirreum.Authorization.ApiKey` follow [`MIGRATION-v1.md`](MIGRATION-v1.md).

## See also

- [`MIGRATION-v1.md`](MIGRATION-v1.md) — step-by-step migration walkthrough
- [`CHANGELOG.md`](CHANGELOG.md) — full release notes
