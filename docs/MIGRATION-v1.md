# Migration to Cirreum.Authentication.ApiKey v1.0

**From:** `Cirreum.Authorization.ApiKey 1.0.x` (now deprecated)
**To:** `Cirreum.Authentication.ApiKey 1.0.0`

## Why v1

`Cirreum.Authentication.ApiKey` is a renamed-and-rebuilt successor to the deprecated `Cirreum.Authorization.ApiKey`. The rename brings the package name in line with what it actually does — every handler type was already named `ApiKey*AuthenticationHandler` / `ApiKey*AuthenticationOptions`; only the package name was misclassified.

The rename is one step in the broader **Cirreum 1.0 Foundation Reset**, which recognizes Authentication as a first-class security pillar distinct from Authorization. Authentication asks "who is the caller?"; Authorization asks "what may an authenticated caller do?" Conflating the two in one package family caused the rename.

## Breaking Changes — Find/Replace Table

| Before (`Cirreum.Authorization.ApiKey`) | After (`Cirreum.Authentication.ApiKey`) |
|---|---|
| `using Cirreum.Authorization.ApiKey;` | `using Cirreum.Authentication.ApiKey;` |
| `using Cirreum.Authorization.ApiKey.Configuration;` | `using Cirreum.Authentication.ApiKey.Configuration;` |
| `ApiKeyAuthorizationRegistrar` | `ApiKeyAuthenticationRegistrar` |
| `ApiKeyAuthorizationInstanceSettings` | `ApiKeyAuthenticationInstanceSettings` |
| `ApiKeyAuthorizationSettings` | `ApiKeyAuthenticationSettings` |
| `AddAuthorization(authz => authz.AddApiKey(...))` | `AddAuthentication(auth => auth.AddApiKey(...))` |
| `Cirreum:Authorization:Providers:ApiKey:Instances:{name}` | `Cirreum:Authentication:Providers:ApiKey:Instances:{name}` |

## New Capabilities

**`Authorization: Bearer` transport.** ApiKey credentials now accept `Authorization: Bearer {key}` in addition to the legacy custom-header transport. New `ApiKeyClient` defaults to `AcceptedTransports = CredentialTransport.BearerAuthorizationHeader`; existing custom-header consumers explicitly opt in via `AcceptedTransports = CredentialTransport.CustomHeader` and `CustomHeaderName = "X-Api-Key"`.

**Selector-based dispatch.** The legacy `AuthorizationSchemeRegistry` header-to-scheme map is retired. The package ships an `ApiKeyAuthenticationSchemeSelector` implementing `ISchemeSelector` with `SchemeCategory.Machine` — the dynamic forward resolver picks ApiKey by inspecting the request for Bearer or custom-header indicators, then dispatches to the matching scheme.

## Migration Walkthrough

1. **Update `<PackageReference>` entries** in your csproj — replace `Cirreum.Authorization.ApiKey` with `Cirreum.Authentication.ApiKey`. Bump the version to `1.0.0`.
2. **Apply the find/replace table above** across your codebase.
3. **Update `appsettings.json`** — rename the configuration root from `Cirreum:Authorization:Providers:ApiKey` to `Cirreum:Authentication:Providers:ApiKey`. Instance keys (e.g., `Instances:partnerA`) are unchanged.
4. **Move the `AddApiKey` call** out of the `AddAuthorization(...)` builder and into a new `AddAuthentication(...)` builder. The two pillars are now configured separately at the composition root.
5. **(Optional) Adopt `Authorization: Bearer` transport** for new partners. Existing partners continue using the custom-header transport unchanged.
6. **Rebuild and verify.** The deprecation message on the old `Cirreum.Authorization.ApiKey` NuGet package points here for additional context.

## What Didn't Change

- The `ApiKeyClient` data shape (`ClientId`, `ClientName`, `Roles`, etc.) is preserved.
- The configuration binding (instance keys = scheme names) is preserved.
- The `IApiKeyClientResolver` family (configuration / dynamic / caching / composite) is preserved.
- The `ApiKeyAuthenticationHandler` validates credentials the same way; only the transport-reading prelude is extended.
- ASP.NET Core authentication scheme registration via `AuthenticationBuilder` is preserved.

## Downstream Package Impact

- **`Cirreum.AuthorizationProvider`** — the auth-pillar abstractions (`HeaderAuthorizationProviderRegistrar`, instance settings base) move to `Cirreum.AuthenticationProvider`. The old `Cirreum.AuthorizationProvider` retains authorization-only content for its 2.0.0 release.
- **`Cirreum.Runtime.Authorization`** — splits into `Cirreum.Runtime.Authentication` (new) + `Cirreum.Runtime.Authorization 2.0.0` (scoped down). Apps install both alongside.
