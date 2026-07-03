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

> **Beyond the rename, ApiKey was substantially hardened and reworked** (two adversarial passes, ADR-0020). Your existing API keys still authenticate — it is still an API-key-in-a-header scheme — but the **registration/composition API changed**. Review the items below and the [`CHANGELOG.md`](CHANGELOG.md) for the full surface.

## New / Changed Capabilities

**Two-forms source model.** Dynamic key stores are now registered as **sources**: `AddDefaultSource<T>(...)` (reached without a routing header) and `AddNamedSource<T>(name, ...)` (addressable via `X-Api-Source`). The `ApiKeySourceDispatcher` composes configured (appsettings) keys + the default source + named sources in one engine — **the old `CompositeApiKeyClientResolver` is gone** (replaced by the dispatcher). *Configured* keys are startup strength-checked (length + 112-bit entropy; opt out with `Validation:AllowWeakConfiguredKeys`); *managed* source keys are 256-bit by construction.

**Transport model.** `AddApiKey()` accepts all well-known transports; `AcceptTransports(...)` restricts to a subset; `AddCustomTransport(headerName)` additively layers a non-standard header. Credentials now also accept `Authorization: Bearer {key}` (RFC 6750), and there is one ASP.NET scheme per `(Provider, Transport)` tuple. An optional per-provider `BearerPrefix` (`ak_{env}_`) lets multiple Bearer-probing providers coexist.

**Revocation.** `IApiKeyDenylist.Revoke(id, expiresAt?)` with a bounded denylist; a faulted boot hydration fails closed (auth returns `503`, the `apikey-revocation` health check reports `Unhealthy`) unless `Revocation:AllowFaultedDenylist`.

**Single security chokepoint.** Key expiry / cryptoperiod and revocation are enforced on the non-replaceable `ApiKeyAuthenticationHandler` after every resolution — a custom resolver or a cache hit can no longer authenticate an expired or revoked credential.

**Selector-based dispatch.** The legacy `AuthorizationSchemeRegistry` header-to-scheme map is retired for `ApiKeyAuthenticationSchemeSelector` (`ISchemeSelector`, `SchemeCategory.Machine`).

## Migration Walkthrough

1. **Update `<PackageReference>` entries** in your csproj — replace `Cirreum.Authorization.ApiKey` with `Cirreum.Authentication.ApiKey`. Bump the version to `1.0.0`.
2. **Apply the find/replace table above** across your codebase.
3. **Update `appsettings.json`** — rename the configuration root from `Cirreum:Authorization:Providers:ApiKey` to `Cirreum:Authentication:Providers:ApiKey`. Instance keys (e.g., `Instances:partnerA`) are unchanged.
4. **Move the `AddApiKey` call** out of the `AddAuthorization(...)` builder and into a new `AddAuthentication(...)` builder. The two pillars are now configured separately at the composition root.
5. **(Optional) Adopt `Authorization: Bearer` transport** for new partners. Existing partners continue using the custom-header transport unchanged.
6. **Rebuild and verify.** The deprecation message on the old `Cirreum.Authorization.ApiKey` NuGet package points here for additional context.

## What Didn't Change

- **Your existing API keys still authenticate** — the credential model and the core hash-compare verify path are preserved (constant-time compare, PBKDF2 for imported low-entropy secrets).
- The `ApiKeyClient` core data shape (`ClientId`, `ClientName`, `Roles`) is preserved (extended with `CreatedAt` / `ExpiresAt` / `MaxKeyAge` for the expiry seam).
- The configuration binding (instance keys = scheme names) is preserved.
- The `Configuration` / `Dynamic` / `Caching` `IApiKeyClientResolver` implementations remain; only the `Composite` resolver was replaced (by `ApiKeySourceDispatcher`).
- ASP.NET Core authentication scheme registration via `AuthenticationBuilder` is preserved.

## Downstream Package Impact

- **`Cirreum.AuthorizationProvider`** — the auth-pillar abstractions (`HeaderAuthorizationProviderRegistrar`, instance settings base) move to `Cirreum.AuthenticationProvider`. The old `Cirreum.AuthorizationProvider` retains authorization-only content for its 2.0.0 release.
- **`Cirreum.Runtime.Authorization`** — splits into `Cirreum.Runtime.Authentication` (new) + `Cirreum.Runtime.Authorization 2.0.0` (scoped down). Apps install both alongside.
