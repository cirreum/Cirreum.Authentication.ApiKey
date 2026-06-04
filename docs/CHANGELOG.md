# Cirreum.Authentication.ApiKey Changelog

All notable changes to **Cirreum.Authentication.ApiKey** are documented in this file.

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) — [SemVer](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added

- Initial release. Cirreum.Authentication.ApiKey is the ApiKey authentication scheme of the Cirreum framework, established as part of the **Cirreum 1.0 Foundation Reset** wave.
- **Renamed and re-homed from the deprecated `Cirreum.Authorization.ApiKey`** under the Three Security Pillars separation. The scheme is unambiguously authentication content (every handler type was already named `ApiKey*AuthenticationHandler` / `ApiKey*AuthenticationOptions`) — the rename brings the package name in line with what it actually does.
- **ApiKey scheme content absorbed from former `Cirreum.AuthorizationProvider.ApiKey`:**
  - `IApiKeyClientResolver` + `ConfigurationApiKeyClientResolver` / `DynamicApiKeyClientResolver` / `CachingApiKeyClientResolver` / `CompositeApiKeyClientResolver`
  - `ApiKeyClient`, `ApiKeyResolveResult`, `ApiKeyLookupContext`, `StoredApiKey`
  - `IApiKeyValidator` + `DefaultApiKeyValidator`
  - `ApiKeyClientRegistry` + `ApiKeyClientEntry`
  - `ApiKeyValidation` (cross-instance uniqueness guard)
  - `ApiKeyValidationOptions`, `ApiKeyCachingOptions`
- **NEW — `CredentialTransport.AuthorizationBearer`:**
  - `ApiKeyClient.AcceptedTransports` defaults to `BearerAuthorizationHeader` (RFC 6750 alignment, lower friction for partner tooling).
  - `ApiKeyClient.CustomHeaderName` controls the header name when `CustomHeader` transport is accepted.
  - `ApiKeyAuthenticationHandler` reads from both transports (Bearer first, custom header fallback) when both are configured.
  - Token-shape disambiguation routes JWT-pattern values to JWT-Bearer schemes; opaque values route to ApiKey selectors.
- **NEW — `ApiKeyAuthenticationSchemeSelector` implements `ISchemeSelector`** with `SchemeCategory.Machine`. Replaces the legacy `AuthorizationSchemeRegistry` header-to-scheme dispatch.
- **NEW — `AddApiKey(...)` unified composition verb** on `IAuthenticationBuilder`, the single app-facing entry point for the ApiKey provider (app-composed inside `AddAuthentication(...)`; no longer auto-registered by the umbrella package):
  - `ApiKeyTransports` + `ApiKeySchemes` constants — the IntelliSense-discoverable transport/scheme names (`ApiKey:Bearer`, `ApiKey:X-Api-Key`, …).
  - `ApiKeyOptions` with three composition modes — bare `AddApiKey()` registers all well-known transports (mode A); `AddTransport(...)` selects an explicit subset (mode B); `AddCustomHeaderTransport(...)` is the non-standard-header escape hatch (mode C).
  - `AddResolver<T>(caching?)` folds the former `AddDynamicApiKeys<T>` into the options — when configured instances also exist, the configuration resolver is composed ahead of the dynamic one via `CompositeApiKeyClientResolver`.
  - `NullApiKeyClientResolver` — fallback for orphaned transports (a declared transport with no validation source) so they return 401 cleanly; the boot-time auth-posture analyzer flags them.

### Migration

Apps consuming `Cirreum.Authorization.ApiKey` migrate by installing `Cirreum.Authentication.ApiKey` and switching their composition root from `AddAuthorization(authz => authz.AddApiKey(...))` to `AddAuthentication(auth => auth.AddApiKey(...))`. The old `Cirreum.Authorization.ApiKey` package deprecates on NuGet with a successor message pointing here. See [`docs/MIGRATION-v1.md`](MIGRATION-v1.md).
