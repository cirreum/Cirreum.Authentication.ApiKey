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
  - `ApiKeyProviderState` (per-host scheme-claim + cross-instance key-uniqueness guard)
  - `ApiKeyValidationOptions`, `ApiKeyCachingOptions`
- **NEW — `CredentialTransport.BearerAuthorizationHeader`:**
  - `ApiKeyClient.AcceptedTransports` defaults to `BearerAuthorizationHeader` (RFC 6750 alignment, lower friction for partner tooling).
  - One ASP.NET scheme per `(Provider, Transport)` tuple; each scheme handler reads exactly one source (`options.Transport`). An instance declares exactly one transport (enforced by the registrar) — split a multi-transport client into separate instances.
  - Token-shape disambiguation routes JWT-pattern values to JWT-Bearer schemes; opaque values route to ApiKey selectors. An optional per-provider `BearerPrefix` (`ak_{env}_`) lets multiple Bearer-probing providers coexist.
- **NEW — `ApiKeyAuthenticationSchemeSelector` implements `ISchemeSelector`** with `SchemeCategory.Machine`. Replaces the legacy `AuthorizationSchemeRegistry` header-to-scheme dispatch.
- **NEW — `AddApiKey(...)` unified composition verb** on `IAuthenticationBuilder`, the single app-facing entry point for the ApiKey provider (app-composed inside `AddAuthentication(...)`; no longer auto-registered by the umbrella package):
  - `ApiKeyTransports` + `ApiKeySchemes` constants — the IntelliSense-discoverable transport/scheme names (`ApiKey:Bearer`, `ApiKey:X-Api-Key`, …).
  - `ApiKeyOptions` with three composition modes — bare `AddApiKey()` registers all well-known transports (mode A); `AddTransport(...)` selects an explicit subset (mode B); `AddCustomHeaderTransport(...)` is the non-standard-header escape hatch (mode C).
  - `AddResolver<T>(caching?)` folds the former `AddDynamicApiKeys<T>` into the options — when configured instances also exist, the configuration resolver is composed ahead of the dynamic one via `CompositeApiKeyClientResolver`.
  - `NullApiKeyClientResolver` — fallback for orphaned transports (a declared transport with no validation source) so they return 401 cleanly; the boot-time auth-posture analyzer flags them.

### Security

Adversarial hardening pass (ADR-0020). No authentication bypass was found in the core verify path; the changes below close defects in hashing defaults, caching, revocation availability, and resolver correctness, and add the first test coverage.

- **Two-forms model** — dropped the conformance-profile concept. *Configured* (Form 1) keys are strength-checked at startup (length + 112-bit entropy floor) and fail fast unless `Validation:AllowWeakConfiguredKeys` (off by default); *managed* (Form 2) keys are 256-bit by construction. `AddDynamicStore<TResolver>(name)` no longer takes a profile.
- **Fail-closed hash verification** — `VerifyKey` rejects any stored value that is not self-describing (the legacy bare-SHA-256 fallback is gone) and dispatches to exactly one hasher by the encoded algorithm tag (`sha256$` / `pbkdf2$`), foreclosing algorithm confusion. Request-time entropy gating removed (it was a structural oracle); entropy is an issuance-time concern only.
- **Fail-closed revocation hydration** — a faulted boot hydration leaves the denylist not-authoritative: ApiKey auth returns a retryable `503`, a `Critical` log is emitted, and the new `apikey-revocation` health check reports `Unhealthy`. Opt out with `Revocation:AllowFaultedDenylist` (off by default). Auth is gated on hydration completion (closes the startup race).
- **Bounded denylist** — `IApiKeyDenylist.Revoke(id, expiresAt?)` with evict-on-credential-expiry and a `Revocation:MaxDenylistEntries` cap that refuses (with `Critical`) rather than evicting a live entry or silently dropping.
- **Resolver correctness** — `ApiKeyResolveResult` gains a typed `Outcome` discriminator (the composite chain branches on it, not on free-text); a throwing resolver fails closed to a miss (never a `500`); the caching cache key includes the routing dimension (`X-Api-Source`) and negative caching now defaults **off**.
- **Reserved-claim guard** — custom client claims can no longer shadow `client_type` / `scope` / name / role / identifier.
- **Per-host state** — cross-instance key-uniqueness moved off a process-static dictionary onto `ApiKeyProviderState`.
- **Tests** — new `Cirreum.Authentication.ApiKey.Tests` (84 tests): constant-time compare, fail-closed hash dispatch, two-forms strength, revocation gate + denylist, resolver chain + dispatch, the handler's fail-closed posture and status mapping, and input fuzzing.

### Migration

Apps consuming `Cirreum.Authorization.ApiKey` migrate by installing `Cirreum.Authentication.ApiKey` and switching their composition root from `AddAuthorization(authz => authz.AddApiKey(...))` to `AddAuthentication(auth => auth.AddApiKey(...))`. The old `Cirreum.Authorization.ApiKey` package deprecates on NuGet with a successor message pointing here. See [`docs/MIGRATION-v1.md`](MIGRATION-v1.md).
