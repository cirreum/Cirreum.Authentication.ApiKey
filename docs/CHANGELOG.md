# Cirreum.Authentication.ApiKey Changelog

All notable changes to **Cirreum.Authentication.ApiKey** are documented in this file.

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) — [SemVer](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Updated

- Updated NuGet packages.

## [1.0.6] - 2026-07-19

### Updated

- Updated NuGet packages.

## [1.0.5] - 2026-07-18

### Fixed

- **`AddApiKey()` no longer throws `ArgumentException` at composition time.** The PBKDF2 hasher was
  registered with the single-generic factory overload (`ServiceDescriptor.Singleton<IApiKeyHasher>(factory)`),
  which reports the service type as its own implementation type — `TryAddEnumerable` rejects such
  descriptors as indistinguishable, so every `AddApiKey(...)` call (bare or configured) threw before
  `Build()`, making the provider uncomposable in 1.0.0 through 1.0.4 (GitHub issue #1). The registration
  now uses the two-generic overload (`Singleton<IApiKeyHasher, Pbkdf2ApiKeyHasher>(factory)`), preserving
  the lazy options-driven work-factor wiring. Adds the package's first composition-path coverage:
  `AddApiKey()` on a bare host must compose, must yield both self-describing hashers from the container,
  and the call-twice guard must surface as `InvalidOperationException`.

## [1.0.4] - 2026-07-07

### Updated

- Updated NuGet packages. *(Entry backfilled — the 1.0.3/1.0.4 dependency-bump releases shipped without
  changelog entries.)*

## [1.0.3] - 2026-07-06

### Updated

- Updated NuGet packages. *(Entry backfilled.)*

## [1.0.2] - 2026-07-05

### Fixed

- **`ApiKeyCredentialRevokedHandler` now threads the revoked credential's expiry into the denylist.**
  It called `IApiKeyDenylist.Revoke(evt.CredentialId)` and dropped `CredentialRevoked.ExpiresAt`, so
  every event-driven revocation was recorded with no expiry — a "retain until restart" entry that could
  never be safely evicted, even after the credential's own expiry made it dead weight. Now passes
  `evt.ExpiresAt`, so the denylist reclaims the entry once the credential can no longer authenticate
  (the widen-only, never-evict-a-live-entry safety rules are unchanged). No behavioral change for a
  revoked credential's authentication outcome — only denylist memory hygiene. Adds the handler's first
  test coverage (expiry threading, credential-type filtering, null-safety).

## [1.0.1] - 2026-07-04

### Updated

- Updated NuGet packages.

## [1.0.0] - 2026-07-03

### Added

- Initial release. Cirreum.Authentication.ApiKey is the ApiKey authentication scheme of the Cirreum framework, established as part of the **Cirreum 1.0 Foundation Reset** wave.
- **Renamed and re-homed from the deprecated `Cirreum.Authorization.ApiKey`** under the Three Security Pillars separation. The scheme is unambiguously authentication content (every handler type was already named `ApiKey*AuthenticationHandler` / `ApiKey*AuthenticationOptions`) — the rename brings the package name in line with what it actually does.
- **ApiKey scheme content absorbed from former `Cirreum.AuthorizationProvider.ApiKey`:**
  - `IApiKeyClientResolver` + `ConfigurationApiKeyClientResolver` / `DynamicApiKeyClientResolver` / `CachingApiKeyClientResolver` (the multi-source composite is now the `ApiKeySourceDispatcher`, below)
  - `ApiKeyClient`, `ApiKeyResolveResult`, `ApiKeyLookupContext`, `StoredApiKey`
  - `IApiKeyValidator` + `DefaultApiKeyValidator`
  - `ApiKeyClientRegistry` + `ApiKeyClientEntry`
  - `ApiKeyProviderState` (per-host scheme-claim + cross-instance key-uniqueness guard)
  - `ApiKeyValidationOptions`, `ApiKeySourceCachingOptions`
- **NEW — `CredentialTransport.BearerAuthorizationHeader`:**
  - `ApiKeyClient.AcceptedTransports` defaults to `BearerAuthorizationHeader` (RFC 6750 alignment, lower friction for partner tooling).
  - One ASP.NET scheme per `(Provider, Transport)` tuple; each scheme handler reads exactly one source (`options.Transport`). An instance declares exactly one transport (enforced by the registrar) — split a multi-transport client into separate instances.
  - Token-shape disambiguation routes JWT-pattern values to JWT-Bearer schemes; opaque values route to ApiKey selectors. An optional per-provider `BearerPrefix` (`ak_{env}_`) lets multiple Bearer-probing providers coexist.
- **NEW — `ApiKeyAuthenticationSchemeSelector` implements `ISchemeSelector`** with `SchemeCategory.Machine`. Replaces the legacy `AuthorizationSchemeRegistry` header-to-scheme dispatch.
- **NEW — `AddApiKey(...)` unified composition verb** on `IAuthenticationBuilder`, the single app-facing entry point for the ApiKey provider (app-composed inside `AddAuthentication(...)`; no longer auto-registered by the umbrella package):
  - `ApiKeyTransports` + `ApiKeySchemes` constants — the IntelliSense-discoverable transport/scheme names (`ApiKey:Bearer`, `ApiKey:X-Api-Key`, …).
  - `ApiKeyOptions` transport selection — bare `AddApiKey()` accepts all well-known transports (the `ApiKeyTransport` enum); `AcceptTransports(...)` restricts to a subset (empty clears them); `AddCustomTransport(headerName)` additively accepts a non-standard header on top of the active set.
  - `AddDefaultSource<T>(requireClientId?, caching?)` and `AddNamedSource<T>(name, requireClientId?, caching?)` register dynamic API key sources — the default source is reached without `X-Api-Source`; named sources are addressable-only. The `ApiKeySourceDispatcher` tries configured instances first, then the default source, and routes `X-Api-Source` to named sources — composing them in one engine (no separate composite).
  - Orphan transports (a declared transport with no source behind it) resolve to a clean 401 via the dispatcher; the boot-time auth-posture analyzer flags them.

### Security

Adversarial hardening pass (ADR-0020). No authentication bypass was found in the core verify path; the changes below close defects in hashing defaults, caching, revocation availability, and resolver correctness, and add the first test coverage.

- **Two-forms model** — dropped the conformance-profile concept. *Configured* (Form 1) keys are strength-checked at startup (length + 112-bit entropy floor) and fail fast unless `Validation:AllowWeakConfiguredKeys` (off by default); *managed* (Form 2) keys are 256-bit by construction, registered via `AddDefaultSource` / `AddNamedSource`.
- **Fail-closed hash verification** — `VerifyKey` rejects any stored value that is not self-describing (the legacy bare-SHA-256 fallback is gone) and dispatches to exactly one hasher by the encoded algorithm tag (`sha256$` / `pbkdf2$`), foreclosing algorithm confusion. Request-time entropy gating removed (it was a structural oracle); entropy is an issuance-time concern only.
- **Fail-closed revocation hydration** — a faulted boot hydration leaves the denylist not-authoritative: ApiKey auth returns a retryable `503`, a `Critical` log is emitted, and the new `apikey-revocation` health check reports `Unhealthy`. Opt out with `Revocation:AllowFaultedDenylist` (off by default). Auth is gated on hydration completion (closes the startup race).
- **Bounded denylist** — `IApiKeyDenylist.Revoke(id, expiresAt?)` with evict-on-credential-expiry and a `Revocation:MaxDenylistEntries` cap that refuses (with `Critical`) rather than evicting a live entry or silently dropping.
- **Resolver correctness** — `ApiKeyResolveResult` gains a typed `Outcome` discriminator (the dispatcher branches on it, not on free-text); an addressed source is authoritative (no silent fall-through to the default); a throwing source fails closed to a miss (never a `500`); the caching cache key includes the routing dimension (`X-Api-Source`) and negative caching now defaults **off**; a source may require an `X-Client-Id` index (a missing index is a non-descript `400`, so resolvers do indexed lookups rather than scans).
- **Reserved-claim guard** — custom client claims can no longer shadow `client_type` / `scope` / name / role / identifier.
- **Per-host state** — cross-instance key-uniqueness moved off a process-static dictionary onto `ApiKeyProviderState`.
- **Tests** — new `Cirreum.Authentication.ApiKey.Tests`: constant-time compare, fail-closed hash dispatch, two-forms strength, revocation gate + denylist, source dispatch (config-first, authoritative routing, the client-id gate), the handler's fail-closed posture and status mapping, and input fuzzing.

#### Second adversarial pass — RFC + NIST/FIPS hardening

A second review (RFC 6750/7235/9110 conformity and NIST/FIPS-grade posture, tolerating that an app may dial down) confirmed no authentication bypass and closed the items below. **136 tests.**

- **Single security chokepoint** — key expiry / cryptoperiod and revocation are now enforced by the (non-replaceable) `ApiKeyAuthenticationHandler` after *every* resolution, not inside the optional resolver base class. A custom `IApiKeyClientResolver`, a configured (Form-1) key, or a cache hit replaying a once-valid client can no longer authenticate an expired or revoked credential. Configured keys gained `CreatedAt` / `ExpiresAt` / `MaxKeyAge` (so `RequireExpiry` / `MaxKeyAge` now apply to Form 1). The `ApiKeySourceDispatcher` is routing-only; re-registering `IApiKeyClientResolver` cannot disable the security gates.
- **PBKDF2 work-factor floor** — a `MinIterations` (100,000; SP 800-132 / OWASP) floor is enforced at construction (fail-fast at boot) and on verification (a poisoned/downgraded stored iteration count fails closed).
- **Dynamic-key transport** — a dynamic-store key is accepted on the transport it matched on; it is no longer hard-defaulted to Bearer (which silently 401'd dynamic keys presented on a custom header).
- **Revocation correctness** — the resolution cache key now includes the `X-Client-Id` index (closing a same-key/different-client cache-collision); evict-on-expiry never reclaims a revocation while `AllowExpiredKeys` / the grace window would still accept the credential; a denylist that saturates and must refuse a revocation latches non-authoritative and fails auth closed (`503`, health check `Unhealthy`) rather than risk honoring a revoked key; `ApiKeyResolveResult.Success` rejects an empty `ClientId`.
- **Captive dependency** — `AddDefaultSource` / `AddNamedSource` resolvers are resolved per-request in a fresh DI scope, so a scoped dependency (DbContext / repository / tenant context) is never captured on the root container.
- **Entropy estimator** — rewritten to length × per-symbol Shannon entropy over Unicode scalars: it credits strong keys in small alphabets (hex / UUID) and counts surrogate pairs once, instead of rejecting strong keys on character-set diversity or over-counting multi-byte glyphs. Strength-failure messages are graded (re-encode / lower the entropy floor before the global `AllowWeakConfiguredKeys` kill-switch).
- **RFC HTTP-auth conformity** — a custom-header scheme no longer advertises `WWW-Authenticate: Bearer`; the Bearer challenge adds `error="invalid_token"` only when a credential was presented (never echoing the failure reason) and uses a stable realm; a valid credential on an unaccepted transport returns `403` (not a `401` re-auth); custom header names are validated as RFC 7230 tokens at startup; multi-valued credential / routing headers are rejected (`400`).
- **Hardening & hygiene** — claim values from a dynamic store are de-duplicated and screened for control characters; a configured-key format reject falls through to dynamic sources instead of short-circuiting the chain; the public constant-time compare bounds the presented key's length; a boot-time advisory makes a dialed-down posture (`AllowExpiredKeys` / `AllowWeakConfiguredKeys` / no cryptoperiod) loud. Removed the dead legacy `HashKey` / `ValidateKeyHash` / `ApiKeyHashResult` surface and the unenforced `StoredApiKey.ThrottleLimit`; `ApiKeyClientRegistry.Register` and the externally-supplied-cache constructor are now internal.

### Migration

Apps consuming `Cirreum.Authorization.ApiKey` migrate by installing `Cirreum.Authentication.ApiKey` and switching their composition root from `AddAuthorization(authz => authz.AddApiKey(...))` to `AddAuthentication(auth => auth.AddApiKey(...))`. The old `Cirreum.Authorization.ApiKey` package deprecates on NuGet with a successor message pointing here. See [`docs/MIGRATION-v1.md`](MIGRATION-v1.md).
