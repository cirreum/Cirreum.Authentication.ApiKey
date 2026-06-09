# Cirreum Authentication - API Key

[![NuGet Version](https://img.shields.io/nuget/v/Cirreum.Authentication.ApiKey.svg?style=flat-square&labelColor=1F1F1F&color=003D8F)](https://www.nuget.org/packages/Cirreum.Authentication.ApiKey/)
[![NuGet Downloads](https://img.shields.io/nuget/dt/Cirreum.Authentication.ApiKey.svg?style=flat-square&labelColor=1F1F1F&color=003D8F)](https://www.nuget.org/packages/Cirreum.Authentication.ApiKey/)
[![GitHub Release](https://img.shields.io/github/v/release/cirreum/Cirreum.Authentication.ApiKey?style=flat-square&labelColor=1F1F1F&color=FF3B2E)](https://github.com/cirreum/Cirreum.Authentication.ApiKey/releases)
[![License](https://img.shields.io/badge/license-MIT-F2F2F2?style=flat-square&labelColor=1F1F1F)](https://github.com/cirreum/Cirreum.Authentication.ApiKey/blob/main/LICENSE)
[![.NET](https://img.shields.io/badge/.NET-10.0-003D8F?style=flat-square&labelColor=1F1F1F)](https://dotnet.microsoft.com/)

**API key authentication scheme for the Cirreum framework**

## Overview

**Cirreum.Authentication.ApiKey** provides header- and Bearer-based API key authentication for ASP.NET Core applications within the Cirreum ecosystem. It enables secure service-to-service communication and broker authentication scenarios where OAuth/OIDC flows are not appropriate.

The package implements the ApiKey scheme of the Cirreum Authentication track. Apps install it alongside other schemes (`Cirreum.Authentication.SignedRequest`, `Cirreum.Authentication.SessionTicket`, OIDC bearer schemes) and compose them through the umbrella package `Cirreum.Runtime.Authentication`.

### Key features

- **Multi-scheme registration** — One ASP.NET scheme per `(Provider, Transport)` tuple: `ApiKey:Bearer`, `ApiKey:X-Api-Key`, etc. Each scheme handler is bound to a single credential source — no runtime fallback between transports.
- **Per-client transport acceptance** — Configure each client's `AcceptedTransports` independently; a client accepting both Bearer and a custom header is reachable through both ASP.NET schemes but uses the same key material.
- **Bearer-prefix disambiguation** — Optional per-provider `BearerPrefix` (e.g. `ak_prod_`) — modeled on Stripe / GitHub / Slack — lets multiple Bearer-probing providers coexist without colliding. Falls back to JWT-shape disambiguation when no prefix is configured.
- **Selector-based dispatch** — Ships `ApiKeyBearerSchemeSelector` (implements `IBearerSchemeSelector`, `Priority = SchemeSelectorPriority.Key`) for the Bearer transport, plus one `ApiKeyHeaderSchemeSelector` per configured custom-header name.
- **Secure validation** — Constant-time comparison via `CryptographicOperations.FixedTimeEquals` prevents timing attacks. Stored hashes are self-describing (PHC-style `{algorithm}$…`) and verified by fail-closed single-algorithm dispatch.
- **Two forms of keys** — *Configured* keys (appsettings / Key Vault) with a startup strength floor, and *managed* keys (Cirreum-generated, hash-stored) that are strong by construction. See [Two forms of keys](#two-forms-of-keys).
- **Revocation** — A per-request denylist consulted after the cache, hydrated at boot, with a **fail-closed** posture and a health check. See [Revocation](#revocation).
- **Role-based claims** — Configure roles per client for downstream authorization. Custom claims cannot shadow the reserved framework claim types.
- **Dynamic resolution** — Database-backed `DynamicApiKeyClientResolver` for large-scale partner deployments, with optional caching and `X-Api-Source` store routing.

### Use cases

- Service-to-service communication
- Broker applications pushing data to APIs
- External system integrations
- Background job authentication
- IoT device connectivity

## Installation

```bash
dotnet add package Cirreum.Authentication.ApiKey
```

## Configuration

Add API key clients to your `appsettings.json`:

```json
{
  "Cirreum": {
	"Authentication": {
	  "Providers": {
		"ApiKey": {
		  "BearerPrefix": "ak_prod_",
		  "Instances": {
			"TrackBroker": {
			  "Enabled": true,
			  "ClientId": "track-broker",
			  "ClientName": "Track Broker Application",
			  "Key": "ak_prod_a1b2c3d4e5f6...", // shown for example only - store in secrets.json or Key Vault
			  "AcceptedTransports": "BearerAuthorizationHeader",
			  "Roles": ["App.System"]
			},
			"ExternalService": {
			  "Enabled": true,
			  "ClientId": "external-service",
			  "ClientName": "External Integration Service",
			  "Key": "x1y2z3w4v5u6...", // shown for example only - store in secrets.json or Key Vault
			  "AcceptedTransports": "CustomHeader",
			  "HeaderName": "X-Api-Key",
			  "Roles": ["App.Agent"]
			}
		  }
		}
	  }
	}
  }
}
```

### Provider-level properties

| Property | Required | Description |
|---|---|---|
| `BearerPrefix` | No | Token prefix shared by every instance that accepts the Bearer transport. When set, the recommended shape is `{scheme}_{env}_{raw}` (e.g. `ak_prod_`). Required at boot when multiple Bearer-probing providers are registered. |

### Instance properties

| Property | Required | Description |
|---|---|---|
| `Enabled` | Yes | Whether this client is active |
| `ClientId` | Yes | Unique identifier; surfaces as `ClaimTypes.NameIdentifier` |
| `ClientName` | No | Display name (defaults to `ClientId`); surfaces as `ClaimTypes.Name` |
| `Key` | No\* | The API key value (\*or provide via `ConnectionStrings:{InstanceName}`) |
| `AcceptedTransports` | No | `BearerAuthorizationHeader` (default), `CustomHeader`, or `"BearerAuthorizationHeader, CustomHeader"` for both. `[Flags]` enum semantics. |
| `HeaderName` | When `CustomHeader` is accepted | Custom header name (e.g. `X-Api-Key`) |
| `Roles` | No | Roles assigned to the authenticated principal |

A client whose `AcceptedTransports` includes both flags is reachable via the `ApiKey:Bearer` scheme AND the `ApiKey:{HeaderName}` scheme — the same key material, validated at request time against whichever scheme handler ran.

## Two forms of keys

ApiKey supports two distinct forms, each with its own strength model:

### Form 1 — statically configured keys

Keys declared in `appsettings` / Key Vault and bound by the registrar (the `Instances` block above). At **startup**, each configured key is checked against a strength floor — a minimum length (`MinimumKeyLength`, default 32) and a minimum estimated entropy (`MinimumKeyEntropyBits`, default **112 bits**, the NIST SP 800-63B §5.1.2 look-up-secret floor). A key below the floor **fails fast at boot** rather than silently authenticating. Entropy is *never* evaluated against a presented credential at request time (that would be a structural oracle) — only at startup.

To run weak demo / prototype keys, set the negative-worded, off-by-default escape hatch:

```json
{ 
	"Cirreum": { 
		"Authentication": { 
			"Providers": { 
				"ApiKey": {
					"Validation": { 
						"AllowWeakConfiguredKeys": true 
					}
				}
			}
		}
	}
}
```

> ⚠ `AllowWeakConfiguredKeys` is for non-production use only. Configured secrets leak (logs, source control, config dumps) and weak keys are guessable.

**Key-Vault-at-rest is a requirement for Form 1 in production.** Configured keys are compared constant-time in memory, but they live in configuration — provide them via `ConnectionStrings:{InstanceName}` resolved from Azure Key Vault (the instance name is the connection-string key), never as a literal `Key` in committed `appsettings`. The literal `Key` property is for dev/testing only.

### Form 2 — dynamic managed keys

Keys minted and stored by the application through a dynamic source — `AddDefaultSource<TResolver>()` for the single, no-routing-header source (the common case), or `AddNamedSource<TResolver>(name)` for additional addressable sources reached via `X-Api-Source`. These are strong by construction: generate them with `IApiKeyGenerator` (256-bit CSPRNG, URL-safe) and persist only a self-describing hash via `IApiKeyValidator.HashKeyEncoded(...)`.

```csharp
// Generate a 256-bit secret (raw portion); prefix with ak_{env}_ if you use BearerPrefix.
var raw = generator.Generate();                 // IApiKeyGenerator — 256-bit, URL-safe
var stored = validator.HashKeyEncoded(raw);     // "sha256$…" — store THIS, hand `raw` to the client once
```

The stored-hash algorithm is set by `Validation:HashAlgorithm` — **`Sha256`** (default; a fast salted hash, correct because managed keys are high-entropy) or **`Pbkdf2`** (a work-factored KDF, offered only for *imported* low-entropy secrets). Verification dispatches on the encoded algorithm tag and is **fail-closed**: a stored value that is not self-describing is rejected (the legacy bare-SHA-256 path is gone).

## Multi-scheme model

Each ApiKey provider registers one ASP.NET authentication scheme per unique `(Provider, Transport)` tuple in its instance set:

| Instance set | ASP.NET schemes registered |
|---|---|
| Any instances accept `BearerAuthorizationHeader` | `ApiKey:Bearer` |
| Instances accept `CustomHeader` with `HeaderName = X-Api-Key` | `ApiKey:X-Api-Key` |
| Instances accept `CustomHeader` with `HeaderName = X-Customer-Key` | `ApiKey:X-Customer-Key` |

Apps target a specific scheme via `[Authorize(AuthenticationSchemes = "ApiKey:Bearer")]` or compose multiple via the umbrella package's dynamic forward scheme.

### Bearer disambiguation

When `BearerPrefix` is configured, the Bearer selector matches only tokens starting with the prefix — multiple Bearer-probing providers can coexist (`ak_prod_…` for ApiKey, `st_prod_…` for SessionTicket, etc.). Boot-time validation in the umbrella package enforces prefix uniqueness across providers.

When `BearerPrefix` is unset, the Bearer selector falls back to JWT-shape disambiguation: it claims any non-JWT-shaped Bearer value and leaves JWT-shaped values for the framework's audience-routing selector.

### Declaring transports

By default — `AddApiKey()` with **no** `AcceptTransports(...)` call — the provider accepts **all** well-known transports (the `ApiKeyTransport` enum): `Authorization: Bearer`, `X-Api-Key`, `Ocp-Apim-Subscription-Key`, and `X-Auth-Token`. **This is the recommended default** — every transport stays open, so dynamic sources and individual customers/clients can each use whichever suits them, with no recompile for a new integration.

Two knobs adjust it:

- **`AcceptTransports(...)` — restrict.** Accept only the listed well-known transports. *Not required;* call it only to narrow the default. Called with **no arguments** it clears them all (accept none of the well-known set).
- **`AddCustomTransport(headerName)` — add.** Additively accept a non-standard header, layered on top of whatever well-known set is active. It never removes a well-known transport.

```csharp
// Restrict to X-Api-Key only:
auth.AddApiKey(o => o.AcceptTransports(ApiKeyTransport.XApiKey));

// Keep ALL well-known transports AND also accept a partner header (additive — no list needed):
auth.AddApiKey(o => o.AddCustomTransport("X-Partner-Key"));

// Accept ONLY a custom header (clear the well-known set, then add):
auth.AddApiKey(o => o.AcceptTransports().AddCustomTransport("X-Partner-Key"));

// Bearer + X-Api-Key + a partner header:
auth.AddApiKey(o => o
	.AcceptTransports(ApiKeyTransport.Bearer, ApiKeyTransport.XApiKey)
	.AddCustomTransport("X-Partner-Key"));
```

## Architecture

```text
ApiKeyAuthenticationRegistrar
└── extends HeaderAuthenticationProviderRegistrar  (Cirreum.AuthenticationProvider)
	├── per-instance: validate, resolve key, register client in ApiKeyClientRegistry
	└── post-loop: register one ASP.NET scheme + selector per (transport, header) tuple
		├── ApiKey:Bearer       → ApiKeyAuthenticationHandler + ApiKeyBearerSchemeSelector (IBearerSchemeSelector)
		└── ApiKey:{Header}     → ApiKeyAuthenticationHandler + ApiKeyHeaderSchemeSelector  (one per distinct header)

ApiKeyAuthenticationHandler  (AuthenticationHandler<ApiKeyAuthenticationOptions>)
├── reads ONE source per scheme — options.Transport selects Bearer or CustomHeader
├── strips configured BearerPrefix when Transport == Bearer
├── resolves the matching client via IApiKeyClientResolver
├── validates the resolved client's AcceptedTransports includes the inbound transport (filter at lookup)
└── builds ClaimsPrincipal with ClientId, ClientName, Roles

ApiKeyClientRegistry / ApiKeyClientEntry  (per-instance API key state)
ApiKeyProviderState  (per-host scheme-claim + cross-instance key-uniqueness guard)
IApiKeyClientResolver  (Configuration / Dynamic / Caching; ApiKeySourceDispatcher routes + composes them)
IApiKeyDenylist  (per-request revocation consult, boot-hydrated, fail-closed)
```

## Dynamic API key resolution

For keys stored in a database or external system, register a dynamic **source** backed by a resolver you implement. Most apps need just one — the **default source**, reached without any routing header.

### Basic setup

```csharp
builder.AddAuthentication(auth => auth
	.AddApiKey(o => o
		.AddDefaultSource<DatabaseApiKeyResolver>()));
```

By default the source **requires an `X-Client-Id` header** so your resolver does an O(1) indexed lookup rather than scanning (and hashing) every client's key — the dispatcher rejects a request without it as a non-descript `400` before your resolver runs. Pass `requireClientId: false` only for a self-identifying key or a tiny store.

### Implementing a custom resolver

```csharp
public class DatabaseApiKeyResolver(
	IApiKeyValidator validator,
	IDbConnection db,
	ILogger<DatabaseApiKeyResolver> logger)
	: DynamicApiKeyClientResolver(validator, logger) {

	protected override async Task<IEnumerable<StoredApiKey>> LookupKeysAsync(
		ApiKeyLookupContext context,
		CancellationToken cancellationToken) {

		// With requireClientId (the default), X-Client-Id is guaranteed present — query by it (indexed,
		// returns at most one key) rather than scanning. If you set requireClientId: false, fall back to
		// your own narrowing here.
		var clientId = context.GetHeader("X-Client-Id");
		return await db.QueryAsync<StoredApiKey>(
			"SELECT * FROM ApiKeys WHERE ClientId = @ClientId AND IsActive = 1",
			new { ClientId = clientId });
	}
}
```

### With caching

```csharp
builder.AddAuthentication(auth => auth
	.AddApiKey(o => o
		.AddDefaultSource<DatabaseApiKeyResolver>(caching: caching => {
			caching.SuccessCacheDuration = TimeSpan.FromMinutes(5);
			// Negative (miss) caching is OFF by default — enabling it can reject a
			// newly provisioned or just-rotated key for up to NotFoundCacheDuration.
			caching.EnableNegativeCaching = true;
			caching.NotFoundCacheDuration = TimeSpan.FromSeconds(30);
		})));
```

Cache entries are keyed by the routing dimension (`X-Api-Source`) together with the header and a hash of the key, so a result cached for one source never satisfies a lookup for another.

## Multiple sources

A single ApiKey provider can front several key sets, tried in this precedence when no `X-Api-Source` is supplied: static **configured** keys (in-memory, cheap) → the **default** source → (nothing else; named sources are not reached without their address). Additional **named** sources are *addressable-only* — registered with `AddNamedSource<TResolver>("name", ...)` and reached solely via an explicit `X-Api-Source` header carrying the source's **opaque derived reference** (not the friendly name), never blind-scanned (the CPU-DoS guarantee). An addressed source is **authoritative**: if the key isn't valid there, the request fails — it does not fall through to the default.

```csharp
builder.AddAuthentication(auth => auth
	.AddApiKey(o => o
		.AddDefaultSource<InternalKeyResolver>()            // reached when no X-Api-Source is sent
		.AddNamedSource<PartnerKeyResolver>("partner-a")    // reached via X-Api-Source
		.AddNamedSource<PartnerKeyResolver>("partner-b")));
```

When named sources exist and a Bearer credential arrives with no `X-Api-Source` (and no configured/default match), the handler returns a non-descript **`400`** (missing routing signal) — it never enumerates valid sources nor scans. A source that requires `X-Client-Id` but receives none is likewise a non-descript **`400`**.

## Revocation

A per-request denylist (`IApiKeyDenylist`) is consulted on every resolution **after** the cache, so a revoked credential is rejected even within a cache entry's TTL. It is hydrated at boot from any registered `IRevokedCredentialProvider` and kept current by `CredentialRevoked` auth-bus events.

The hydrator is **fail-closed**: if a provider faults at startup (the denylist may be missing revoked credentials), ApiKey authentication fails closed with a retryable **`503`**, a `Critical` log is emitted, and the `apikey-revocation` health check reports `Unhealthy` — until hydration succeeds. To deliberately serve with a possibly-incomplete denylist (availability over the revocation guarantee), set the off-by-default escape hatch:

```json
{ 
	"Cirreum": { 
		"Authentication": {
			"Providers": {
				"ApiKey": {
					"Revocation": {
						"AllowFaultedDenylist": true 
					}
				}
			}
		}
	}
}
```

> ⚠ With `AllowFaultedDenylist` set, a revoked credential may authenticate until the live revocation event stream catches up; the health check stays `Degraded`.

The in-memory denylist is bounded by `Revocation:MaxDenylistEntries` (default 1,000,000). It evicts an entry only once the revoked credential's own expiry has passed (never to free space — that would un-revoke a live credential); at the cap it refuses further revocations with a `Critical` log rather than silently dropping. For populations beyond the cap, plug a scale-out `IApiKeyDenylist` backed by the authoritative store.

## Security considerations

- **Constant-time comparison** — Key validation uses `CryptographicOperations.FixedTimeEquals` to prevent timing attacks
- **Self-describing hashing, fail-closed** — Managed keys are stored as PHC-style `{algorithm}$…` and verified by single-algorithm dispatch on the encoded tag; a non-self-describing stored value is rejected, foreclosing both the legacy bare-hash fallback and algorithm confusion
- **Strength at issuance** — Configured keys must clear a startup strength floor (length + 112-bit entropy) unless `AllowWeakConfiguredKeys`; managed keys are 256-bit by construction. Entropy is never tested against a presented credential
- **Key storage** — Never commit API keys to source control; provide configured keys via Key Vault (`ConnectionStrings:{InstanceName}`), and persist only hashes for managed keys
- **Fail-closed revocation** — The denylist is consulted every request after the cache; a faulted boot hydration fails authentication closed (`503`) with a health-check signal unless `AllowFaultedDenylist` is set
- **No claim shadowing** — Custom client claims cannot override the reserved framework claim types (`client_type`, `scope`, name, role, identifier)
- **Key rotation** — Plan for key rotation by supporting multiple active keys during transition periods
- **Transport security** — Always use HTTPS to protect keys in transit
- **Least privilege** — Assign minimum required roles to each client

## Claims emitted

Authenticated requests receive the following claims:

| Claim | Value |
| --- | --- |
| `ClaimTypes.NameIdentifier` | `ClientId` |
| `ClaimTypes.Name` | `ClientName` |
| `ClaimTypes.Role` | Each configured role |
| `scope` | Each granted scope (per-key overrides) |
| `client_type` | `api_key` |

A client may carry additional custom claims, but any custom claim whose type collides with a reserved type above (`client_type`, `scope`, name, role, identifier) is dropped with a warning — it cannot shadow the values the handler emits.

The ASP.NET authentication scheme that authenticated the request (`ApiKey:Bearer`, `ApiKey:X-Api-Key`, etc.) is carried on `AuthenticationTicket.AuthenticationScheme` — no `auth_scheme` claim side-channel.

## License

MIT — see [LICENSE](LICENSE).

---

**Cirreum Foundation Framework**  
*Layered simplicity for modern .NET*
