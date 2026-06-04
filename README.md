# Cirreum Authentication - API Key

[![NuGet Version](https://img.shields.io/nuget/v/Cirreum.Authentication.ApiKey.svg?style=flat-square&labelColor=1F1F1F&color=003D8F)](https://www.nuget.org/packages/Cirreum.Authentication.ApiKey/)
[![NuGet Downloads](https://img.shields.io/nuget/dt/Cirreum.Authentication.ApiKey.svg?style=flat-square&labelColor=1F1F1F&color=003D8F)](https://www.nuget.org/packages/Cirreum.Authentication.ApiKey/)
[![GitHub Release](https://img.shields.io/github/v/release/cirreum/Cirreum.Authentication.ApiKey?style=flat-square&labelColor=1F1F1F&color=FF3B2E)](https://github.com/cirreum/Cirreum.Authentication.ApiKey/releases)
[![License](https://img.shields.io/github/license/cirreum/Cirreum.Authentication.ApiKey?style=flat-square&labelColor=1F1F1F&color=F2F2F2)](https://github.com/cirreum/Cirreum.Authentication.ApiKey/blob/main/LICENSE)
[![.NET](https://img.shields.io/badge/.NET-10.0-003D8F?style=flat-square&labelColor=1F1F1F)](https://dotnet.microsoft.com/)

**API key authentication scheme for the Cirreum framework**

> **Migrating from `Cirreum.Authorization.ApiKey`?** This package is its renamed successor — same scheme, proper layer. See [`docs/MIGRATION-v1.md`](docs/MIGRATION-v1.md).

## Overview

**Cirreum.Authentication.ApiKey** provides header- and Bearer-based API key authentication for ASP.NET Core applications within the Cirreum ecosystem. It enables secure service-to-service communication and broker authentication scenarios where OAuth/OIDC flows are not appropriate.

The package implements the ApiKey scheme of the Cirreum Authentication track. Apps install it alongside other schemes (`Cirreum.Authentication.SignedRequest`, `Cirreum.Authentication.SessionTicket`, OIDC bearer schemes) and compose them through the umbrella package `Cirreum.Runtime.Authentication`.

### Key features

- **Multi-scheme registration** — One ASP.NET scheme per `(Provider, Transport)` tuple: `ApiKey:Bearer`, `ApiKey:X-Api-Key`, etc. Each scheme handler is bound to a single credential source — no runtime fallback between transports.
- **Per-client transport acceptance** — Configure each client's `AcceptedTransports` independently; a client accepting both Bearer and a custom header is reachable through both ASP.NET schemes but uses the same key material.
- **Bearer-prefix disambiguation** — Optional per-provider `BearerPrefix` (e.g. `ak_prod_`) — modeled on Stripe / GitHub / Slack — lets multiple Bearer-probing providers coexist without colliding. Falls back to JWT-shape disambiguation when no prefix is configured.
- **Selector-based dispatch** — Ships `ApiKeyBearerSchemeSelector` (implements `IBearerSchemeSelector`, `Priority = SchemeSelectorPriority.Key`) for the Bearer transport, plus one `ApiKeyHeaderSchemeSelector` per configured custom-header name.
- **Secure validation** — Constant-time comparison via `CryptographicOperations.FixedTimeEquals` prevents timing attacks.
- **Role-based claims** — Configure roles per client for downstream authorization.
- **Dynamic resolution** — Database-backed `DynamicApiKeyClientResolver` for large-scale partner deployments, with optional caching.

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
              "Key": "ak_prod_a1b2c3d4e5f6...",
              "AcceptedTransports": "BearerAuthorizationHeader",
              "Roles": ["App.System"]
            },
            "ExternalService": {
              "Enabled": true,
              "ClientId": "external-service",
              "ClientName": "External Integration Service",
              "Key": "x1y2z3w4v5u6...",
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

### Secure key storage

API keys can be provided in two ways (checked in order):

1. **Direct value** — `Key` property in instance configuration (dev/testing only)
2. **Connection string** — `ConnectionStrings:{InstanceName}` in configuration (production)

For production environments, store API keys in Azure Key Vault using the connection string pattern. The instance name is used as the connection string key, allowing both the API and client applications to resolve the same secret from Key Vault.

### Generating API keys

When using the `BearerPrefix` convention:

```csharp
var raw = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
var key = $"ak_prod_{raw}";
```

When no prefix is configured (opaque-only), generate the raw bytes alone:

```csharp
var key = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
```

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
ApiKeyValidation  (cross-instance uniqueness guard)
IApiKeyClientResolver  (Configuration / Dynamic / Caching / Composite implementations)
```

## Dynamic API key resolution

For large-scale deployments with many partners/customers, implement database-backed resolution:

### Basic setup

```csharp
builder.AddAuthentication(auth => auth
    .AddApiKey(o => o
        .AddTransport(ApiKeyTransports.XApiKey)
        .AddResolver<DatabaseApiKeyResolver>()));
```

### Implementing a custom resolver

```csharp
public class DatabaseApiKeyResolver(
    IApiKeyValidator validator,
    IDbConnection db,
    ILogger<DatabaseApiKeyResolver> logger)
    : DynamicApiKeyClientResolver(validator, logger) {

    public override IReadOnlySet<string> SupportedHeaders =>
        new HashSet<string> { ApiKeyTransports.XApiKey };

    protected override async Task<IEnumerable<StoredApiKey>> LookupKeysAsync(
        ApiKeyLookupContext context,
        CancellationToken cancellationToken) {

        var clientId = context.GetHeader("X-Client-Id");
        if (!string.IsNullOrEmpty(clientId)) {
            return await db.QueryAsync<StoredApiKey>(
                "SELECT * FROM ApiKeys WHERE ClientId = @ClientId AND IsActive = 1",
                new { ClientId = clientId });
        }

        return await db.QueryAsync<StoredApiKey>(
            "SELECT * FROM ApiKeys WHERE HeaderName = @HeaderName AND IsActive = 1",
            new { HeaderName = context.HeaderName });
    }
}
```

### With caching

```csharp
builder.AddAuthentication(auth => auth
    .AddApiKey(o => o
        .AddTransport(ApiKeyTransports.XApiKey)
        .AddResolver<DatabaseApiKeyResolver>(caching => {
            caching.SuccessCacheDuration = TimeSpan.FromMinutes(5);
            caching.NotFoundCacheDuration = TimeSpan.FromSeconds(30);
        })));
```

## Security considerations

- **Constant-time comparison** — Key validation uses `CryptographicOperations.FixedTimeEquals` to prevent timing attacks
- **Key storage** — Never commit API keys to source control; use Azure Key Vault or similar secret management
- **Key rotation** — Plan for key rotation by supporting multiple active keys during transition periods
- **Transport security** — Always use HTTPS to protect keys in transit
- **Least privilege** — Assign minimum required roles to each client

## Claims emitted

Authenticated requests receive the following claims:

| Claim | Value |
|---|---|
| `ClaimTypes.NameIdentifier` | `ClientId` |
| `ClaimTypes.Name` | `ClientName` |
| `ClaimTypes.Role` | Each configured role |
| `client_type` | `api_key` |

The ASP.NET authentication scheme that authenticated the request (`ApiKey:Bearer`, `ApiKey:X-Api-Key`, etc.) is carried on `AuthenticationTicket.AuthenticationScheme` — no `auth_scheme` claim side-channel.

## License

MIT — see [LICENSE](LICENSE).

---

**Cirreum Foundation Framework**
*Layered simplicity for modern .NET*
