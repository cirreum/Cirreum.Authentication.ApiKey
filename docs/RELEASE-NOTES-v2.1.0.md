# Cirreum.Authentication.ApiKey 2.1.0 — every ApiKey scheme declares what it authenticates

## Why this release exists

The attribute-authority model has providers declare what kind of party they authenticate, so
nothing downstream infers it from token contents. ApiKey was the provider that broke the
declaration delivery twice: the registrar base filed records keyed on the *instance key*, which
is never an ApiKey scheme name (`ApiKey:Bearer`, `ApiKey:{header}`), and the zero-instance
dynamic-resolver path — the normal configuration for a database-backed key store — filed nothing
at all. This release routes every ApiKey scheme through the registration funnel at the one place
its names are actually born.

## What's new

**`SubjectKind.Machine`, declared at the scheme birthplace.** The shared scheme-registration
helpers — used by the configured-instance path and the `AddApiKey(...)` dynamic path alike — now
register and declare through `IAuthenticationBuilder.AddScheme`. An API key identifies a calling
application, not a person; every `ApiKey:{transport}` scheme now says so, whichever path
registered it.

**`ApiKeyTransport.HeaderName()` is public.** The enum was write-only for consumers: an
application could accept a transport but had to hardcode its header name to *call* an API with
it. The enum is now readable as well:

```csharp
request.Headers.Add(ApiKeyTransport.XApiKey.HeaderName(), apiKey);
```

`HeaderName()` throws for `ApiKeyTransport.Bearer`, which carries its key in the standard
`Authorization` header rather than a custom one — behavior unchanged, now documented since the
throw is publicly reachable.

## Compatibility

- **Applications have nothing to change.** Composition (`AddApiKey(...)`, configured instances,
  dynamic sources) is untouched.
- **Registrar plumbing changed signature** per the `Cirreum.AuthenticationProvider` 3.0.x
  contract consolidation (`Register` / `AddAuthenticationHandler` take `IAuthenticationBuilder`).
  These are framework-invoked members no application calls directly; shipped as a Minor with
  that scope stated deliberately.
- The declarations are read by higher-layer packages releasing later in the same wave; until
  then they change no behavior.

## See also

- `Cirreum.AuthenticationProvider 3.0.1` — the registration funnel and the release notes that
  tell the wave's story.
- `Cirreum.Kernel 2.1.0` — the `SubjectKind` / `ClaimAuthority` vocabulary.
