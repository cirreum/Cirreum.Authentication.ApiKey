# Cirreum.Authentication.ApiKey 2.0.0

One breaking change affecting applications rather than this package's own surface, plus two
hardening fixes.

Full detail and step-by-step upgrade instructions: [`docs/MIGRATION-v2.md`](MIGRATION-v2.md).

## Breaking: `IRevokedCredentialProvider` reports expiry

The contract an application implements to expose its revocation state now reports each credential's
own expiry alongside its identifier. It lives in `Cirreum.AuthenticationProvider`, which reached
2.0.0.

```csharp
// Before
IAsyncEnumerable<string> GetRevokedCredentialIdsAsync(CancellationToken ct = default);

// Now
IAsyncEnumerable<RevokedCredential> GetRevokedCredentialsAsync(CancellationToken ct = default);
```

**The minimum change is one line** — `yield return new RevokedCredential(id)` preserves existing
behaviour exactly, because `ExpiresAt` is optional.

Supplying it is worth doing. A revocation loaded at boot was previously retained for the denylist's
full lifetime regardless of when the credential expired, while one created by a live
`CredentialRevoked` event already self-evicted; passing the expiry makes both paths behave the same.
That matters because the denylist is capacity-bounded and **fails authentication closed on
saturation** — it refuses rather than forgetting a revocation — so entries that can never
authenticate again still consume capacity.

`null` stays correct for a credential that does not expire, or when your store cannot determine one:
the entry is retained until restart. The trade is memory, never a re-admitted credential.

ApiKey's own public API is unchanged. Every type, composition verb, and contract in this package
works as before.

## Hardening — no action needed

**`ApiKeyClientRegistry` now refuses a blank key on either side of its comparison.**
`CryptographicOperations.FixedTimeEquals` reports two zero-length spans as equal, so a blank
presented key arriving alongside a blank configured one would have authenticated. That could not
happen in the composed pipeline — `ValidateFormat` imposes a length floor on what is presented and
the registrar an entropy floor on what is configured — but the comparison was safe only because of
invariants held in two other files, while its sibling `DefaultApiKeyValidator.CompareKeysSecurely`
already guarded the same case itself.

**A bearer credential consisting of nothing but the configured `BearerPrefix` no longer reaches
lookup as an empty key.** The custom-header transport has always rejected a blank credential
explicitly; the bearer transport did not re-check after stripping the prefix, leaving `ValidateFormat`
as the only thing between an empty string and the registry. It now returns no result, matching the
custom-header branch.

Both came out of a sweep for the blank-comparison pattern across the authentication packages, prompted
by a related defect found in `Cirreum.Authentication.External`.
