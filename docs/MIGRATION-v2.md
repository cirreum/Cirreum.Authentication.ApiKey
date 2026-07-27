# Migration to Cirreum.Authentication.ApiKey v2.0

**From:** `Cirreum.Authentication.ApiKey 1.0.x`
**To:** `Cirreum.Authentication.ApiKey 2.0.0`

## Why v2

One breaking change, and it affects applications rather than the package's own surface:
`IRevokedCredentialProvider` — the contract an application implements to tell the framework which
credentials are revoked — now reports a credential's own expiry alongside its identifier.

ApiKey's public API is unchanged. The major reflects that upgrading requires an application code
change, which is what a version number is for.

## Breaking change

### `IRevokedCredentialProvider` reports expiry

The contract lives in `Cirreum.AuthenticationProvider`, which reached 2.0.0.

**Before:**

```csharp
public sealed class MyRevocationProvider(AppDbContext db) : IRevokedCredentialProvider {

	public async IAsyncEnumerable<string> GetRevokedCredentialIdsAsync(
		[EnumeratorCancellation] CancellationToken cancellationToken = default) {

		await foreach (var row in db.RevokedKeys.AsAsyncEnumerable().WithCancellation(cancellationToken)) {
			yield return row.KeyId;
		}
	}
}
```

**Now:**

```csharp
public sealed class MyRevocationProvider(AppDbContext db) : IRevokedCredentialProvider {

	public async IAsyncEnumerable<RevokedCredential> GetRevokedCredentialsAsync(
		[EnumeratorCancellation] CancellationToken cancellationToken = default) {

		await foreach (var row in db.RevokedKeys.AsAsyncEnumerable().WithCancellation(cancellationToken)) {
			yield return new RevokedCredential(row.KeyId, row.ExpiresAt);
		}
	}
}
```

Three things changed: the method name, the element type, and the addition of an expiry.

**The minimum change** — `new RevokedCredential(row.KeyId)` — compiles and preserves existing
behaviour exactly. `ExpiresAt` is optional and defaults to null.

### Why supply `ExpiresAt`

A revocation loaded at boot was previously retained for the denylist's full lifetime, regardless of
when the credential itself expired. One created by a live `CredentialRevoked` event already
self-evicted. Supplying the expiry makes the two paths behave identically.

This matters because the in-memory denylist is **capacity-bounded and fails authentication closed on
saturation** — it refuses rather than silently forgetting a revocation. Entries that can never
authenticate again but are held anyway consume that capacity. Passing the credential's expiry lets
them go.

`null` remains correct and safe for a credential that does not expire, or when your store cannot
determine it: the entry is retained until restart. The trade is memory, never a re-admitted
credential.

> `ExpiresAt` is the **credential's** expiry, not the revocation's. A revocation never expires early.

## Also in this release

Both are fixes needing no action — see [`CHANGELOG.md`](CHANGELOG.md).

- `ApiKeyClientRegistry` now refuses a blank key on either side of its credential comparison, rather
  than relying on the length and entropy floors enforced elsewhere in the pipeline.
- A bearer credential consisting of nothing but the configured `BearerPrefix` no longer reaches
  lookup as an empty key.

## Migration walkthrough

1. Update `<PackageReference Include="Cirreum.Authentication.ApiKey" Version="2.0.0" />`.
2. Rename your `IRevokedCredentialProvider` implementation's method to `GetRevokedCredentialsAsync`
   and change its element type to `RevokedCredential`.
3. Yield `new RevokedCredential(id, expiresAt)` where your store knows the credential's expiry, or
   `new RevokedCredential(id)` where it does not.
4. Rebuild and confirm revocation still hydrates at startup — the health check reports the denylist
   as authoritative once hydration completes.

## What didn't change

- Every ApiKey public type and composition verb
- `IApiKeyClientResolver`, `IApiKeyValidator`, `IApiKeyDenylist` and their contracts
- Key format, hashing, and the strength floors
- Transport configuration, source routing, and scheme selection
- The revocation posture: hydration failure and denylist saturation still fail authentication closed
