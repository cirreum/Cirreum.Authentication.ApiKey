namespace Cirreum.Authentication.ApiKey;

using System.Buffers.Text;
using System.Security.Cryptography;

/// <summary>
/// Default <see cref="IApiKeyGenerator"/> — fills a byte buffer from
/// <see cref="RandomNumberGenerator"/> and encodes it URL-safe (Base64Url, unpadded), so the
/// secret is safe in an <c>Authorization: Bearer</c> value or a custom header.
/// </summary>
public sealed class DefaultApiKeyGenerator : IApiKeyGenerator {

	/// <summary>The NIST SP 800-63B §5.1.2 look-up-secret entropy floor, in bits.</summary>
	public const int MinimumEntropyBits = 112;

	/// <inheritdoc />
	public string Generate(int entropyBits = 256) {
		var bits = Math.Max(entropyBits, MinimumEntropyBits);
		var byteCount = (bits + 7) / 8;

		var buffer = new byte[byteCount];
		RandomNumberGenerator.Fill(buffer);

		// URL-safe, unpadded Base64 (Base64Url, RFC 4648 §5) — safe in an Authorization: Bearer value or a
		// custom header. Avoids '+', '/', '=' without the allocate-then-replace chain.
		return Base64Url.EncodeToString(buffer);
	}

}
