namespace Cirreum.Authentication.ApiKey;

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

		// URL-safe, unpadded Base64 (net8-safe; avoids '+', '/', '=').
		return Convert.ToBase64String(buffer)
			.Replace('+', '-')
			.Replace('/', '_')
			.TrimEnd('=');
	}

}
