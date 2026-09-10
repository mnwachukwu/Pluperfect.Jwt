using System.Security.Cryptography;
using System.Text;

namespace Pluperfect.Jwt;

/// <summary>
/// Makes refresh tokens and hashes them for storage.
/// </summary>
/// <remarks>
/// <para>⚠ <strong>Opaque, not a JWT.</strong> A refresh token carries no claims and means
/// nothing on its own — it is a lookup key into a table that says whether it is still live.
/// That is the entire point: it can be revoked, which a signed token cannot be without somewhere
/// to write the revocation.</para>
///
/// <para>⚠ <strong>Only the hash is stored.</strong> SHA-256 with no salt and no work factor,
/// deliberately: this is a 256-bit random value, not a password, so there is no dictionary to
/// attack and nothing for a slow hash to buy. What it does buy is that a reader of the table
/// cannot present what they find there.</para>
/// </remarks>
public static class RefreshTokens
{
    /// <summary>256 bits, the same strength as the signing key.</summary>
    private const int TokenBytes = 32;

    /// <summary>Mints a new token. The only place the raw value ever exists.</summary>
    /// <returns>A base64url-encoded 256-bit random value.</returns>
    public static string Create() => Base64Url(RandomNumberGenerator.GetBytes(TokenBytes));

    /// <summary>Hashes a token for storage or lookup.</summary>
    /// <param name="token">The raw token as presented by the client.</param>
    /// <returns>Lower-case hex, 64 characters — size the column for exactly this.</returns>
    public static string Hash(string token) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(token)));

    /// <remarks>
    /// Base64url rather than base64: the value goes in a <c>Set-Cookie</c> header, where
    /// <c>+</c>, <c>/</c> and <c>=</c> are either reserved or invite quoting, and a cookie that
    /// round-trips differently than it was written is a session that fails on some clients and
    /// not others.
    /// </remarks>
    private static string Base64Url(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
