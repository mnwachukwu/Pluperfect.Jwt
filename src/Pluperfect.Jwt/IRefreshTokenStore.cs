namespace Pluperfect.Jwt;

/// <summary>Why a refresh attempt did not produce a new session.</summary>
public enum RefreshOutcome
{
    /// <summary>The token was live and has been rotated.</summary>
    Ok,

    /// <summary>No record matched the presented token.</summary>
    Unknown,

    /// <summary>The record matched but its lifetime had passed.</summary>
    Expired,

    /// <summary>
    /// The token was already redeemed.
    /// </summary>
    /// <remarks>
    /// ⚠ Treated as theft, not as a mistake. A refresh token is single-use, so a second
    /// redemption means two parties hold the same value and only one of them should — the
    /// legitimate client has already rotated past it. Every token for that subject should be
    /// revoked in response, which signs the attacker and the victim out together and forces a
    /// password-backed login.
    /// </remarks>
    Replayed,
}

/// <summary>The result of redeeming a refresh token.</summary>
/// <param name="Outcome">Whether a new session was produced, and if not, why not.</param>
/// <param name="SubjectId">The account this token authenticates, when the outcome is Ok.</param>
/// <param name="SubjectName">
/// The subject's human-readable identifier — usually an email address or username. Carried so a
/// caller can rebuild claims without a second lookup.
/// </param>
/// <param name="Persistent">Whether the session outlives the browser window.</param>
public sealed record RefreshResult(
    RefreshOutcome Outcome,
    string? SubjectId,
    string? SubjectName,
    bool Persistent);

/// <summary>
/// Storage for refresh tokens.
/// </summary>
/// <remarks>
/// <para>⚠ <strong>Only hashes cross this boundary.</strong> The raw token exists in the response
/// to the client and nowhere else — never in a log, never in a column. A reader of the database
/// cannot mint a session from what is stored there, which is the property that makes a long-lived
/// credential worth persisting at all.</para>
///
/// <para>Rotation and replay detection live behind <see cref="RedeemAsync"/> rather than in the
/// caller, because the read, the revoke and the insert have to be one transaction. Split across
/// three calls, two concurrent refreshes interleave and either both succeed — defeating
/// single-use — or both fail and sign a legitimate user out.</para>
///
/// <para>This library deliberately ships no implementation. Every consumer already has a
/// database and an ORM, and an implementation here would have to pick one for all of them.</para>
/// </remarks>
public interface IRefreshTokenStore
{
    /// <summary>Records a freshly issued token.</summary>
    /// <param name="subjectId">The account the token authenticates.</param>
    /// <param name="subjectName">The subject's email or username.</param>
    /// <param name="tokenHash">The value from <see cref="RefreshTokens.Hash"/>, never the raw token.</param>
    /// <param name="expiresAt">When this token stops being redeemable.</param>
    /// <param name="issuedForIp">The client address, for the audit trail. May be null.</param>
    /// <param name="persistent">Whether the session should outlive the browser window.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    Task CreateAsync(
        string subjectId,
        string subjectName,
        string tokenHash,
        DateTimeOffset expiresAt,
        string? issuedForIp,
        bool persistent,
        CancellationToken cancellationToken);

    /// <summary>
    /// Consumes one token and issues its replacement, atomically.
    /// </summary>
    /// <remarks>
    /// The old record is revoked and pointed at the new one, so the audit trail distinguishes a
    /// normal rotation from a security revocation: a revoked row with a successor was consumed
    /// legitimately, one without was killed.
    /// </remarks>
    /// <param name="presentedHash">Hash of the token the client sent.</param>
    /// <param name="replacementHash">Hash of the token that replaces it.</param>
    /// <param name="replacementExpiresAt">When the replacement stops being redeemable.</param>
    /// <param name="issuedForIp">The client address, for the audit trail. May be null.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>What happened, and the subject when it worked.</returns>
    Task<RefreshResult> RedeemAsync(
        string presentedHash,
        string replacementHash,
        DateTimeOffset replacementExpiresAt,
        string? issuedForIp,
        CancellationToken cancellationToken);

    /// <summary>Revokes a single token, for a deliberate sign-out.</summary>
    /// <param name="tokenHash">Hash of the token to kill.</param>
    /// <param name="reason">Recorded on the row, for the audit trail.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    Task RevokeAsync(string tokenHash, string reason, CancellationToken cancellationToken);

    /// <summary>Revokes every live token for a subject.</summary>
    /// <remarks>What <see cref="RefreshOutcome.Replayed"/> should trigger.</remarks>
    /// <param name="subjectId">The account to sign out everywhere.</param>
    /// <param name="reason">Recorded on the rows, for the audit trail.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    Task RevokeAllAsync(string subjectId, string reason, CancellationToken cancellationToken);

    /// <summary>
    /// Deletes dead rows: expired or revoked, and past the grace period.
    /// </summary>
    /// <remarks>
    /// Expired and revoked rows are dead weight, and this table grows by one row per login per
    /// device forever without it. Keep them for
    /// <see cref="PluperfectJwtOptions.RevokedTokenGraceDays"/> after expiry so a replay arriving
    /// late is still recognised as a replay rather than as an unknown token.
    /// </remarks>
    /// <param name="olderThan">The cutoff instant.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>How many rows were removed.</returns>
    Task<int> DeleteDeadAsync(DateTimeOffset olderThan, CancellationToken cancellationToken);
}
