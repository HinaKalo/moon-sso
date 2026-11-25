package cloud.moonl.sso.spring.logout;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.jspecify.annotations.Nullable;

import cloud.moonl.sso.spring.jwt.MoonSsoJwtDecoders;

import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.JwtValidationException;

/**
 * Validates OpenID Connect Back-Channel Logout tokens: JWS signature (RS256/ES256) from the
 * issuer's JWKS, header {@code typ == logout+jwt}, {@code iss}, {@code aud} containing the
 * client id, {@code iat} not in the future (beyond the clock skew), {@code exp} not passed,
 * the back-channel logout event, {@code sub} or {@code sid}, no {@code nonce} and a
 * {@code jti}. Replay detection of the {@code jti} is done by the caller.
 */
public final class LogoutTokenValidator {

	/** Event key required in the {@code events} claim. */
	public static final String BACKCHANNEL_LOGOUT_EVENT = "http://schemas.openid.net/event/backchannel-logout";

	private final JwtDecoder decoder;

	public LogoutTokenValidator(JWKSource<SecurityContext> jwkSource, String issuer, String clientId,
			Duration clockSkew, Clock clock) {
		this.decoder = MoonSsoJwtDecoders.create(jwkSource, Set.of(JWSAlgorithm.RS256, JWSAlgorithm.ES256),
				claimsValidator(issuer, clientId, clockSkew, clock), MoonSsoJwtDecoders.LOGOUT_TOKEN_TYPE);
	}

	/**
	 * Validates a logout token.
	 * @throws InvalidLogoutTokenException when the token is not acceptable
	 */
	public LogoutToken validate(String token) {
		if (token == null || token.isBlank() || token.length() > 16 * 1024) {
			throw new InvalidLogoutTokenException("missing or oversized logout_token");
		}
		Jwt jwt;
		try {
			jwt = this.decoder.decode(token);
		}
		catch (JwtValidationException ex) {
			String reason = ex.getErrors()
				.stream()
				.map(OAuth2Error::getDescription)
				.filter((d) -> d != null && !d.isBlank())
				.findFirst()
				.orElse("invalid logout token");
			throw new InvalidLogoutTokenException(reason);
		}
		catch (JwtException ex) {
			throw new InvalidLogoutTokenException("logout token could not be verified");
		}
		Instant exp = jwt.getExpiresAt();
		return new LogoutToken(jwt.getId(), jwt.getSubject(), jwt.getClaimAsString("sid"), jwt.getClaimAsString("iss"),
				(exp != null) ? exp : Instant.EPOCH);
	}

	static OAuth2TokenValidator<Jwt> claimsValidator(String issuer, String clientId, Duration clockSkew,
			Clock clock) {
		return (jwt) -> {
			String failure = check(jwt, issuer, clientId, clockSkew, clock);
			if (failure == null) {
				return OAuth2TokenValidatorResult.success();
			}
			return OAuth2TokenValidatorResult.failure(new OAuth2Error("invalid_request", failure, null));
		};
	}

	private static @Nullable String check(Jwt jwt, String issuer, String clientId, Duration clockSkew, Clock clock) {
		Instant now = clock.instant();
		Object iss = jwt.getClaims().get("iss");
		if (iss == null || !issuer.equals(iss.toString())) {
			return "iss mismatch";
		}
		List<String> aud = jwt.getAudience();
		if (aud == null || !aud.contains(clientId)) {
			return "aud does not contain the client id";
		}
		Instant iat = jwt.getIssuedAt();
		if (iat == null) {
			return "iat missing";
		}
		if (iat.isAfter(now.plus(clockSkew))) {
			return "iat is in the future";
		}
		Instant exp = jwt.getExpiresAt();
		if (exp == null) {
			return "exp missing";
		}
		if (now.minus(clockSkew).isAfter(exp)) {
			return "logout token expired";
		}
		Object events = jwt.getClaims().get("events");
		if (!(events instanceof Map<?, ?> map) || !map.containsKey(BACKCHANNEL_LOGOUT_EVENT)) {
			return "events lacks the back-channel logout event";
		}
		Object eventValue = map.get(BACKCHANNEL_LOGOUT_EVENT);
		if (!(eventValue instanceof Map<?, ?>)) {
			return "back-channel logout event must be a JSON object";
		}
		String sub = jwt.getSubject();
		String sid = jwt.getClaimAsString("sid");
		if ((sub == null || sub.isBlank()) && (sid == null || sid.isBlank())) {
			return "sub or sid required";
		}
		if (jwt.getClaims().containsKey("nonce")) {
			return "nonce not allowed";
		}
		String jti = jwt.getId();
		if (jti == null || jti.isBlank()) {
			return "jti missing";
		}
		return null;
	}

	/**
	 * A validated logout token.
	 * @param jti token id
	 * @param sub subject ({@code null} when only {@code sid} is present)
	 * @param sid session id ({@code null} when only {@code sub} is present)
	 * @param issuer issuer
	 * @param expiresAt expiry
	 */
	public record LogoutToken(String jti, @Nullable String sub, @Nullable String sid, String issuer,
			Instant expiresAt) {
	}

	/** The logout token was rejected. The message is safe to return to the caller. */
	public static final class InvalidLogoutTokenException extends RuntimeException {

		private static final long serialVersionUID = 1L;

		public InvalidLogoutTokenException(String message) {
			super(message);
		}

	}

}
