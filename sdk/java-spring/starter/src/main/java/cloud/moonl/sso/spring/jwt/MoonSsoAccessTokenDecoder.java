package cloud.moonl.sso.spring.jwt;

import java.time.Clock;
import java.time.Duration;
import java.util.Collection;
import java.util.List;
import java.util.Set;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.JwtIssuerValidator;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.util.Assert;

/**
 * Validates Moon SSO access tokens locally (resource server use): ES256 signature from the
 * issuer's JWKS, header {@code typ == at+jwt}, {@code iss}, {@code exp}, {@code nbf} (with the
 * configured clock skew) and that {@code aud} contains one of the expected audiences.
 */
public final class MoonSsoAccessTokenDecoder implements JwtDecoder {

	private final NimbusJwtDecoder delegate;

	private final List<String> audiences;

	public MoonSsoAccessTokenDecoder(JWKSource<SecurityContext> jwkSource, String issuer,
			Collection<String> audiences, Duration clockSkew, Clock clock) {
		Assert.notEmpty(audiences, "at least one audience is required");
		this.audiences = List.copyOf(audiences);
		JwtTimestampValidator timestamps = new JwtTimestampValidator(clockSkew);
		timestamps.setAllowEmptyExpiryClaim(false);
		timestamps.setClock(clock);
		OAuth2TokenValidator<Jwt> validator = new DelegatingOAuth2TokenValidator<>(timestamps,
				new JwtIssuerValidator(issuer), audienceValidator(this.audiences));
		this.delegate = MoonSsoJwtDecoders.create(jwkSource, Set.of(JWSAlgorithm.ES256), validator,
				MoonSsoJwtDecoders.ACCESS_TOKEN_TYPE);
	}

	@Override
	public Jwt decode(String token) throws JwtException {
		return this.delegate.decode(token);
	}

	/** The audiences this decoder accepts. */
	public List<String> getAudiences() {
		return this.audiences;
	}

	static OAuth2TokenValidator<Jwt> audienceValidator(List<String> expected) {
		OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.INVALID_TOKEN,
				"The access token audience does not contain an accepted value", null);
		return (jwt) -> {
			List<String> aud = jwt.getAudience();
			if (aud != null) {
				for (String a : aud) {
					if (expected.contains(a)) {
						return OAuth2TokenValidatorResult.success();
					}
				}
			}
			return OAuth2TokenValidatorResult.failure(error);
		};
	}

}
