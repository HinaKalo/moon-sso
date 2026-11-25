package cloud.moonl.sso.spring.jwt;

import java.util.Set;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;

import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

/** Builds Nimbus-backed decoders that pin the JOSE {@code typ} and the accepted algorithms. */
public final class MoonSsoJwtDecoders {

	/** {@code typ} of access tokens (RFC 9068). */
	public static final JOSEObjectType ACCESS_TOKEN_TYPE = new JOSEObjectType("at+jwt");

	/** {@code typ} of back-channel logout tokens. */
	public static final JOSEObjectType LOGOUT_TOKEN_TYPE = new JOSEObjectType("logout+jwt");

	private MoonSsoJwtDecoders() {
	}

	/**
	 * Creates a decoder.
	 * @param jwkSource verification keys
	 * @param algorithms accepted JWS algorithms
	 * @param validator claim validation
	 * @param types accepted {@code typ} header values ({@code null} allows a missing header)
	 */
	public static NimbusJwtDecoder create(JWKSource<SecurityContext> jwkSource, Set<JWSAlgorithm> algorithms,
			OAuth2TokenValidator<Jwt> validator, JOSEObjectType... types) {
		DefaultJWTProcessor<SecurityContext> processor = new DefaultJWTProcessor<>();
		processor.setJWSTypeVerifier(new DefaultJOSEObjectTypeVerifier<>(types));
		processor.setJWSKeySelector(new JWSVerificationKeySelector<>(algorithms, jwkSource));
		// claims are validated by Spring Security validators
		processor.setJWTClaimsSetVerifier((claims, context) -> {
		});
		NimbusJwtDecoder decoder = new NimbusJwtDecoder(processor);
		decoder.setJwtValidator(validator);
		return decoder;
	}

}
