package cloud.moonl.sso.spring.jwt;

import java.time.Clock;
import java.time.Duration;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import org.springframework.security.oauth2.client.oidc.authentication.OidcIdTokenDecoderFactory;
import org.springframework.security.oauth2.client.oidc.authentication.OidcIdTokenValidator;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoderFactory;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

/**
 * ID token decoders for Spring Security's OIDC login: RS256 or ES256 signatures from the shared,
 * rate-limited JWKS cache, {@code iss}, {@code aud == client_id}, {@code azp}, {@code exp} and
 * {@code iat} with the configured clock skew. Nonce is checked by Spring Security during the
 * code exchange and {@code at_hash} by {@code MoonSsoOidcUserService}.
 */
public final class MoonSsoIdTokenDecoderFactory implements JwtDecoderFactory<ClientRegistration> {

	private final JWKSource<SecurityContext> jwkSource;

	private final Duration clockSkew;

	private final Clock clock;

	private final Map<String, Cached> decoders = new ConcurrentHashMap<>();

	public MoonSsoIdTokenDecoderFactory(JWKSource<SecurityContext> jwkSource, Duration clockSkew, Clock clock) {
		this.jwkSource = jwkSource;
		this.clockSkew = clockSkew;
		this.clock = clock;
	}

	@Override
	public JwtDecoder createDecoder(ClientRegistration registration) {
		Cached cached = this.decoders.get(registration.getRegistrationId());
		if (cached != null && cached.registration().equals(registration)) {
			return cached.decoder();
		}
		OidcIdTokenValidator validator = new OidcIdTokenValidator(registration);
		validator.setClockSkew(this.clockSkew);
		validator.setClock(this.clock);
		NimbusJwtDecoder decoder = MoonSsoJwtDecoders.create(this.jwkSource, Set.of(JWSAlgorithm.RS256, JWSAlgorithm.ES256),
				validator, JOSEObjectType.JWT, null);
		decoder.setClaimSetConverter(OidcIdTokenDecoderFactory.createDefaultClaimTypeConverter());
		this.decoders.put(registration.getRegistrationId(), new Cached(registration, decoder));
		return decoder;
	}

	private record Cached(ClientRegistration registration, JwtDecoder decoder) {
	}

}
