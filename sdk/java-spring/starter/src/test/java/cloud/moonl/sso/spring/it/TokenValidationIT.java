package cloud.moonl.sso.spring.it;

import java.time.Clock;
import java.time.Duration;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import cloud.moonl.sso.spring.MoonSsoProperties;
import cloud.moonl.sso.spring.client.MoonSsoClientRegistrationRepository;
import cloud.moonl.sso.spring.client.MoonSsoOidcUserService;
import cloud.moonl.sso.spring.core.MoonSsoDiscovery;
import cloud.moonl.sso.spring.core.MoonSsoHttp;
import cloud.moonl.sso.spring.jwt.MoonSsoAccessTokenDecoder;
import cloud.moonl.sso.spring.jwt.MoonSsoIdTokenDecoderFactory;
import cloud.moonl.sso.spring.jwt.MoonSsoJwkSource;

import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** Local validation of real testbed tokens. */
@Tag("testbed")
class TokenValidationIT {

	private final MoonSsoHttp http = new MoonSsoHttp(Duration.ofSeconds(10), Duration.ofSeconds(30));

	private final MoonSsoDiscovery discovery = new MoonSsoDiscovery(Testbed.URL, this.http, Duration.ofHours(1),
			Clock.systemUTC());

	private final MoonSsoJwkSource jwks = new MoonSsoJwkSource(this.discovery, this.http);

	@BeforeAll
	static void requireTestbed() {
		assertThat(Testbed.reachable()).as("Moon SSO testbed reachable at " + Testbed.URL).isTrue();
	}

	private MoonSsoAccessTokenDecoder decoder(String... audiences) {
		return new MoonSsoAccessTokenDecoder(this.jwks, Testbed.URL, List.of(audiences), Duration.ofSeconds(60),
				Clock.systemUTC());
	}

	@Test
	void accessTokenDecoderAcceptsRealTokenAndRejectsWrongAudience() {
		Testbed.User user = Testbed.createUser();
		Map<String, Object> tokens = Testbed.challengeLogin(Testbed.NATIVE_CLIENT, user,
				"openid profile offline_access profile:write");
		String accessToken = (String) tokens.get("access_token");

		Jwt jwt = decoder(Testbed.NATIVE_CLIENT).decode(accessToken);
		assertThat(jwt.getSubject()).isEqualTo(user.publicSub());
		assertThat(jwt.getHeaders()).containsEntry("typ", "at+jwt").containsEntry("alg", "ES256");
		assertThat(jwt.getAudience()).contains(Testbed.NATIVE_CLIENT, this.discovery.metadata().apiAudience());
		assertThat(jwt.getClaimAsString("client_id")).isEqualTo(Testbed.NATIVE_CLIENT);

		// API scopes add the API audience
		assertThat(decoder(this.discovery.metadata().apiAudience()).decode(accessToken).getSubject())
			.isEqualTo(user.publicSub());

		assertThatThrownBy(() -> decoder("some-other-client").decode(accessToken)).isInstanceOf(JwtException.class)
			.hasMessageContaining("audience");

		// an ID token is not an access token (typ JWT, RS256)
		assertThatThrownBy(() -> decoder(Testbed.NATIVE_CLIENT).decode((String) tokens.get("id_token")))
			.isInstanceOf(JwtException.class);

		// tampering breaks the signature
		String tampered = accessToken.substring(0, accessToken.length() - 4)
				+ (accessToken.endsWith("AAAA") ? "BBBB" : "AAAA");
		assertThatThrownBy(() -> decoder(Testbed.NATIVE_CLIENT).decode(tampered)).isInstanceOf(JwtException.class);
	}

	@Test
	void idTokenDecoderValidatesRealIdTokenAndAtHash() {
		Testbed.User user = Testbed.createUser();
		Map<String, Object> tokens = Testbed.challengeLogin(Testbed.NATIVE_CLIENT, user, "openid profile");
		MoonSsoProperties properties = new MoonSsoProperties();
		properties.setIssuer(Testbed.URL);
		properties.setClientId(Testbed.NATIVE_CLIENT);
		ClientRegistration registration = new MoonSsoClientRegistrationRepository(properties, this.discovery)
			.findByRegistrationId("moon-sso");

		Jwt idToken = new MoonSsoIdTokenDecoderFactory(this.jwks, Duration.ofSeconds(60), Clock.systemUTC())
			.createDecoder(registration)
			.decode((String) tokens.get("id_token"));
		assertThat(idToken.getSubject()).isEqualTo(user.publicSub());
		assertThat(idToken.getClaimAsString("preferred_username")).isEqualTo(user.username());
		assertThat(idToken.getClaimAsString("at_hash"))
			.isEqualTo(MoonSsoOidcUserService.atHash((String) tokens.get("access_token")));

		// an ID token for another client is rejected
		properties.setClientId("another-client");
		ClientRegistration other = new MoonSsoClientRegistrationRepository(properties, this.discovery)
			.findByRegistrationId("moon-sso");
		assertThatThrownBy(() -> new MoonSsoIdTokenDecoderFactory(this.jwks, Duration.ofSeconds(60), Clock.systemUTC())
			.createDecoder(other)
			.decode((String) tokens.get("id_token"))).isInstanceOf(JwtException.class);
	}

}
