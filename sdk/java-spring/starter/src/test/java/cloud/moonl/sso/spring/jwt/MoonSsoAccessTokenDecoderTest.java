package cloud.moonl.sso.spring.jwt;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.function.Consumer;

import com.nimbusds.jwt.JWTClaimsSet;
import org.junit.jupiter.api.Test;

import cloud.moonl.sso.spring.TestKeys;

import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class MoonSsoAccessTokenDecoderTest {

	static final String ISSUER = "https://sso.example.test";

	private final TestKeys keys = new TestKeys();

	private final MoonSsoAccessTokenDecoder decoder = new MoonSsoAccessTokenDecoder(this.keys.jwkSource(), ISSUER,
			List.of("my-client", "https://sso.example.test/api"), Duration.ofSeconds(60), Clock.systemUTC());

	private String token(String typ, Consumer<JWTClaimsSet.Builder> customizer) {
		Instant now = Instant.now();
		JWTClaimsSet.Builder b = new JWTClaimsSet.Builder().issuer(ISSUER)
			.subject("user-1")
			.audience(List.of("my-client"))
			.issueTime(Date.from(now))
			.notBeforeTime(Date.from(now.minusSeconds(5)))
			.expirationTime(Date.from(now.plusSeconds(600)))
			.jwtID("j1")
			.claim("client_id", "my-client")
			.claim("scope", "openid profile");
		customizer.accept(b);
		return this.keys.signEs256(typ, b.build());
	}

	@Test
	void acceptsValidAccessToken() {
		Jwt jwt = this.decoder.decode(token("at+jwt", (b) -> {
		}));
		assertThat(jwt.getSubject()).isEqualTo("user-1");
		assertThat(jwt.getClaimAsString("scope")).isEqualTo("openid profile");
	}

	@Test
	void acceptsAnyConfiguredAudience() {
		assertThat(this.decoder.decode(token("at+jwt", (b) -> b.audience(List.of("x", "https://sso.example.test/api")))))
			.isNotNull();
	}

	@Test
	void rejectsWrongTyp() {
		assertThatThrownBy(() -> this.decoder.decode(token("JWT", (b) -> {
		}))).isInstanceOf(JwtException.class);
		assertThatThrownBy(() -> this.decoder.decode(token(null, (b) -> {
		}))).isInstanceOf(JwtException.class);
	}

	@Test
	void rejectsWrongAudience() {
		assertThatThrownBy(() -> this.decoder.decode(token("at+jwt", (b) -> b.audience("someone-else"))))
			.isInstanceOf(JwtException.class)
			.hasMessageContaining("audience");
	}

	@Test
	void rejectsWrongIssuer() {
		assertThatThrownBy(() -> this.decoder.decode(token("at+jwt", (b) -> b.issuer("https://other.test"))))
			.isInstanceOf(JwtException.class);
	}

	@Test
	void rejectsExpiredAndNotYetValid() {
		Instant past = Instant.now().minusSeconds(3600);
		assertThatThrownBy(() -> this.decoder.decode(token("at+jwt",
				(b) -> b.issueTime(Date.from(past)).notBeforeTime(Date.from(past)).expirationTime(Date.from(past.plusSeconds(600))))))
			.isInstanceOf(JwtException.class);
		Instant future = Instant.now().plusSeconds(600);
		assertThatThrownBy(() -> this.decoder.decode(token("at+jwt", (b) -> b.notBeforeTime(Date.from(future)))))
			.isInstanceOf(JwtException.class);
	}

	@Test
	void rejectsMissingExp() {
		assertThatThrownBy(() -> this.decoder.decode(token("at+jwt", (b) -> b.expirationTime(null))))
			.isInstanceOf(JwtException.class);
	}

	@Test
	void rejectsRs256AccessTokens() {
		JWTClaimsSet claims = new JWTClaimsSet.Builder().issuer(ISSUER)
			.audience("my-client")
			.subject("u")
			.expirationTime(Date.from(Instant.now().plusSeconds(600)))
			.build();
		String rs = this.keys.signRs256("at+jwt", claims);
		assertThatThrownBy(() -> this.decoder.decode(rs)).isInstanceOf(JwtException.class);
	}

}
