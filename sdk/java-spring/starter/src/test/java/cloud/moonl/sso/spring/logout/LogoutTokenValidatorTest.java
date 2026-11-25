package cloud.moonl.sso.spring.logout;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.Map;
import java.util.function.Consumer;

import com.nimbusds.jwt.JWTClaimsSet;
import org.junit.jupiter.api.Test;

import cloud.moonl.sso.spring.TestKeys;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class LogoutTokenValidatorTest {

	static final String ISSUER = "https://sso.example.test";

	static final String CLIENT = "client-1";

	private final TestKeys keys = new TestKeys();

	private final LogoutTokenValidator validator = new LogoutTokenValidator(this.keys.jwkSource(), ISSUER, CLIENT,
			Duration.ofSeconds(60), Clock.systemUTC());

	private String token(Consumer<JWTClaimsSet.Builder> customizer) {
		return this.keys.signRs256("logout+jwt", TestKeys.logoutClaims(ISSUER, CLIENT, customizer));
	}

	@Test
	void acceptsValidRs256Token() {
		LogoutTokenValidator.LogoutToken t = this.validator.validate(token((b) -> {
		}));
		assertThat(t.sub()).isEqualTo("user-sub");
		assertThat(t.sid()).isEqualTo("sid-1");
		assertThat(t.jti()).startsWith("jti-");
		assertThat(t.issuer()).isEqualTo(ISSUER);
	}

	@Test
	void acceptsValidEs256Token() {
		String token = this.keys.signEs256("logout+jwt", TestKeys.logoutClaims(ISSUER, CLIENT, (b) -> {
		}));
		assertThat(this.validator.validate(token).sid()).isEqualTo("sid-1");
	}

	@Test
	void acceptsSidOnlyAndSubOnly() {
		assertThat(this.validator.validate(token((b) -> b.subject(null))).sub()).isNull();
		assertThat(this.validator.validate(token((b) -> b.claim("sid", null))).sid()).isNull();
	}

	@Test
	void rejectsWrongTyp() {
		String idTokenTyped = this.keys.signRs256("JWT", TestKeys.logoutClaims(ISSUER, CLIENT, (b) -> {
		}));
		assertRejected(idTokenTyped);
		String untyped = this.keys.signRs256(null, TestKeys.logoutClaims(ISSUER, CLIENT, (b) -> {
		}));
		assertRejected(untyped);
		String accessTokenTyped = this.keys.signEs256("at+jwt", TestKeys.logoutClaims(ISSUER, CLIENT, (b) -> {
		}));
		assertRejected(accessTokenTyped);
	}

	@Test
	void rejectsWrongIssuer() {
		assertRejected(token((b) -> b.issuer("https://evil.example.test")), "iss");
	}

	@Test
	void rejectsWrongAudience() {
		assertRejected(token((b) -> b.audience("other-client")), "aud");
	}

	@Test
	void acceptsAudienceList() {
		assertThat(this.validator.validate(token((b) -> b.audience(java.util.List.of("x", CLIENT))))).isNotNull();
	}

	@Test
	void rejectsMissingEvent() {
		assertRejected(token((b) -> b.claim("events", Map.of("urn:other", Map.of()))), "event");
		assertRejected(token((b) -> b.claim("events", null)), "event");
	}

	@Test
	void rejectsNonce() {
		assertRejected(token((b) -> b.claim("nonce", "n-1")), "nonce");
	}

	@Test
	void rejectsMissingSubAndSid() {
		assertRejected(token((b) -> b.subject(null).claim("sid", null)), "sub or sid");
	}

	@Test
	void rejectsMissingJti() {
		assertRejected(token((b) -> b.jwtID(null)), "jti");
	}

	@Test
	void rejectsExpiredToken() {
		Instant past = Instant.now().minusSeconds(600);
		assertRejected(token((b) -> b.issueTime(Date.from(past)).expirationTime(Date.from(past.plusSeconds(120)))));
	}

	@Test
	void rejectsIatInTheFuture() {
		Instant future = Instant.now().plusSeconds(300);
		assertRejected(token((b) -> b.issueTime(Date.from(future)).expirationTime(Date.from(future.plusSeconds(120)))),
				"future");
	}

	@Test
	void toleratesSmallClockSkew() {
		Instant soon = Instant.now().plusSeconds(30);
		assertThat(this.validator
			.validate(token((b) -> b.issueTime(Date.from(soon)).expirationTime(Date.from(soon.plusSeconds(120))))))
			.isNotNull();
	}

	@Test
	void rejectsSignatureFromUnknownKey() {
		TestKeys other = new TestKeys();
		String forged = other.signRs256("logout+jwt", TestKeys.logoutClaims(ISSUER, CLIENT, (b) -> {
		}));
		assertRejected(forged);
	}

	@Test
	void rejectsGarbage() {
		assertRejected("not.a.jwt");
		assertRejected("");
		assertRejected(null);
	}

	private void assertRejected(String token) {
		assertThatThrownBy(() -> this.validator.validate(token))
			.isInstanceOf(LogoutTokenValidator.InvalidLogoutTokenException.class);
	}

	private void assertRejected(String token, String messagePart) {
		assertThatThrownBy(() -> this.validator.validate(token))
			.isInstanceOf(LogoutTokenValidator.InvalidLogoutTokenException.class)
			.hasMessageContaining(messagePart);
	}

}
