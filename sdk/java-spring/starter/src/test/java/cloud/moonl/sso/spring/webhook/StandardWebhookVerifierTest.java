package cloud.moonl.sso.spring.webhook;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class StandardWebhookVerifierTest {

	// Test vector from docs/sdk-spec.md §5.2
	static final String SECRET = "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw";

	static final String ID = "msg_p5jXN8AQM9LWM0D4loKWxJek";

	static final long TIMESTAMP = 1614265330L;

	static final byte[] BODY = "{\"test\": 2432232314}".getBytes(StandardCharsets.UTF_8);

	static final String SIGNATURE = "v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE=";

	private final StandardWebhookVerifier verifier = new StandardWebhookVerifier(SECRET, Duration.ofMinutes(5),
			Clock.fixed(Instant.ofEpochSecond(TIMESTAMP), ZoneOffset.UTC));

	@Test
	void specTestVectorSignature() {
		assertThat(this.verifier.sign(ID, TIMESTAMP, BODY)).isEqualTo(SIGNATURE);
	}

	@Test
	void specTestVectorVerifies() {
		assertThatNoException().isThrownBy(() -> this.verifier.verify(ID, Long.toString(TIMESTAMP), SIGNATURE, BODY));
	}

	@Test
	void anyOfSeveralSignaturesMayMatch() {
		String header = "v1,Zm9vYmFy v2,abc " + SIGNATURE;
		assertThatNoException().isThrownBy(() -> this.verifier.verify(ID, Long.toString(TIMESTAMP), header, BODY));
	}

	@Test
	void tamperedBodyIsRejected() {
		byte[] tampered = "{\"test\": 2432232315}".getBytes(StandardCharsets.UTF_8);
		assertThatThrownBy(() -> this.verifier.verify(ID, Long.toString(TIMESTAMP), SIGNATURE, tampered))
			.isInstanceOf(WebhookVerificationException.class);
	}

	@Test
	void otherMessageIdIsRejected() {
		assertThatThrownBy(() -> this.verifier.verify("msg_other", Long.toString(TIMESTAMP), SIGNATURE, BODY))
			.isInstanceOf(WebhookVerificationException.class);
	}

	@Test
	void timestampOutsideToleranceIsRejected() {
		StandardWebhookVerifier late = new StandardWebhookVerifier(SECRET, Duration.ofMinutes(5),
				Clock.fixed(Instant.ofEpochSecond(TIMESTAMP + 301), ZoneOffset.UTC));
		assertThatThrownBy(() -> late.verify(ID, Long.toString(TIMESTAMP), SIGNATURE, BODY))
			.isInstanceOf(WebhookVerificationException.class)
			.hasMessageContaining("tolerance");
		StandardWebhookVerifier early = new StandardWebhookVerifier(SECRET, Duration.ofMinutes(5),
				Clock.fixed(Instant.ofEpochSecond(TIMESTAMP - 301), ZoneOffset.UTC));
		assertThatThrownBy(() -> early.verify(ID, Long.toString(TIMESTAMP), SIGNATURE, BODY))
			.isInstanceOf(WebhookVerificationException.class);
		StandardWebhookVerifier edge = new StandardWebhookVerifier(SECRET, Duration.ofMinutes(5),
				Clock.fixed(Instant.ofEpochSecond(TIMESTAMP + 300), ZoneOffset.UTC));
		assertThatNoException().isThrownBy(() -> edge.verify(ID, Long.toString(TIMESTAMP), SIGNATURE, BODY));
	}

	@Test
	void missingOrMalformedHeadersAreRejected() {
		assertThatThrownBy(() -> this.verifier.verify(ID, "not-a-number", SIGNATURE, BODY))
			.isInstanceOf(WebhookVerificationException.class);
		assertThatThrownBy(() -> this.verifier.verify(ID, Long.toString(TIMESTAMP), null, BODY))
			.isInstanceOf(WebhookVerificationException.class);
		assertThatThrownBy(() -> this.verifier.verify(null, Long.toString(TIMESTAMP), SIGNATURE, BODY))
			.isInstanceOf(WebhookVerificationException.class);
		assertThatThrownBy(() -> this.verifier.verify(ID, Long.toString(TIMESTAMP), "v1,%%%", BODY))
			.isInstanceOf(WebhookVerificationException.class);
	}

	@Test
	void secretWithoutPrefixIsAccepted() {
		StandardWebhookVerifier bare = new StandardWebhookVerifier(SECRET.substring("whsec_".length()),
				Duration.ofMinutes(5), Clock.fixed(Instant.ofEpochSecond(TIMESTAMP), ZoneOffset.UTC));
		assertThat(bare.sign(ID, TIMESTAMP, BODY)).isEqualTo(SIGNATURE);
	}

}
