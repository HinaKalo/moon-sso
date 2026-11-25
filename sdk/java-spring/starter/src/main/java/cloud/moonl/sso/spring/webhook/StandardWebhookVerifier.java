package cloud.moonl.sso.spring.webhook;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Duration;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.util.Assert;

/**
 * Verifies <a href="https://www.standardwebhooks.com/">Standard Webhooks</a> signatures.
 *
 * <p>The signed content is {@code "{webhook-id}.{webhook-timestamp}.{body}"}, signed with
 * HMAC-SHA256 using the base64-decoded part of the secret after {@code whsec_}. The
 * {@code webhook-signature} header may contain several space separated {@code v1,<base64>}
 * signatures; any match is accepted (constant time comparison). Timestamps further than the
 * tolerance (5 minutes by default) from now are rejected.
 */
public final class StandardWebhookVerifier {

	private static final String SECRET_PREFIX = "whsec_";

	private final SecretKeySpec key;

	private final Duration tolerance;

	private final Clock clock;

	public StandardWebhookVerifier(String secret, Duration tolerance, Clock clock) {
		Assert.hasText(secret, "webhook secret must not be empty");
		String encoded = secret.startsWith(SECRET_PREFIX) ? secret.substring(SECRET_PREFIX.length()) : secret;
		byte[] raw;
		try {
			raw = Base64.getDecoder().decode(encoded);
		}
		catch (IllegalArgumentException ex) {
			throw new IllegalArgumentException("webhook secret is not valid base64 after the whsec_ prefix");
		}
		Assert.isTrue(raw.length > 0, "webhook secret must not be empty");
		this.key = new SecretKeySpec(raw, "HmacSHA256");
		this.tolerance = tolerance;
		this.clock = clock;
	}

	public StandardWebhookVerifier(String secret) {
		this(secret, Duration.ofMinutes(5), Clock.systemUTC());
	}

	/**
	 * Verifies a delivery.
	 * @param id {@code webhook-id} header
	 * @param timestamp {@code webhook-timestamp} header (unix seconds)
	 * @param signatureHeader {@code webhook-signature} header
	 * @param body raw request body
	 * @throws WebhookVerificationException if the delivery must be rejected
	 */
	public void verify(String id, String timestamp, String signatureHeader, byte[] body) {
		if (id == null || id.isBlank() || timestamp == null || timestamp.isBlank() || signatureHeader == null
				|| signatureHeader.isBlank()) {
			throw new WebhookVerificationException("missing webhook headers");
		}
		long ts;
		try {
			ts = Long.parseLong(timestamp.trim());
		}
		catch (NumberFormatException ex) {
			throw new WebhookVerificationException("invalid webhook-timestamp");
		}
		long now = this.clock.instant().getEpochSecond();
		if (Math.abs(now - ts) > this.tolerance.toSeconds()) {
			throw new WebhookVerificationException("webhook-timestamp outside the tolerance window");
		}
		byte[] expected = mac(id, ts, body);
		for (String candidate : signatureHeader.trim().split(" +")) {
			int comma = candidate.indexOf(',');
			if (comma <= 0 || !"v1".equals(candidate.substring(0, comma))) {
				continue;
			}
			byte[] given;
			try {
				given = Base64.getDecoder().decode(candidate.substring(comma + 1));
			}
			catch (IllegalArgumentException ex) {
				continue;
			}
			if (MessageDigest.isEqual(expected, given)) {
				return;
			}
		}
		throw new WebhookVerificationException("no matching webhook signature");
	}

	/** Computes the {@code v1,<base64>} signature for a message (useful in tests). */
	public String sign(String id, long timestamp, byte[] body) {
		return "v1," + Base64.getEncoder().encodeToString(mac(id, timestamp, body));
	}

	private byte[] mac(String id, long timestamp, byte[] body) {
		try {
			Mac mac = Mac.getInstance("HmacSHA256");
			mac.init(this.key);
			mac.update((id + "." + timestamp + ".").getBytes(StandardCharsets.UTF_8));
			mac.update(body);
			return mac.doFinal();
		}
		catch (NoSuchAlgorithmException | InvalidKeyException ex) {
			throw new IllegalStateException("HmacSHA256 unavailable", ex);
		}
	}

}
