package cloud.moonl.sso.spring.webhook;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Test;
import tools.jackson.databind.DeserializationFeature;
import tools.jackson.databind.json.JsonMapper;

import cloud.moonl.sso.spring.core.ReplayCache;

import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import static org.assertj.core.api.Assertions.assertThat;

class MoonSsoWebhookFilterTest {

	static final String SECRET = "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw";

	private final StandardWebhookVerifier verifier = new StandardWebhookVerifier(SECRET, Duration.ofMinutes(5),
			Clock.systemUTC());

	private final List<Object> published = new ArrayList<>();

	private boolean failListener;

	private final MoonSsoWebhookFilter filter = new MoonSsoWebhookFilter("/moon-sso/webhooks", this.verifier,
			new ReplayCache.InMemory(Duration.ofMinutes(10), 1000, Clock.systemUTC()),
			JsonMapper.builder().disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES).build(), (event) -> {
				if (this.failListener) {
					throw new IllegalStateException("listener failed");
				}
				this.published.add(event);
			}, 64 * 1024);

	static String body(String id, String type, long pv, String name) {
		return "{\"id\":\"" + id + "\",\"seq\":42,\"type\":\"" + type + "\",\"occurred_at\":\"2026-11-20T08:00:00.123456Z\","
				+ "\"data\":{\"sub\":\"sub-1\",\"status\":\"active\",\"preferred_username\":\"alice\",\"name\":\"" + name
				+ "\",\"nickname\":\"" + name + "\",\"picture\":null,\"profile_version\":" + pv
				+ ",\"updated_at\":1763625600,\"changed\":[\"nickname\"]}}";
	}

	private MockHttpServletResponse deliver(String webhookId, String body, String signature, long ts) throws Exception {
		MockHttpServletRequest request = new MockHttpServletRequest("POST", "/moon-sso/webhooks");
		request.setContentType("application/json");
		request.setContent(body.getBytes(StandardCharsets.UTF_8));
		request.addHeader("webhook-id", webhookId);
		request.addHeader("webhook-timestamp", Long.toString(ts));
		request.addHeader("webhook-signature", signature);
		MockHttpServletResponse response = new MockHttpServletResponse();
		this.filter.doFilter(request, response, new MockFilterChain());
		return response;
	}

	private MockHttpServletResponse deliver(String webhookId, String body) throws Exception {
		long ts = Instant.now().getEpochSecond();
		return deliver(webhookId, body, this.verifier.sign(webhookId, ts, body.getBytes(StandardCharsets.UTF_8)), ts);
	}

	@Test
	void verifiedDeliveryPublishesTypedEvent() throws Exception {
		MockHttpServletResponse response = deliver("evt_42", body("evt_42", "user.updated", 7, "Alice"));
		assertThat(response.getStatus()).isEqualTo(204);
		assertThat(this.published).singleElement().isInstanceOf(UserUpdatedEvent.class);
		UserUpdatedEvent event = (UserUpdatedEvent) this.published.get(0);
		assertThat(event.id()).isEqualTo("evt_42");
		assertThat(event.seq()).isEqualTo(42);
		assertThat(event.sub()).isEqualTo("sub-1");
		assertThat(event.source()).isEqualTo(MoonSsoEvent.Source.WEBHOOK);
		assertThat(event.data().preferredUsername()).isEqualTo("alice");
		assertThat(event.data().profileVersion()).isEqualTo(7L);
		assertThat(event.data().changed()).containsExactly("nickname");
		assertThat(event.data().picture()).isNull();
		assertThat(event.occurredAt()).isNotNull();
	}

	@Test
	void everyEventTypeMapsToItsClass() throws Exception {
		String[][] types = { { "user.password_changed", "UserPasswordChangedEvent" },
				{ "user.disabled", "UserDisabledEvent" }, { "user.enabled", "UserEnabledEvent" },
				{ "user.deleted", "UserDeletedEvent" }, { "consent.revoked", "ConsentRevokedEvent" },
				{ "ping", "WebhookPingEvent" }, { "user.future_thing", "UnknownMoonSsoEvent" } };
		int i = 0;
		for (String[] t : types) {
			String id = "evt_t" + i++;
			assertThat(deliver(id, body(id, t[0], 100 + i, "n")).getStatus()).isEqualTo(204);
			assertThat(this.published.get(this.published.size() - 1).getClass().getSimpleName()).isEqualTo(t[1]);
		}
	}

	@Test
	void badSignatureIsRejected() throws Exception {
		String body = body("evt_1", "user.updated", 1, "A");
		long ts = Instant.now().getEpochSecond();
		MockHttpServletResponse response = deliver("evt_1", body, "v1,AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
				ts);
		assertThat(response.getStatus()).isEqualTo(401);
		assertThat(this.published).isEmpty();
	}

	@Test
	void oldTimestampIsRejected() throws Exception {
		String body = body("evt_1", "user.updated", 1, "A");
		long ts = Instant.now().minusSeconds(600).getEpochSecond();
		MockHttpServletResponse response = deliver("evt_1", body,
				this.verifier.sign("evt_1", ts, body.getBytes(StandardCharsets.UTF_8)), ts);
		assertThat(response.getStatus()).isEqualTo(401);
		assertThat(this.published).isEmpty();
	}

	@Test
	void duplicateDeliveryIsAcknowledgedOnce() throws Exception {
		String body = body("evt_9", "user.updated", 3, "A");
		assertThat(deliver("evt_9", body).getStatus()).isEqualTo(204);
		assertThat(deliver("evt_9", body).getStatus()).isEqualTo(204);
		assertThat(this.published).hasSize(1);
	}

	@Test
	void staleProfileVersionIsDropped() throws Exception {
		assertThat(deliver("evt_20", body("evt_20", "user.updated", 20, "new")).getStatus()).isEqualTo(204);
		assertThat(deliver("evt_19", body("evt_19", "user.updated", 19, "old")).getStatus()).isEqualTo(204);
		assertThat(this.published).hasSize(1);
		assertThat(((MoonSsoEvent) this.published.get(0)).data().name()).isEqualTo("new");
	}

	@Test
	void listenerFailureAnswers500AndAllowsRedelivery() throws Exception {
		String body = body("evt_5", "user.updated", 5, "A");
		this.failListener = true;
		assertThat(deliver("evt_5", body).getStatus()).isEqualTo(500);
		this.failListener = false;
		assertThat(deliver("evt_5", body).getStatus()).isEqualTo(204);
		assertThat(this.published).hasSize(1);
	}

	@Test
	void malformedJsonIsRejected() throws Exception {
		assertThat(deliver("evt_x", "{not json").getStatus()).isEqualTo(400);
	}

}
