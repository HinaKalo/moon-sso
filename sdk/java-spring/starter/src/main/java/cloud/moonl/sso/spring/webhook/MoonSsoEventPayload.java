package cloud.moonl.sso.spring.webhook;

import java.time.Instant;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.jspecify.annotations.Nullable;

/**
 * Wire format of an event, identical for webhooks, the changes feed and SSE.
 *
 * @param id event id ({@code evt_<seq>})
 * @param seq per-client sequence number
 * @param type event type, e.g. {@code user.updated}
 * @param occurredAt when the change happened
 * @param data user snapshot as seen by this client
 */
public record MoonSsoEventPayload(String id, long seq, String type,
		@JsonProperty("occurred_at") @Nullable Instant occurredAt, @Nullable MoonSsoEventData data) {

	/** Event data, never {@code null}. */
	public MoonSsoEventData dataOrEmpty() {
		return (this.data != null) ? this.data : MoonSsoEventData.EMPTY;
	}

}
