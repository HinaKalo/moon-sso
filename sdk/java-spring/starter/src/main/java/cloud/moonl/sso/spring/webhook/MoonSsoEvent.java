package cloud.moonl.sso.spring.webhook;

import java.time.Instant;

import org.jspecify.annotations.Nullable;

/**
 * Base class of the Spring application events published for Moon SSO user events. Listen to a
 * concrete type ({@link UserUpdatedEvent}, {@link UserDeletedEvent}...) or to this class for
 * all of them:
 *
 * <pre>{@code
 * @EventListener
 * void on(UserUpdatedEvent event) {
 *     users.applyIfNewer(event.sub(), event.data().profileVersion(), event.data());
 * }
 * }</pre>
 *
 * Events can arrive more than once and, rarely, out of order: use {@link #id()} to deduplicate
 * and {@link MoonSsoEventData#profileVersion()} to discard stale data.
 */
public abstract class MoonSsoEvent {

	/** Where an event came from. */
	public enum Source {

		/** Pushed to the webhook endpoint. */
		WEBHOOK,

		/** Pulled from {@code /api/v1/users/changes}. */
		CHANGES_FEED

	}

	private final MoonSsoEventPayload payload;

	private final Source source;

	protected MoonSsoEvent(MoonSsoEventPayload payload, Source source) {
		this.payload = payload;
		this.source = source;
	}

	/** Creates the typed event for a payload. */
	public static MoonSsoEvent of(MoonSsoEventPayload payload, Source source) {
		String type = (payload.type() != null) ? payload.type() : "";
		return switch (type) {
			case UserUpdatedEvent.TYPE -> new UserUpdatedEvent(payload, source);
			case UserPasswordChangedEvent.TYPE -> new UserPasswordChangedEvent(payload, source);
			case UserDisabledEvent.TYPE -> new UserDisabledEvent(payload, source);
			case UserEnabledEvent.TYPE -> new UserEnabledEvent(payload, source);
			case UserDeletedEvent.TYPE -> new UserDeletedEvent(payload, source);
			case ConsentRevokedEvent.TYPE -> new ConsentRevokedEvent(payload, source);
			case WebhookPingEvent.TYPE -> new WebhookPingEvent(payload, source);
			default -> new UnknownMoonSsoEvent(payload, source);
		};
	}

	public MoonSsoEventPayload payload() {
		return this.payload;
	}

	public Source source() {
		return this.source;
	}

	/** Event id ({@code evt_<seq>}), stable across redeliveries. */
	public String id() {
		return this.payload.id();
	}

	public long seq() {
		return this.payload.seq();
	}

	public String type() {
		return this.payload.type();
	}

	public @Nullable Instant occurredAt() {
		return this.payload.occurredAt();
	}

	public MoonSsoEventData data() {
		return this.payload.dataOrEmpty();
	}

	/** Client-specific subject of the affected user. */
	public @Nullable String sub() {
		return data().sub();
	}

	@Override
	public String toString() {
		return getClass().getSimpleName() + "[id=" + id() + ", type=" + type() + ", source=" + this.source + "]";
	}

}
