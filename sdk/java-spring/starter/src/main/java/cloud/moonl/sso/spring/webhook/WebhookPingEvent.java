package cloud.moonl.sso.spring.webhook;

/** Test delivery sent from the developer center: {@code ping}. {@link MoonSsoEventData#clientId()} is set. */
public final class WebhookPingEvent extends MoonSsoEvent {

	/** Wire type. */
	public static final String TYPE = "ping";

	public WebhookPingEvent(MoonSsoEventPayload payload, Source source) {
		super(payload, source);
	}

}
