package cloud.moonl.sso.spring.webhook;

/** An event type this SDK version does not know yet; inspect {@link #type()} and {@link #payload()}. */
public final class UnknownMoonSsoEvent extends MoonSsoEvent {

	public UnknownMoonSsoEvent(MoonSsoEventPayload payload, Source source) {
		super(payload, source);
	}

}
