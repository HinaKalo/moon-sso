package cloud.moonl.sso.spring.webhook;

/** The user's profile (username, nickname, avatar) changed: {@code user.updated}. */
public final class UserUpdatedEvent extends MoonSsoEvent {

	/** Wire type. */
	public static final String TYPE = "user.updated";

	public UserUpdatedEvent(MoonSsoEventPayload payload, Source source) {
		super(payload, source);
	}

}
