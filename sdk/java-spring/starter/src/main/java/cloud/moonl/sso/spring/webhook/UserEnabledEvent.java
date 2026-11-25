package cloud.moonl.sso.spring.webhook;

/** A disabled account was enabled again: {@code user.enabled}. */
public final class UserEnabledEvent extends MoonSsoEvent {

	/** Wire type. */
	public static final String TYPE = "user.enabled";

	public UserEnabledEvent(MoonSsoEventPayload payload, Source source) {
		super(payload, source);
	}

}
