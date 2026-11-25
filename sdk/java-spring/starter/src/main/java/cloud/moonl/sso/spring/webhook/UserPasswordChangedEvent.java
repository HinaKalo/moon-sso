package cloud.moonl.sso.spring.webhook;

/** The user changed the password; other sessions were signed out: {@code user.password_changed}. */
public final class UserPasswordChangedEvent extends MoonSsoEvent {

	/** Wire type. */
	public static final String TYPE = "user.password_changed";

	public UserPasswordChangedEvent(MoonSsoEventPayload payload, Source source) {
		super(payload, source);
	}

}
