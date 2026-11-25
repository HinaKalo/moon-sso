package cloud.moonl.sso.spring.webhook;

/** An administrator disabled the account: {@code user.disabled}. */
public final class UserDisabledEvent extends MoonSsoEvent {

	/** Wire type. */
	public static final String TYPE = "user.disabled";

	public UserDisabledEvent(MoonSsoEventPayload payload, Source source) {
		super(payload, source);
	}

}
