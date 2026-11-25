package cloud.moonl.sso.spring.webhook;

/** The account was deleted; only {@code sub} and {@code status} remain: {@code user.deleted}. */
public final class UserDeletedEvent extends MoonSsoEvent {

	/** Wire type. */
	public static final String TYPE = "user.deleted";

	public UserDeletedEvent(MoonSsoEventPayload payload, Source source) {
		super(payload, source);
	}

}
