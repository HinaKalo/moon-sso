package cloud.moonl.sso.spring.webhook;

/** The user withdrew the authorization of this application: {@code consent.revoked}. */
public final class ConsentRevokedEvent extends MoonSsoEvent {

	/** Wire type. */
	public static final String TYPE = "consent.revoked";

	public ConsentRevokedEvent(MoonSsoEventPayload payload, Source source) {
		super(payload, source);
	}

}
