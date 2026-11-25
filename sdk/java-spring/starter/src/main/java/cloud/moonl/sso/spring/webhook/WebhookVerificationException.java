package cloud.moonl.sso.spring.webhook;

/** A webhook delivery failed signature or timestamp verification. */
public class WebhookVerificationException extends RuntimeException {

	private static final long serialVersionUID = 1L;

	public WebhookVerificationException(String message) {
		super(message);
	}

}
