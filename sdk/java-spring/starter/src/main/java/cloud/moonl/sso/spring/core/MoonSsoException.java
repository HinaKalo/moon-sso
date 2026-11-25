package cloud.moonl.sso.spring.core;

import org.jspecify.annotations.Nullable;

/**
 * Error raised by every Moon SSO SDK call.
 *
 * <p>Fields follow the SDK error model: {@link #getError()} is an OAuth error code (or
 * {@code network} / {@code invalid_response}), {@link #getErrorDescription()} the
 * server's description, {@link #getStatus()} the HTTP status ({@code 0} when no
 * response was received) and {@link #getField()} the offending field of a 422
 * validation error.
 */
public class MoonSsoException extends RuntimeException {

	private static final long serialVersionUID = 1L;

	/** Error code for transport failures (DNS, connect, reset, timeout). */
	public static final String NETWORK = "network";

	/** Error code for responses that could not be understood. */
	public static final String INVALID_RESPONSE = "invalid_response";

	private final String error;

	private final @Nullable String errorDescription;

	private final int status;

	private final @Nullable String field;

	public MoonSsoException(String error, @Nullable String errorDescription, int status, @Nullable String field) {
		this(error, errorDescription, status, field, null);
	}

	public MoonSsoException(String error, @Nullable String errorDescription, int status, @Nullable String field,
			@Nullable Throwable cause) {
		super(buildMessage(error, errorDescription, status, field), cause);
		this.error = error;
		this.errorDescription = errorDescription;
		this.status = status;
		this.field = field;
	}

	private static String buildMessage(String error, @Nullable String description, int status,
			@Nullable String field) {
		StringBuilder sb = new StringBuilder(error);
		if (status > 0) {
			sb.append(" (HTTP ").append(status).append(')');
		}
		if (description != null && !description.isBlank()) {
			sb.append(": ").append(description);
		}
		if (field != null && !field.isBlank()) {
			sb.append(" [field=").append(field).append(']');
		}
		return sb.toString();
	}

	public String getError() {
		return this.error;
	}

	public @Nullable String getErrorDescription() {
		return this.errorDescription;
	}

	public int getStatus() {
		return this.status;
	}

	public @Nullable String getField() {
		return this.field;
	}

	/** True for transport failures and 5xx/429 responses that may succeed later. */
	public boolean isTransient() {
		return NETWORK.equals(this.error) || this.status == 429 || this.status >= 500;
	}

	/** True when an {@code If-Match} precondition failed (HTTP 412). */
	public boolean isVersionConflict() {
		return this.status == 412;
	}

}
