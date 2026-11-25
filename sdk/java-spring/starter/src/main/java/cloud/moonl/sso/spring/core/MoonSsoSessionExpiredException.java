package cloud.moonl.sso.spring.core;

import org.jspecify.annotations.Nullable;

/**
 * The refresh token was rejected with {@code invalid_grant}: the user's session at Moon SSO
 * ended (logout, password change, revoked consent, disabled account...). The stored tokens
 * were discarded; the user has to sign in again.
 *
 * <p>When thrown inside a Spring MVC request whose chain contains Spring Security's
 * {@code OAuth2AuthorizationRequestRedirectFilter}, the cause chain contains a
 * {@code ClientAuthorizationRequiredException} so the browser is sent to the login page
 * automatically.
 */
public class MoonSsoSessionExpiredException extends MoonSsoException {

	private static final long serialVersionUID = 1L;

	public MoonSsoSessionExpiredException(@Nullable String errorDescription, @Nullable Throwable cause) {
		super("invalid_grant", errorDescription, 400, null, cause);
	}

}
