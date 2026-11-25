package cloud.moonl.sso.spring.account;

import cloud.moonl.sso.spring.client.MoonSsoAuthorizedClientManager;
import cloud.moonl.sso.spring.core.MoonSsoException;
import cloud.moonl.sso.spring.core.MoonSsoSessionExpiredException;

import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.ClientAuthorizationRequiredException;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.web.client.ResourceAccessException;

/**
 * Access token of the user signed in to the current request, obtained from (and silently
 * renewed by) the {@link MoonSsoAuthorizedClientManager}.
 */
public final class CurrentUserTokenSource implements MoonSsoTokenSource {

	private final MoonSsoAuthorizedClientManager manager;

	private final String registrationId;

	public CurrentUserTokenSource(MoonSsoAuthorizedClientManager manager, String registrationId) {
		this.manager = manager;
		this.registrationId = registrationId;
	}

	@Override
	public String accessToken(boolean forceRefresh) {
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		if (authentication == null || !authentication.isAuthenticated()
				|| authentication instanceof AnonymousAuthenticationToken) {
			throw new MoonSsoException("login_required", "No signed-in user in the current request", 401, null);
		}
		try {
			OAuth2AuthorizedClient client = this.manager.authorize(OAuth2AuthorizeRequest
				.withClientRegistrationId(this.registrationId)
				.principal(authentication)
				.build());
			if (client == null) {
				throw new MoonSsoException("login_required", "The user has no Moon SSO tokens", 401, null,
						new ClientAuthorizationRequiredException(this.registrationId));
			}
			if (forceRefresh) {
				client = this.manager.forceRefresh(client, authentication);
				if (client == null) {
					throw new MoonSsoException("invalid_token", "Access token rejected and no refresh token available",
							401, null);
				}
			}
			return client.getAccessToken().getTokenValue();
		}
		catch (ClientAuthorizationRequiredException ex) {
			throw new MoonSsoException("login_required", "The user has to sign in", 401, null, ex);
		}
		catch (OAuth2AuthorizationException ex) {
			throw translate(ex, this.registrationId);
		}
	}

	/** Maps a Spring Security authorization failure to the SDK error model. */
	public static MoonSsoException translate(OAuth2AuthorizationException ex, String registrationId) {
		String code = ex.getError().getErrorCode();
		String description = ex.getError().getDescription();
		if (OAuth2ErrorCodes.INVALID_GRANT.equals(code)) {
			ClientAuthorizationRequiredException relogin = new ClientAuthorizationRequiredException(registrationId);
			relogin.initCause(ex);
			return new MoonSsoSessionExpiredException(description, relogin);
		}
		for (Throwable t = ex.getCause(); t != null; t = t.getCause()) {
			if (t instanceof ResourceAccessException) {
				return new MoonSsoException(MoonSsoException.NETWORK, "Token endpoint unreachable", 0, null, ex);
			}
		}
		return new MoonSsoException(code, description, 0, null, ex);
	}

}
