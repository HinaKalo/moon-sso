package cloud.moonl.sso.spring.client;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.jspecify.annotations.Nullable;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.web.authentication.logout.LogoutHandler;

/**
 * On local logout, revokes the user's refresh token at Moon SSO and removes the authorized
 * client. Revocation failures never prevent the logout.
 */
public final class RevokeTokensLogoutHandler implements LogoutHandler {

	private final String registrationId;

	private final OAuth2AuthorizedClientRepository repository;

	private final MoonSsoTokenRevoker revoker;

	public RevokeTokensLogoutHandler(String registrationId, OAuth2AuthorizedClientRepository repository,
			MoonSsoTokenRevoker revoker) {
		this.registrationId = registrationId;
		this.repository = repository;
		this.revoker = revoker;
	}

	@Override
	public void logout(HttpServletRequest request, HttpServletResponse response,
			@Nullable Authentication authentication) {
		if (authentication == null) {
			return;
		}
		OAuth2AuthorizedClient client = this.repository.loadAuthorizedClient(this.registrationId, authentication,
				request);
		if (client == null) {
			return;
		}
		if (client.getRefreshToken() != null) {
			this.revoker.revokeRefreshToken(client.getRefreshToken().getTokenValue());
		}
		this.repository.removeAuthorizedClient(this.registrationId, authentication, request, response);
	}

}
