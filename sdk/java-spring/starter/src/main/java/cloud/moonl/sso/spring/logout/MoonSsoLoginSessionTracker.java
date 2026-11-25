package cloud.moonl.sso.spring.logout;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;

import org.springframework.context.ApplicationListener;
import org.springframework.security.authentication.event.InteractiveAuthenticationSuccessEvent;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

/**
 * Registers the HTTP session of every successful Moon SSO login (ID token {@code sid} and
 * {@code sub}) in the {@link MoonSsoSessionRegistry}. It listens to Spring Security's
 * {@link InteractiveAuthenticationSuccessEvent}, which is published after session fixation
 * protection, so it works with any {@code SecurityFilterChain} that uses {@code oauth2Login()}.
 */
public final class MoonSsoLoginSessionTracker implements ApplicationListener<InteractiveAuthenticationSuccessEvent> {

	private final MoonSsoSessionRegistry registry;

	private final String registrationId;

	public MoonSsoLoginSessionTracker(MoonSsoSessionRegistry registry, String registrationId) {
		this.registry = registry;
		this.registrationId = registrationId;
	}

	@Override
	public void onApplicationEvent(InteractiveAuthenticationSuccessEvent event) {
		if (!(event.getAuthentication() instanceof OAuth2AuthenticationToken token)
				|| !this.registrationId.equals(token.getAuthorizedClientRegistrationId())
				|| !(token.getPrincipal() instanceof OidcUser user)) {
			return;
		}
		RequestAttributes attributes = RequestContextHolder.getRequestAttributes();
		if (!(attributes instanceof ServletRequestAttributes servletAttributes)) {
			return;
		}
		HttpServletRequest request = servletAttributes.getRequest();
		HttpSession session = request.getSession(true);
		String sid = user.getIdToken().getClaimAsString("sid");
		this.registry.register(sid, user.getSubject(), session);
	}

}
