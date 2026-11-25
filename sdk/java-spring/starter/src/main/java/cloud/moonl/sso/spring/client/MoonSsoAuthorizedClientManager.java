package cloud.moonl.sso.spring.client;

import java.time.Instant;
import java.util.concurrent.locks.ReentrantLock;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.jspecify.annotations.Nullable;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

/**
 * {@link OAuth2AuthorizedClientManager} for signed-in users that serialises authorization per
 * HTTP session (single-flight refresh: concurrent requests of one session wait for the same
 * refresh instead of each rotating the refresh token) and can force a refresh after a
 * resource server answered 401.
 *
 * <p>Token renewal itself is done by the delegate's providers: refresh_token (proactively when
 * less than {@code moon-sso.refresh-skew}, 120 s by default, remains), client_credentials and
 * authorization_code.
 */
public final class MoonSsoAuthorizedClientManager implements OAuth2AuthorizedClientManager {

	private static final int STRIPES = 64;

	private final OAuth2AuthorizedClientManager delegate;

	private final OAuth2AuthorizedClientRepository repository;

	private final ReentrantLock[] locks = new ReentrantLock[STRIPES];

	public MoonSsoAuthorizedClientManager(OAuth2AuthorizedClientManager delegate,
			OAuth2AuthorizedClientRepository repository) {
		this.delegate = delegate;
		this.repository = repository;
		for (int i = 0; i < STRIPES; i++) {
			this.locks[i] = new ReentrantLock();
		}
	}

	@Override
	public @Nullable OAuth2AuthorizedClient authorize(OAuth2AuthorizeRequest authorizeRequest) {
		ReentrantLock lock = lockFor(authorizeRequest.getPrincipal(), currentRequest(authorizeRequest));
		lock.lock();
		try {
			return this.delegate.authorize(authorizeRequest);
		}
		finally {
			lock.unlock();
		}
	}

	/**
	 * Refreshes the access token even though it has not expired locally, typically after an
	 * API answered 401. When another request of the same session already replaced
	 * {@code rejected}, that newer client is returned without calling the token endpoint.
	 * @param rejected the authorized client whose access token was rejected
	 * @param principal the signed-in user
	 * @return the refreshed client, or {@code null} if it cannot be refreshed (no refresh token)
	 */
	public @Nullable OAuth2AuthorizedClient forceRefresh(OAuth2AuthorizedClient rejected, Authentication principal) {
		HttpServletRequest request = currentRequest(null);
		ReentrantLock lock = lockFor(principal, request);
		lock.lock();
		try {
			if (request != null) {
				OAuth2AuthorizedClient current = this.repository
					.loadAuthorizedClient(rejected.getClientRegistration().getRegistrationId(), principal, request);
				if (current != null && !current.getAccessToken()
					.getTokenValue()
					.equals(rejected.getAccessToken().getTokenValue())) {
					return current;
				}
			}
			if (rejected.getRefreshToken() == null) {
				return null;
			}
			OAuth2AccessToken old = rejected.getAccessToken();
			OAuth2AccessToken expired = new OAuth2AccessToken(old.getTokenType(), old.getTokenValue(), Instant.EPOCH,
					Instant.EPOCH.plusSeconds(1), old.getScopes());
			OAuth2AuthorizedClient stale = new OAuth2AuthorizedClient(rejected.getClientRegistration(),
					rejected.getPrincipalName(), expired, rejected.getRefreshToken());
			return this.delegate.authorize(OAuth2AuthorizeRequest.withAuthorizedClient(stale).principal(principal).build());
		}
		finally {
			lock.unlock();
		}
	}

	private ReentrantLock lockFor(@Nullable Authentication principal, @Nullable HttpServletRequest request) {
		String key = null;
		if (request != null) {
			HttpSession session = request.getSession(false);
			if (session != null) {
				key = session.getId();
			}
		}
		if (key == null && principal != null) {
			key = principal.getName();
		}
		int index = (key != null) ? Math.floorMod(key.hashCode(), STRIPES) : 0;
		return this.locks[index];
	}

	private static @Nullable HttpServletRequest currentRequest(@Nullable OAuth2AuthorizeRequest authorizeRequest) {
		if (authorizeRequest != null) {
			Object fromAttributes = authorizeRequest.getAttribute(HttpServletRequest.class.getName());
			if (fromAttributes instanceof HttpServletRequest r) {
				return r;
			}
		}
		RequestAttributes attributes = RequestContextHolder.getRequestAttributes();
		if (attributes instanceof ServletRequestAttributes servlet) {
			return servlet.getRequest();
		}
		return null;
	}

}
