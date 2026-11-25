package cloud.moonl.sso.spring.logout;

import jakarta.servlet.http.HttpSession;
import org.jspecify.annotations.Nullable;

/**
 * Maps Moon SSO sessions ({@code sid}) and subjects ({@code sub}) to local HTTP sessions so a
 * back-channel logout can end them.
 *
 * <p>The default {@link InMemoryMoonSsoSessionRegistry} holds the container's session objects
 * and therefore works for a single instance with container-managed sessions. Applications
 * using Spring Session or several instances should provide their own bean (for example on
 * top of {@code FindByIndexNameSessionRepository}).
 */
public interface MoonSsoSessionRegistry {

	/** Records that {@code session} belongs to the given Moon SSO session and subject. */
	void register(@Nullable String sid, String sub, HttpSession session);

	/**
	 * Ends the local sessions matching a logout token: those with the given {@code sid}
	 * when present (and the same {@code sub} if both are given), otherwise every session of
	 * {@code sub}.
	 * @return number of local sessions invalidated
	 */
	int logout(@Nullable String sub, @Nullable String sid);

}
