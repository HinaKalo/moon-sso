package cloud.moonl.sso.spring.logout;

import org.jspecify.annotations.Nullable;

/**
 * Published after a valid back-channel logout token was received and the matching local
 * sessions were invalidated ({@code onLogout(sub, sid)} in the SDK specification). Listen to it
 * to clean up application state such as caches or WebSocket connections.
 *
 * @param sub subject from the logout token, may be {@code null} when only {@code sid} was sent
 * @param sid Moon SSO session id, may be {@code null} when only {@code sub} was sent
 * @param sessionsEnded number of local HTTP sessions that were invalidated
 */
public record MoonSsoBackChannelLogoutEvent(@Nullable String sub, @Nullable String sid, int sessionsEnded) {
}
