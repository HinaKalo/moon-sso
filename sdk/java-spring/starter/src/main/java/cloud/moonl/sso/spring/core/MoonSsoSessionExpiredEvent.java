package cloud.moonl.sso.spring.core;

/**
 * Published when a user's Moon SSO session is found to be over because refreshing the access
 * token failed with {@code invalid_grant} ({@code SessionExpired} in the SDK specification).
 *
 * @param principalName name of the Spring Security principal whose tokens were discarded
 * @param registrationId client registration id
 */
public record MoonSsoSessionExpiredEvent(String principalName, String registrationId) {
}
