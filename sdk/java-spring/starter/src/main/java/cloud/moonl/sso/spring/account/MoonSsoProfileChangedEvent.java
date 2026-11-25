package cloud.moonl.sso.spring.account;

/**
 * Published after a successful profile change made through {@link MoonSsoAccountClient}
 * ({@code onProfileChanged} in the SDK specification).
 *
 * @param profile the profile returned by the server after the change
 */
public record MoonSsoProfileChangedEvent(MoonSsoProfile profile) {
}
