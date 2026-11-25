package cloud.moonl.sso.spring.account;

/**
 * Supplies the access token for API calls.
 */
@FunctionalInterface
public interface MoonSsoTokenSource {

	/**
	 * Returns a usable access token.
	 * @param forceRefresh {@code true} after the API rejected the previous token with 401: the
	 * token must be refreshed even if it has not expired locally
	 * @throws cloud.moonl.sso.spring.core.MoonSsoSessionExpiredException when refreshing failed
	 * with {@code invalid_grant}
	 */
	String accessToken(boolean forceRefresh);

	/** A fixed token (no refresh); useful for tests and tokens obtained elsewhere. */
	static MoonSsoTokenSource of(String accessToken) {
		return (force) -> accessToken;
	}

}
