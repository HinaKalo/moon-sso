package cloud.moonl.sso.spring.client;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;

import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;

/**
 * Loads the OIDC user after verifying the ID token's {@code at_hash} against the access token
 * it was issued with (when present). Moon SSO signs ID tokens with RS256 or ES256, both of
 * which use SHA-256 for {@code at_hash}. Also used when a refresh returns a new ID token.
 */
public final class MoonSsoOidcUserService implements OAuth2UserService<OidcUserRequest, OidcUser> {

	private final OAuth2UserService<OidcUserRequest, OidcUser> delegate;

	public MoonSsoOidcUserService() {
		this(new OidcUserService());
	}

	public MoonSsoOidcUserService(OAuth2UserService<OidcUserRequest, OidcUser> delegate) {
		this.delegate = delegate;
	}

	@Override
	public OidcUser loadUser(OidcUserRequest userRequest) throws OAuth2AuthenticationException {
		String atHash = userRequest.getIdToken().getAccessTokenHash();
		if (atHash != null && !atHash.isEmpty()) {
			String expected = atHash(userRequest.getAccessToken().getTokenValue());
			if (!MessageDigest.isEqual(expected.getBytes(StandardCharsets.US_ASCII),
					atHash.getBytes(StandardCharsets.US_ASCII))) {
				throw new OAuth2AuthenticationException(
						new OAuth2Error("invalid_id_token", "ID token at_hash does not match the access token", null));
			}
		}
		return this.delegate.loadUser(userRequest);
	}

	/** {@code base64url(left half of SHA-256(access_token))}. */
	public static String atHash(String accessToken) {
		try {
			byte[] digest = MessageDigest.getInstance("SHA-256").digest(accessToken.getBytes(StandardCharsets.US_ASCII));
			return Base64.getUrlEncoder().withoutPadding().encodeToString(Arrays.copyOf(digest, digest.length / 2));
		}
		catch (NoSuchAlgorithmException ex) {
			throw new IllegalStateException("SHA-256 unavailable", ex);
		}
	}

}
