package cloud.moonl.sso.spring.client;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import cloud.moonl.sso.spring.MoonSsoProperties;
import cloud.moonl.sso.spring.core.MoonSsoDiscovery;
import cloud.moonl.sso.spring.core.MoonSsoException;
import cloud.moonl.sso.spring.core.MoonSsoHttp;

import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClient;

/**
 * Revokes tokens at the authorization server ({@code /oauth/revoke}, RFC 7009). Revocation is
 * best effort: failures are logged (without the token) and never propagated.
 */
public final class MoonSsoTokenRevoker {

	private static final Log logger = LogFactory.getLog(MoonSsoTokenRevoker.class);

	private final MoonSsoProperties properties;

	private final MoonSsoDiscovery discovery;

	private final MoonSsoHttp http;

	public MoonSsoTokenRevoker(MoonSsoProperties properties, MoonSsoDiscovery discovery, MoonSsoHttp http) {
		this.properties = properties;
		this.discovery = discovery;
		this.http = http;
	}

	/**
	 * Revokes a refresh token.
	 * @return {@code true} when the server acknowledged the request
	 */
	public boolean revokeRefreshToken(String refreshToken) {
		return revoke(refreshToken, "refresh_token");
	}

	/**
	 * Revokes a token.
	 * @param tokenTypeHint {@code refresh_token} or {@code access_token}
	 * @return {@code true} when the server acknowledged the request
	 */
	public boolean revoke(String token, String tokenTypeHint) {
		try {
			String endpoint = this.discovery.metadata().revocationEndpoint();
			if (endpoint == null) {
				return false;
			}
			MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
			form.add("token", token);
			form.add("token_type_hint", tokenTypeHint);
			RestClient.RequestBodySpec spec = this.http.restClient()
				.post()
				.uri(endpoint)
				.contentType(MediaType.APPLICATION_FORM_URLENCODED);
			applyClientAuthentication(this.properties, spec, form);
			MoonSsoHttp.Response response = this.http.execute(spec.body(form));
			if (!response.is2xx()) {
				logger.debug("Token revocation answered HTTP " + response.status());
				return false;
			}
			return true;
		}
		catch (MoonSsoException ex) {
			logger.debug("Token revocation failed: " + ex.getError());
			return false;
		}
	}

	/**
	 * Adds client authentication ({@code client_secret_basic}, {@code client_secret_post} or
	 * {@code none}) to a form request.
	 */
	static void applyClientAuthentication(MoonSsoProperties properties, RestClient.RequestBodySpec spec,
			MultiValueMap<String, String> form) {
		String method = properties.effectiveClientAuthenticationMethod();
		if ("client_secret_basic".equals(method) && properties.hasClientSecret()) {
			spec.header(HttpHeaders.AUTHORIZATION, basic(properties.getClientId(), properties.getClientSecret()));
		}
		else if ("client_secret_post".equals(method) && properties.hasClientSecret()) {
			form.add("client_id", properties.getClientId());
			form.add("client_secret", properties.getClientSecret());
		}
		else {
			form.add("client_id", properties.getClientId());
		}
	}

	/** HTTP Basic credentials, form-urlencoding id and secret first (RFC 6749 §2.3.1). */
	public static String basic(String clientId, String clientSecret) {
		String id = URLEncoder.encode(clientId, StandardCharsets.UTF_8);
		String secret = URLEncoder.encode(clientSecret, StandardCharsets.UTF_8);
		return "Basic " + java.util.Base64.getEncoder()
			.encodeToString((id + ":" + secret).getBytes(StandardCharsets.UTF_8));
	}

}
