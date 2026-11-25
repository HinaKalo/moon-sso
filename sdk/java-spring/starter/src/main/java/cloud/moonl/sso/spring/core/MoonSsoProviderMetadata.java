package cloud.moonl.sso.spring.core;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.jspecify.annotations.Nullable;

/**
 * The authorization server's discovery document ({@code /.well-known/openid-configuration}).
 *
 * @param raw the complete document
 */
public record MoonSsoProviderMetadata(Map<String, Object> raw) {

	public MoonSsoProviderMetadata {
		raw = Collections.unmodifiableMap(new LinkedHashMap<>(raw));
	}

	public String issuer() {
		return required("issuer");
	}

	public String authorizationEndpoint() {
		return required("authorization_endpoint");
	}

	public String tokenEndpoint() {
		return required("token_endpoint");
	}

	public String jwksUri() {
		return required("jwks_uri");
	}

	public @Nullable String userinfoEndpoint() {
		return optional("userinfo_endpoint");
	}

	public @Nullable String endSessionEndpoint() {
		return optional("end_session_endpoint");
	}

	public @Nullable String revocationEndpoint() {
		return optional("revocation_endpoint");
	}

	public @Nullable String introspectionEndpoint() {
		return optional("introspection_endpoint");
	}

	public @Nullable String registrationEndpoint() {
		return optional("registration_endpoint");
	}

	public @Nullable String authorizationChallengeEndpoint() {
		return optional("authorization_challenge_endpoint");
	}

	/** Audience of access tokens that carry API scopes ({@code moon_api_audience}). */
	public String apiAudience() {
		String v = optional("moon_api_audience");
		return (v != null) ? v : issuer() + "/api";
	}

	/** Base URL of the account and sync API ({@code <issuer>/api/v1}). */
	public String apiBase() {
		return issuer() + "/api/v1";
	}

	/** Whether authorization responses carry the RFC 9207 {@code iss} parameter. */
	public boolean authorizationResponseIssParameterSupported() {
		return Boolean.TRUE.equals(this.raw.get("authorization_response_iss_parameter_supported"));
	}

	@SuppressWarnings("unchecked")
	public List<String> scopesSupported() {
		Object v = this.raw.get("scopes_supported");
		return (v instanceof List<?> l) ? (List<String>) l : List.of();
	}

	private String required(String key) {
		String v = optional(key);
		if (v == null || v.isBlank()) {
			throw new MoonSsoException(MoonSsoException.INVALID_RESPONSE, "Discovery document lacks " + key, 0, null);
		}
		return v;
	}

	private @Nullable String optional(String key) {
		Object v = this.raw.get(key);
		return (v == null) ? null : v.toString();
	}

}
