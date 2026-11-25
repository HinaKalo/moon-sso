package cloud.moonl.sso.spring.registration;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.jspecify.annotations.Nullable;

/**
 * RFC 7591 client metadata for dynamic client registration. Build it with {@link #builder()};
 * unset fields are omitted from the request.
 */
public final class ClientMetadata {

	private final Map<String, Object> values;

	private ClientMetadata(Map<String, Object> values) {
		this.values = Map.copyOf(values);
	}

	public static Builder builder() {
		return new Builder();
	}

	/** The JSON members of the registration request. */
	public Map<String, Object> asMap() {
		return this.values;
	}

	/** Builder of {@link ClientMetadata}. */
	public static final class Builder {

		private final Map<String, Object> values = new LinkedHashMap<>();

		public Builder clientName(String name) {
			return put("client_name", name);
		}

		public Builder redirectUris(List<String> uris) {
			return put("redirect_uris", List.copyOf(uris));
		}

		public Builder postLogoutRedirectUris(List<String> uris) {
			return put("post_logout_redirect_uris", List.copyOf(uris));
		}

		public Builder grantTypes(List<String> grantTypes) {
			return put("grant_types", List.copyOf(grantTypes));
		}

		/** {@code client_secret_basic}, {@code client_secret_post} or {@code none}. */
		public Builder tokenEndpointAuthMethod(String method) {
			return put("token_endpoint_auth_method", method);
		}

		/** {@code web} or {@code native}. */
		public Builder applicationType(String type) {
			return put("application_type", type);
		}

		/** Space separated scopes. */
		public Builder scope(String scope) {
			return put("scope", scope);
		}

		/** {@code RS256} or {@code ES256}. */
		public Builder idTokenSignedResponseAlg(String alg) {
			return put("id_token_signed_response_alg", alg);
		}

		public Builder backchannelLogoutUri(String uri) {
			return put("backchannel_logout_uri", uri);
		}

		public Builder dpopBoundAccessTokens(boolean value) {
			return put("dpop_bound_access_tokens", value);
		}

		public Builder webhookUrl(String url) {
			return put("webhook_url", url);
		}

		public Builder webhookEvents(List<String> events) {
			return put("webhook_events", List.copyOf(events));
		}

		public Builder logoUri(String uri) {
			return put("logo_uri", uri);
		}

		public Builder clientUri(String uri) {
			return put("client_uri", uri);
		}

		public Builder policyUri(String uri) {
			return put("policy_uri", uri);
		}

		public Builder tosUri(String uri) {
			return put("tos_uri", uri);
		}

		public Builder description(String description) {
			return put("description", description);
		}

		/** Any other metadata member. */
		public Builder put(String name, @Nullable Object value) {
			if (value == null) {
				this.values.remove(name);
			}
			else {
				this.values.put(name, value);
			}
			return this;
		}

		public ClientMetadata build() {
			return new ClientMetadata(this.values);
		}

	}

}
