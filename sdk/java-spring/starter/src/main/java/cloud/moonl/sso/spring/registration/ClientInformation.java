package cloud.moonl.sso.spring.registration;

import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.jspecify.annotations.Nullable;

/**
 * Response of dynamic client registration (RFC 7591 / 7592). Secrets are only present in the
 * response of the registration itself (and of a webhook URL change); store them securely.
 *
 * @param clientId client id
 * @param clientSecret client secret (confidential clients)
 * @param registrationAccessToken token for RFC 7592 management calls
 * @param registrationClientUri URL for RFC 7592 management calls
 * @param webhookSecret webhook signing secret, when a webhook URL was registered
 * @param status {@code active}, {@code pending_approval} or {@code disabled}
 * @param clientName client name
 * @param redirectUris redirect URIs
 * @param grantTypes grant types
 * @param tokenEndpointAuthMethod token endpoint authentication method
 * @param applicationType {@code web} or {@code native}
 * @param scope space separated scopes
 * @param raw the complete response
 */
public record ClientInformation(@JsonProperty("client_id") String clientId,
		@JsonProperty("client_secret") @Nullable String clientSecret,
		@JsonProperty("registration_access_token") @Nullable String registrationAccessToken,
		@JsonProperty("registration_client_uri") @Nullable String registrationClientUri,
		@JsonProperty("webhook_secret") @Nullable String webhookSecret, @Nullable String status,
		@JsonProperty("client_name") @Nullable String clientName,
		@JsonProperty("redirect_uris") @Nullable List<String> redirectUris,
		@JsonProperty("grant_types") @Nullable List<String> grantTypes,
		@JsonProperty("token_endpoint_auth_method") @Nullable String tokenEndpointAuthMethod,
		@JsonProperty("application_type") @Nullable String applicationType, @Nullable String scope,
		Map<String, Object> raw) {

	public ClientInformation {
		raw = (raw != null) ? Map.copyOf(raw) : Map.of();
	}

	/** Builds the record from a registration response document. */
	@SuppressWarnings("unchecked")
	public static ClientInformation fromMap(Map<String, Object> document) {
		Map<String, Object> raw = new java.util.LinkedHashMap<>();
		document.forEach((k, v) -> {
			if (k != null && v != null) {
				raw.put(k, v);
			}
		});
		return new ClientInformation(str(raw, "client_id"), str(raw, "client_secret"),
				str(raw, "registration_access_token"), str(raw, "registration_client_uri"), str(raw, "webhook_secret"),
				str(raw, "status"), str(raw, "client_name"), (List<String>) list(raw, "redirect_uris"),
				(List<String>) list(raw, "grant_types"), str(raw, "token_endpoint_auth_method"),
				str(raw, "application_type"), str(raw, "scope"), raw);
	}

	private static @Nullable String str(Map<String, Object> m, String key) {
		Object v = m.get(key);
		return (v == null) ? null : v.toString();
	}

	private static @Nullable List<?> list(Map<String, Object> m, String key) {
		Object v = m.get(key);
		return (v instanceof List<?> l) ? List.copyOf(l) : null;
	}

	/** True when the client can be used immediately. */
	public boolean isActive() {
		return "active".equals(this.status);
	}

	/** True when an administrator still has to approve the client. */
	public boolean isPendingApproval() {
		return "pending_approval".equals(this.status);
	}

	@Override
	public String toString() {
		return "ClientInformation[clientId=" + this.clientId + ", status=" + this.status + ", clientName="
				+ this.clientName + "]";
	}

}
