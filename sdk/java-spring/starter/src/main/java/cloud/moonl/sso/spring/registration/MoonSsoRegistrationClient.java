package cloud.moonl.sso.spring.registration;

import java.util.LinkedHashMap;
import java.util.Map;

import org.jspecify.annotations.Nullable;

import cloud.moonl.sso.spring.MoonSsoProperties;
import cloud.moonl.sso.spring.client.MoonSsoTokenRevoker;
import cloud.moonl.sso.spring.core.MoonSsoDiscovery;
import cloud.moonl.sso.spring.core.MoonSsoException;
import cloud.moonl.sso.spring.core.MoonSsoHttp;

import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.util.Assert;
import org.springframework.web.util.UriComponentsBuilder;

/**
 * Account registration from the application's server ({@code POST /api/v1/register}, client
 * authentication with the configured secret) and dynamic client registration (RFC 7591 /
 * RFC 7592).
 */
public final class MoonSsoRegistrationClient {

	private final MoonSsoProperties properties;

	private final MoonSsoDiscovery discovery;

	private final MoonSsoHttp http;

	public MoonSsoRegistrationClient(MoonSsoProperties properties, MoonSsoDiscovery discovery, MoonSsoHttp http) {
		this.properties = properties;
		this.discovery = discovery;
		this.http = http;
	}

	/** {@code GET /api/v1/registration}. */
	public RegistrationInfo registrationInfo() {
		MoonSsoHttp.Response response = this.http.execute(this.http.restClient()
			.get()
			.uri(this.discovery.metadata().apiBase() + "/registration")
			.accept(MediaType.APPLICATION_JSON));
		if (!response.is2xx()) {
			throw this.http.error(response);
		}
		return this.http.read(response, RegistrationInfo.class);
	}

	/**
	 * Creates an end-user account ({@code POST /api/v1/register}). Requires a confidential
	 * client. Errors: 403 {@code registration_closed}, 422 {@code validation_failed} with
	 * {@link MoonSsoException#getField()}, 429 {@code rate_limited}.
	 * @param displayName optional display name
	 */
	public RegistrationResult register(String username, String password, @Nullable String displayName) {
		Assert.hasText(username, "username must not be empty");
		Assert.hasText(password, "password must not be empty");
		Assert.state(this.properties.hasClientSecret(), "moon-sso.client-secret is required to register users");
		Map<String, Object> json = new LinkedHashMap<>();
		json.put("username", username);
		json.put("password", password);
		if (displayName != null && !displayName.isBlank()) {
			json.put("display_name", displayName);
		}
		MoonSsoHttp.Response response = this.http.execute(this.http.restClient()
			.post()
			.uri(this.discovery.metadata().apiBase() + "/register")
			.contentType(MediaType.APPLICATION_JSON)
			.accept(MediaType.APPLICATION_JSON)
			.header(HttpHeaders.AUTHORIZATION,
					MoonSsoTokenRevoker.basic(this.properties.getClientId(), this.properties.getClientSecret()))
			.body(this.http.write(json)));
		if (!response.is2xx()) {
			throw this.http.error(response);
		}
		return this.http.read(response, RegistrationResult.class);
	}

	/**
	 * Registers a new client (RFC 7591) with an initial access token from the developer
	 * center ({@code registerClient(iat, metadata)} in the SDK specification).
	 */
	public ClientInformation registerClient(String initialAccessToken, ClientMetadata metadata) {
		Assert.hasText(initialAccessToken, "initialAccessToken must not be empty");
		Assert.notNull(metadata, "metadata must not be null");
		String endpoint = this.discovery.metadata().registrationEndpoint();
		if (endpoint == null) {
			throw new MoonSsoException("unsupported", "The server does not support dynamic client registration", 0,
					null);
		}
		MoonSsoHttp.Response response = this.http.execute(this.http.restClient()
			.post()
			.uri(endpoint)
			.contentType(MediaType.APPLICATION_JSON)
			.accept(MediaType.APPLICATION_JSON)
			.header(HttpHeaders.AUTHORIZATION, "Bearer " + initialAccessToken)
			.body(this.http.write(metadata.asMap())));
		return clientInformation(response);
	}

	/** Reads a registration (RFC 7592) with its registration access token. */
	public ClientInformation readClient(String clientId, String registrationAccessToken) {
		MoonSsoHttp.Response response = this.http.execute(this.http.restClient()
			.get()
			.uri(java.net.URI.create(managementUri(clientId)))
			.accept(MediaType.APPLICATION_JSON)
			.header(HttpHeaders.AUTHORIZATION, "Bearer " + registrationAccessToken));
		return clientInformation(response);
	}

	/** Replaces a registration's metadata (RFC 7592). */
	public ClientInformation updateClient(String clientId, String registrationAccessToken, ClientMetadata metadata) {
		MoonSsoHttp.Response response = this.http.execute(this.http.restClient()
			.put()
			.uri(java.net.URI.create(managementUri(clientId)))
			.contentType(MediaType.APPLICATION_JSON)
			.accept(MediaType.APPLICATION_JSON)
			.header(HttpHeaders.AUTHORIZATION, "Bearer " + registrationAccessToken)
			.body(this.http.write(metadata.asMap())));
		return clientInformation(response);
	}

	/** Deletes a registration (RFC 7592). */
	public void deleteClient(String clientId, String registrationAccessToken) {
		MoonSsoHttp.Response response = this.http.execute(this.http.restClient()
			.delete()
			.uri(java.net.URI.create(managementUri(clientId)))
			.header(HttpHeaders.AUTHORIZATION, "Bearer " + registrationAccessToken));
		if (!response.is2xx()) {
			throw this.http.error(response);
		}
	}

	@SuppressWarnings("unchecked")
	private ClientInformation clientInformation(MoonSsoHttp.Response response) {
		if (!response.is2xx()) {
			throw this.http.error(response);
		}
		return ClientInformation.fromMap(this.http.read(response, Map.class));
	}

	private String managementUri(String clientId) {
		Assert.hasText(clientId, "clientId must not be empty");
		String endpoint = this.discovery.metadata().registrationEndpoint();
		if (endpoint == null) {
			throw new MoonSsoException("unsupported", "The server does not support dynamic client registration", 0,
					null);
		}
		return UriComponentsBuilder.fromUriString(endpoint + "/{id}").buildAndExpand(clientId).encode().toUriString();
	}

}
