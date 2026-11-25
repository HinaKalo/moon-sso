package cloud.moonl.sso.spring.client;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jspecify.annotations.Nullable;

import cloud.moonl.sso.spring.MoonSsoProperties;
import cloud.moonl.sso.spring.core.MoonSsoDiscovery;
import cloud.moonl.sso.spring.core.MoonSsoException;
import cloud.moonl.sso.spring.core.MoonSsoProviderMetadata;

import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;

/**
 * Client registrations built lazily from the issuer's discovery document, so the application
 * starts even while the authorization server is unreachable and picks up endpoint changes
 * after the discovery cache expires.
 *
 * <ul>
 * <li>{@code moon-sso.registration-id} (default {@code moon-sso}): authorization code flow,
 * PKCE S256 forced for every client type (the server requires it).</li>
 * <li>{@code <registration-id>-sync}: client_credentials with scope {@code users:sync}; only
 * when a client secret is configured.</li>
 * </ul>
 */
public final class MoonSsoClientRegistrationRepository
		implements ClientRegistrationRepository, Iterable<ClientRegistration> {

	/** Suffix of the client_credentials registration id. */
	public static final String SYNC_SUFFIX = "-sync";

	private static final Log logger = LogFactory.getLog(MoonSsoClientRegistrationRepository.class);

	private final MoonSsoProperties properties;

	private final MoonSsoDiscovery discovery;

	private volatile @Nullable Built built;

	public MoonSsoClientRegistrationRepository(MoonSsoProperties properties, MoonSsoDiscovery discovery) {
		this.properties = properties;
		this.discovery = discovery;
	}

	/** Registration id of the login (authorization code) registration. */
	public String loginRegistrationId() {
		return this.properties.getRegistrationId();
	}

	/** Registration id of the client_credentials registration. */
	public String syncRegistrationId() {
		return this.properties.getRegistrationId() + SYNC_SUFFIX;
	}

	@Override
	public @Nullable ClientRegistration findByRegistrationId(String registrationId) {
		if (loginRegistrationId().equals(registrationId)) {
			return registrations().login();
		}
		if (syncRegistrationId().equals(registrationId)) {
			return registrations().sync();
		}
		return null;
	}

	/**
	 * Iterates the registrations. Spring Security calls this while building the filter chain
	 * (to render login links); if the authorization server is unreachable at that moment the
	 * iterator is empty instead of failing application startup. Lookups by id keep retrying
	 * discovery.
	 */
	@Override
	public Iterator<ClientRegistration> iterator() {
		Built b;
		try {
			b = registrations();
		}
		catch (MoonSsoException ex) {
			logger.warn("Moon SSO discovery unavailable (" + ex.getError()
					+ "); client registrations will be resolved on first use");
			return Collections.emptyIterator();
		}
		List<ClientRegistration> all = new ArrayList<>(2);
		all.add(b.login());
		if (b.sync() != null) {
			all.add(b.sync());
		}
		return all.iterator();
	}

	private Built registrations() {
		MoonSsoProviderMetadata metadata = this.discovery.metadata();
		Built current = this.built;
		if (current != null && current.metadata() == metadata) {
			return current;
		}
		synchronized (this) {
			current = this.built;
			if (current != null && current.metadata() == metadata) {
				return current;
			}
			Built fresh = new Built(metadata, buildLogin(metadata), buildSync(metadata));
			this.built = fresh;
			return fresh;
		}
	}

	private ClientRegistration buildLogin(MoonSsoProviderMetadata metadata) {
		ClientRegistration.Builder builder = ClientRegistration.withRegistrationId(loginRegistrationId())
			.clientId(this.properties.getClientId())
			.clientAuthenticationMethod(
					new ClientAuthenticationMethod(this.properties.effectiveClientAuthenticationMethod()))
			.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
			.redirectUri(this.properties.getRedirectUri())
			.scope(this.properties.getScopes())
			.authorizationUri(metadata.authorizationEndpoint())
			.tokenUri(metadata.tokenEndpoint())
			.jwkSetUri(metadata.jwksUri())
			.issuerUri(metadata.issuer())
			.userNameAttributeName(this.properties.getLogin().getUserNameAttribute())
			.providerConfigurationMetadata(metadata.raw())
			.clientName("Moon SSO")
			.clientSettings(ClientRegistration.ClientSettings.builder().requireProofKey(true).build());
		if (this.properties.hasClientSecret()) {
			builder.clientSecret(this.properties.getClientSecret());
		}
		String userinfo = metadata.userinfoEndpoint();
		if (userinfo != null) {
			builder.userInfoUri(userinfo);
		}
		return builder.build();
	}

	private @Nullable ClientRegistration buildSync(MoonSsoProviderMetadata metadata) {
		if (!this.properties.hasClientSecret()) {
			return null;
		}
		return ClientRegistration.withRegistrationId(syncRegistrationId())
			.clientId(this.properties.getClientId())
			.clientSecret(this.properties.getClientSecret())
			.clientAuthenticationMethod(
					new ClientAuthenticationMethod(this.properties.effectiveClientAuthenticationMethod()))
			.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
			.scope(this.properties.getSync().getScope())
			.tokenUri(metadata.tokenEndpoint())
			.jwkSetUri(metadata.jwksUri())
			.issuerUri(metadata.issuer())
			.providerConfigurationMetadata(metadata.raw())
			.clientName("Moon SSO (sync)")
			.build();
	}

	private record Built(MoonSsoProviderMetadata metadata, ClientRegistration login,
			@Nullable ClientRegistration sync) {
	}

}
