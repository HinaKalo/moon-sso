package cloud.moonl.sso.spring.web;

import cloud.moonl.sso.spring.MoonSsoProperties;
import cloud.moonl.sso.spring.client.MoonSsoTokenRevoker;
import cloud.moonl.sso.spring.core.MoonSsoDiscovery;
import cloud.moonl.sso.spring.jwt.MoonSsoAccessTokenDecoder;

import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;

/**
 * Entry point for applications that define their own {@code SecurityFilterChain}:
 *
 * <pre>{@code
 * @Bean
 * SecurityFilterChain security(HttpSecurity http, MoonSsoSecurity moonSso) {
 *     http.authorizeHttpRequests((a) -> a.requestMatchers("/", "/css/**").permitAll()
 *         .anyRequest().authenticated());
 *     moonSso.apply(http);
 *     return http.build();
 * }
 * }</pre>
 */
public final class MoonSsoSecurity {

	private final MoonSsoProperties properties;

	private final MoonSsoDiscovery discovery;

	private final ClientRegistrationRepository clientRegistrations;

	private final OAuth2AuthorizationRequestResolver authorizationRequestResolver;

	private final OAuth2AuthorizedClientRepository authorizedClients;

	private final MoonSsoTokenRevoker revoker;

	private final MoonSsoAccessTokenDecoder accessTokenDecoder;

	public MoonSsoSecurity(MoonSsoProperties properties, MoonSsoDiscovery discovery,
			ClientRegistrationRepository clientRegistrations,
			OAuth2AuthorizationRequestResolver authorizationRequestResolver,
			OAuth2AuthorizedClientRepository authorizedClients, MoonSsoTokenRevoker revoker,
			MoonSsoAccessTokenDecoder accessTokenDecoder) {
		this.properties = properties;
		this.discovery = discovery;
		this.clientRegistrations = clientRegistrations;
		this.authorizationRequestResolver = authorizationRequestResolver;
		this.authorizedClients = authorizedClients;
		this.revoker = revoker;
		this.accessTokenDecoder = accessTokenDecoder;
	}

	/** A new configurer; apply it with {@code http.with(configurer, customizer)}. */
	public MoonSsoSecurityConfigurer configurer() {
		return new MoonSsoSecurityConfigurer(this.properties, this.discovery, this.clientRegistrations,
				this.authorizationRequestResolver, this.authorizedClients, this.revoker, this.accessTokenDecoder);
	}

	/** Applies the Moon SSO configuration to {@code http}. */
	public HttpSecurity apply(HttpSecurity http) {
		return http.with(configurer(), Customizer.withDefaults());
	}

	/** Path that starts login, {@code /oauth2/authorization/<registration-id>}. */
	public String loginUrl() {
		return "/oauth2/authorization/" + this.properties.getRegistrationId();
	}

}
