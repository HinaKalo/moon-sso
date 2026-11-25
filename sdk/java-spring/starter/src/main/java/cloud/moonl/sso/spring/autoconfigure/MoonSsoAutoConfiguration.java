package cloud.moonl.sso.spring.autoconfigure;

import java.time.Clock;
import java.util.List;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import cloud.moonl.sso.spring.MoonSsoProperties;
import cloud.moonl.sso.spring.account.CurrentUserTokenSource;
import cloud.moonl.sso.spring.account.MoonSsoAccountClient;
import cloud.moonl.sso.spring.client.MoonSsoAuthorizedClientManager;
import cloud.moonl.sso.spring.client.MoonSsoClientRegistrationRepository;
import cloud.moonl.sso.spring.client.MoonSsoOidcUserService;
import cloud.moonl.sso.spring.client.MoonSsoTokenRevoker;
import cloud.moonl.sso.spring.core.MoonSsoDiscovery;
import cloud.moonl.sso.spring.core.MoonSsoHttp;
import cloud.moonl.sso.spring.core.MoonSsoSessionExpiredEvent;
import cloud.moonl.sso.spring.core.ReplayCache;
import cloud.moonl.sso.spring.jwt.MoonSsoAccessTokenDecoder;
import cloud.moonl.sso.spring.jwt.MoonSsoIdTokenDecoderFactory;
import cloud.moonl.sso.spring.jwt.MoonSsoJwkSource;
import cloud.moonl.sso.spring.logout.BackChannelLogoutFilter;
import cloud.moonl.sso.spring.logout.InMemoryMoonSsoSessionRegistry;
import cloud.moonl.sso.spring.logout.LogoutTokenValidator;
import cloud.moonl.sso.spring.logout.MoonSsoLoginSessionTracker;
import cloud.moonl.sso.spring.logout.MoonSsoSessionRegistry;
import cloud.moonl.sso.spring.registration.MoonSsoRegistrationClient;
import cloud.moonl.sso.spring.sync.MoonSsoUserSync;
import cloud.moonl.sso.spring.web.LoginErrorPageFilter;
import cloud.moonl.sso.spring.web.MoonSsoSecurity;
import cloud.moonl.sso.spring.webhook.MoonSsoWebhookFilter;
import cloud.moonl.sso.spring.webhook.StandardWebhookVerifier;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBooleanProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.security.autoconfigure.SecurityAutoConfiguration;
import org.springframework.boot.security.autoconfigure.UserDetailsServiceAutoConfiguration;
import org.springframework.boot.security.autoconfigure.web.servlet.ConditionalOnDefaultServletWebSecurity;
import org.springframework.boot.security.autoconfigure.web.servlet.SecurityFilterProperties;
import org.springframework.boot.security.autoconfigure.web.servlet.ServletWebSecurityAutoConfiguration;
import org.springframework.boot.security.oauth2.client.autoconfigure.OAuth2ClientAutoConfiguration;
import org.springframework.boot.security.oauth2.client.autoconfigure.servlet.OAuth2ClientWebSecurityAutoConfiguration;
import org.springframework.boot.security.oauth2.server.resource.autoconfigure.OAuth2ResourceServerAutoConfiguration;
import org.springframework.boot.security.oauth2.server.resource.autoconfigure.web.OAuth2ResourceServerWebSecurityAutoConfiguration;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.client.AuthorizedClientServiceOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.ClientAuthorizationException;
import org.springframework.security.oauth2.client.InMemoryOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProviderBuilder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.endpoint.RestClientAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.RestClientClientCredentialsTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.RestClientRefreshTokenTokenResponseClient;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestCustomizers;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * Auto-configuration of the Moon SSO starter. Active when {@code moon-sso.issuer} is set.
 */
@AutoConfiguration(before = { OAuth2ClientAutoConfiguration.class, OAuth2ClientWebSecurityAutoConfiguration.class,
		OAuth2ResourceServerAutoConfiguration.class, OAuth2ResourceServerWebSecurityAutoConfiguration.class,
		ServletWebSecurityAutoConfiguration.class, SecurityAutoConfiguration.class,
		UserDetailsServiceAutoConfiguration.class })
@ConditionalOnClass({ ClientRegistrationRepository.class, HttpSecurity.class })
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@ConditionalOnNonEmptyProperty("moon-sso.issuer")
@EnableConfigurationProperties(MoonSsoProperties.class)
public final class MoonSsoAutoConfiguration {

	/** Order of the webhook and back-channel logout filters: before Spring Security. */
	public static final int ENDPOINT_FILTER_ORDER = SecurityFilterProperties.DEFAULT_FILTER_ORDER - 10;

	// ---------------------------------------------------------------- core

	@Bean
	@ConditionalOnMissingBean
	MoonSsoHttp moonSsoHttp(MoonSsoProperties properties) {
		return new MoonSsoHttp(properties.getConnectTimeout(), properties.getReadTimeout());
	}

	@Bean
	@ConditionalOnMissingBean
	MoonSsoDiscovery moonSsoDiscovery(MoonSsoProperties properties, MoonSsoHttp http) {
		Assert.hasText(properties.getIssuer(), "moon-sso.issuer must be set");
		Assert.hasText(properties.getClientId(), "moon-sso.client-id must be set");
		return new MoonSsoDiscovery(properties.normalizedIssuer(), http, properties.getDiscoveryTtl(),
				Clock.systemUTC());
	}

	@Bean
	@ConditionalOnMissingBean
	MoonSsoJwkSource moonSsoJwkSource(MoonSsoDiscovery discovery, MoonSsoHttp http) {
		return new MoonSsoJwkSource(discovery, http);
	}

	@Bean
	@ConditionalOnMissingBean
	MoonSsoAccessTokenDecoder moonSsoAccessTokenDecoder(MoonSsoProperties properties, MoonSsoJwkSource jwkSource) {
		List<String> audiences = properties.getResourceServer().getAudiences().isEmpty()
				? List.of(properties.getClientId()) : properties.getResourceServer().getAudiences();
		return new MoonSsoAccessTokenDecoder(jwkSource, properties.normalizedIssuer(), audiences,
				properties.getClockSkew(), Clock.systemUTC());
	}

	@Bean
	@ConditionalOnMissingBean
	ReplayCache moonSsoReplayCache(MoonSsoProperties properties) {
		java.time.Duration window = properties.getBackchannelLogout().getReplayWindow();
		java.time.Duration webhookWindow = properties.getWebhook().getTolerance().multipliedBy(2);
		return new ReplayCache.InMemory(window.compareTo(webhookWindow) > 0 ? window : webhookWindow, 100_000,
				Clock.systemUTC());
	}

	@Bean
	@ConditionalOnMissingBean
	MoonSsoTokenRevoker moonSsoTokenRevoker(MoonSsoProperties properties, MoonSsoDiscovery discovery,
			MoonSsoHttp http) {
		return new MoonSsoTokenRevoker(properties, discovery, http);
	}

	@Bean
	@ConditionalOnMissingBean
	MoonSsoRegistrationClient moonSsoRegistrationClient(MoonSsoProperties properties, MoonSsoDiscovery discovery,
			MoonSsoHttp http) {
		return new MoonSsoRegistrationClient(properties, discovery, http);
	}

	// ---------------------------------------------------------------- OAuth2 client

	@Configuration(proxyBeanMethods = false)
	static class OAuth2ClientConfiguration {

		@Bean
		@ConditionalOnMissingBean(ClientRegistrationRepository.class)
		MoonSsoClientRegistrationRepository moonSsoClientRegistrationRepository(MoonSsoProperties properties,
				MoonSsoDiscovery discovery) {
			return new MoonSsoClientRegistrationRepository(properties, discovery);
		}

		@Bean
		@ConditionalOnMissingBean
		OAuth2AuthorizedClientRepository moonSsoAuthorizedClientRepository() {
			return new HttpSessionOAuth2AuthorizedClientRepository();
		}

		@Bean
		@ConditionalOnMissingBean
		OAuth2AuthorizedClientService moonSsoAuthorizedClientService(ClientRegistrationRepository registrations) {
			return new InMemoryOAuth2AuthorizedClientService(registrations);
		}

		@Bean
		@ConditionalOnMissingBean(OAuth2AuthorizationRequestResolver.class)
		DefaultOAuth2AuthorizationRequestResolver moonSsoAuthorizationRequestResolver(
				ClientRegistrationRepository registrations) {
			DefaultOAuth2AuthorizationRequestResolver resolver = new DefaultOAuth2AuthorizationRequestResolver(
					registrations, OAuth2AuthorizationRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI);
			// PKCE S256 is mandatory at Moon SSO, also for confidential clients
			resolver.setAuthorizationRequestCustomizer(OAuth2AuthorizationRequestCustomizers.withPkce());
			return resolver;
		}

		@Bean
		@ConditionalOnMissingBean
		RestClientAuthorizationCodeTokenResponseClient moonSsoAuthorizationCodeTokenResponseClient(MoonSsoHttp http) {
			RestClientAuthorizationCodeTokenResponseClient client = new RestClientAuthorizationCodeTokenResponseClient();
			client.setRestClient(http.tokenEndpointRestClient());
			return client;
		}

		@Bean
		@ConditionalOnMissingBean
		MoonSsoIdTokenDecoderFactory moonSsoIdTokenDecoderFactory(MoonSsoProperties properties,
				MoonSsoJwkSource jwkSource) {
			return new MoonSsoIdTokenDecoderFactory(jwkSource, properties.getClockSkew(), Clock.systemUTC());
		}

		@Bean
		@ConditionalOnMissingBean
		MoonSsoOidcUserService moonSsoOidcUserService() {
			return new MoonSsoOidcUserService();
		}

		@Bean
		@ConditionalOnMissingBean
		MoonSsoAuthorizedClientManager moonSsoAuthorizedClientManager(MoonSsoProperties properties,
				ClientRegistrationRepository registrations, OAuth2AuthorizedClientRepository authorizedClients,
				MoonSsoHttp http, ApplicationEventPublisher publisher) {
			DefaultOAuth2AuthorizedClientManager delegate = new DefaultOAuth2AuthorizedClientManager(registrations,
					authorizedClients);
			delegate.setAuthorizedClientProvider(authorizedClientProvider(properties, http, publisher));
			// Only invalid_grant ends the session; network errors, 5xx and 429 keep the tokens.
			delegate.setAuthorizationFailureHandler((exception, principal, attributes) -> {
				if (!OAuth2ErrorCodes.INVALID_GRANT.equals(exception.getError().getErrorCode())) {
					return;
				}
				String registrationId = (exception instanceof ClientAuthorizationException cae)
						? cae.getClientRegistrationId() : properties.getRegistrationId();
				HttpServletRequest request = (HttpServletRequest) attributes.get(HttpServletRequest.class.getName());
				HttpServletResponse response = (HttpServletResponse) attributes
					.get(HttpServletResponse.class.getName());
				if (request != null && response != null) {
					authorizedClients.removeAuthorizedClient(registrationId, principal, request, response);
				}
				publisher.publishEvent(new MoonSsoSessionExpiredEvent(principal.getName(), registrationId));
			});
			return new MoonSsoAuthorizedClientManager(delegate, authorizedClients);
		}

		static OAuth2AuthorizedClientProvider authorizedClientProvider(MoonSsoProperties properties, MoonSsoHttp http,
				ApplicationEventPublisher publisher) {
			RestClientRefreshTokenTokenResponseClient refresh = new RestClientRefreshTokenTokenResponseClient();
			refresh.setRestClient(http.tokenEndpointRestClient());
			RestClientClientCredentialsTokenResponseClient clientCredentials = new RestClientClientCredentialsTokenResponseClient();
			clientCredentials.setRestClient(http.tokenEndpointRestClient());
			return OAuth2AuthorizedClientProviderBuilder.builder()
				.authorizationCode()
				.refreshToken((builder) -> builder.accessTokenResponseClient(refresh)
					.clockSkew(properties.getRefreshSkew())
					.eventPublisher(publisher))
				.clientCredentials((builder) -> builder.accessTokenResponseClient(clientCredentials)
					.clockSkew(properties.getRefreshSkew()))
				.build();
		}

		@Bean
		@ConditionalOnMissingBean
		MoonSsoAccountClient moonSsoAccountClient(MoonSsoProperties properties, MoonSsoDiscovery discovery,
				MoonSsoHttp http, MoonSsoAuthorizedClientManager manager, ApplicationEventPublisher publisher) {
			return new MoonSsoAccountClient(discovery, http,
					new CurrentUserTokenSource(manager, properties.getRegistrationId()), publisher);
		}

		@Bean
		@ConditionalOnMissingBean
		@ConditionalOnNonEmptyProperty("moon-sso.client-secret")
		@ConditionalOnBean(MoonSsoClientRegistrationRepository.class)
		MoonSsoUserSync moonSsoUserSync(MoonSsoProperties properties, MoonSsoDiscovery discovery, MoonSsoHttp http,
				MoonSsoClientRegistrationRepository registrations, OAuth2AuthorizedClientService clientService,
				ApplicationEventPublisher publisher) {
			AuthorizedClientServiceOAuth2AuthorizedClientManager manager = new AuthorizedClientServiceOAuth2AuthorizedClientManager(
					registrations, clientService);
			manager.setAuthorizedClientProvider(authorizedClientProvider(properties, http, publisher));
			return new MoonSsoUserSync(discovery, http, manager, clientService, registrations.syncRegistrationId(),
					properties.getClientId(), properties.getSync().getPageSize(), publisher);
		}

		@Bean
		@ConditionalOnMissingBean
		MoonSsoSecurity moonSsoSecurity(MoonSsoProperties properties, MoonSsoDiscovery discovery,
				ClientRegistrationRepository registrations, OAuth2AuthorizationRequestResolver resolver,
				OAuth2AuthorizedClientRepository authorizedClients, MoonSsoTokenRevoker revoker,
				MoonSsoAccessTokenDecoder accessTokenDecoder) {
			return new MoonSsoSecurity(properties, discovery, registrations, resolver, authorizedClients, revoker,
					accessTokenDecoder);
		}

	}

	@Bean
	FilterRegistrationBean<LoginErrorPageFilter> moonSsoLoginErrorPageFilter(MoonSsoProperties properties) {
		FilterRegistrationBean<LoginErrorPageFilter> registration = new FilterRegistrationBean<>(
				new LoginErrorPageFilter("/oauth2/authorization/" + properties.getRegistrationId()));
		registration.setName("moonSsoLoginErrorPageFilter");
		registration.addUrlPatterns(LoginErrorPageFilter.PATH);
		registration.setOrder(ENDPOINT_FILTER_ORDER);
		return registration;
	}

	// ---------------------------------------------------------------- default security

	@Configuration(proxyBeanMethods = false)
	@ConditionalOnDefaultServletWebSecurity
	@ConditionalOnBooleanProperty(name = "moon-sso.login.default-security-filter-chain", matchIfMissing = true)
	static class DefaultSecurityFilterChainConfiguration {

		@Bean
		SecurityFilterChain moonSsoSecurityFilterChain(HttpSecurity http, MoonSsoProperties properties,
				MoonSsoSecurity moonSso) {
			List<String> permitAll = properties.getLogin().getPermitAll();
			http.authorizeHttpRequests((requests) -> {
				if (!permitAll.isEmpty()) {
					requests.requestMatchers(permitAll.toArray(String[]::new)).permitAll();
				}
				requests.anyRequest().authenticated();
			});
			moonSso.apply(http);
			return http.build();
		}

	}

	// ---------------------------------------------------------------- back-channel logout

	@Configuration(proxyBeanMethods = false)
	@ConditionalOnBooleanProperty(name = "moon-sso.backchannel-logout.enabled", matchIfMissing = true)
	static class BackChannelLogoutConfiguration {

		@Bean
		@ConditionalOnMissingBean(MoonSsoSessionRegistry.class)
		InMemoryMoonSsoSessionRegistry moonSsoSessionRegistry() {
			return new InMemoryMoonSsoSessionRegistry();
		}

		@Bean
		MoonSsoLoginSessionTracker moonSsoLoginSessionTracker(MoonSsoSessionRegistry registry,
				MoonSsoProperties properties) {
			return new MoonSsoLoginSessionTracker(registry, properties.getRegistrationId());
		}

		@Bean
		@ConditionalOnMissingBean
		LogoutTokenValidator moonSsoLogoutTokenValidator(MoonSsoProperties properties, MoonSsoJwkSource jwkSource) {
			return new LogoutTokenValidator(jwkSource, properties.normalizedIssuer(), properties.getClientId(),
					properties.getClockSkew(), Clock.systemUTC());
		}

		@Bean
		FilterRegistrationBean<BackChannelLogoutFilter> moonSsoBackChannelLogoutFilter(MoonSsoProperties properties,
				LogoutTokenValidator validator, ReplayCache replayCache, MoonSsoSessionRegistry registry,
				ApplicationEventPublisher publisher) {
			String path = properties.getBackchannelLogout().getPath();
			BackChannelLogoutFilter filter = new BackChannelLogoutFilter(path, validator, replayCache, registry,
					publisher);
			FilterRegistrationBean<BackChannelLogoutFilter> registration = new FilterRegistrationBean<>(filter);
			registration.setName("moonSsoBackChannelLogoutFilter");
			registration.addUrlPatterns(path);
			registration.setOrder(ENDPOINT_FILTER_ORDER);
			return registration;
		}

	}

	// ---------------------------------------------------------------- webhooks

	@Configuration(proxyBeanMethods = false)
	@ConditionalOnBooleanProperty(name = "moon-sso.webhook.enabled", matchIfMissing = true)
	@ConditionalOnNonEmptyProperty("moon-sso.webhook.secret")
	static class WebhookConfiguration {

		@Bean
		@ConditionalOnMissingBean
		StandardWebhookVerifier moonSsoWebhookVerifier(MoonSsoProperties properties) {
			return new StandardWebhookVerifier(properties.getWebhook().getSecret(),
					properties.getWebhook().getTolerance(), Clock.systemUTC());
		}

		@Bean
		FilterRegistrationBean<MoonSsoWebhookFilter> moonSsoWebhookFilter(MoonSsoProperties properties,
				StandardWebhookVerifier verifier, ReplayCache replayCache, MoonSsoHttp http,
				ApplicationEventPublisher publisher) {
			String path = properties.getWebhook().getPath();
			Assert.state(StringUtils.hasText(path), "moon-sso.webhook.path must not be empty");
			MoonSsoWebhookFilter filter = new MoonSsoWebhookFilter(path, verifier, replayCache, http.json(), publisher,
					properties.getWebhook().getMaxBodyBytes());
			FilterRegistrationBean<MoonSsoWebhookFilter> registration = new FilterRegistrationBean<>(filter);
			registration.setName("moonSsoWebhookFilter");
			registration.addUrlPatterns(path);
			registration.setOrder(ENDPOINT_FILTER_ORDER);
			return registration;
		}

	}

}
