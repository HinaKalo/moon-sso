package cloud.moonl.sso.spring.web;

import java.util.LinkedHashMap;
import java.util.Map;

import jakarta.servlet.http.HttpServletRequest;

import cloud.moonl.sso.spring.MoonSsoProperties;
import cloud.moonl.sso.spring.client.AuthorizationResponseIssuerFilter;
import cloud.moonl.sso.spring.client.MoonSsoTokenRevoker;
import cloud.moonl.sso.spring.client.RevokeTokensLogoutHandler;
import cloud.moonl.sso.spring.core.MoonSsoDiscovery;
import cloud.moonl.sso.spring.jwt.MoonSsoAccessTokenDecoder;

import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.OAuth2LoginAuthenticationFilter;
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationEntryPoint;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.DelegatingAuthenticationEntryPoint;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.StringUtils;

/**
 * Applies the Moon SSO setup to an {@link HttpSecurity}:
 * <ul>
 * <li>{@code oauth2Login()} with the PKCE-enforcing authorization request resolver and the
 * configured processing/failure URLs; the ID token decoder, OIDC user service ({@code at_hash})
 * and retrying token client are picked up from the starter's beans;</li>
 * <li>RFC 9207 {@code iss} validation of the authorization response;</li>
 * <li>{@code oauth2Client()} so access tokens refresh silently through the
 * {@code OAuth2AuthorizedClientManager};</li>
 * <li>an HTMX-aware authentication entry point (200 + {@code HX-Redirect});</li>
 * <li>logout that revokes the refresh token and continues with RP-initiated logout at
 * {@code end_session_endpoint};</li>
 * <li>optionally, Bearer access token authentication ({@code moon-sso.resource-server.enabled}).</li>
 * </ul>
 * Obtain instances from {@link MoonSsoSecurity#configurer()}; each instance can be applied to
 * one {@code HttpSecurity}.
 */
public final class MoonSsoSecurityConfigurer extends AbstractHttpConfigurer<MoonSsoSecurityConfigurer, HttpSecurity> {

	private static final String DEFAULT_CALLBACK_PATTERN = "/login/oauth2/code/*";

	private final MoonSsoProperties properties;

	private final MoonSsoDiscovery discovery;

	private final ClientRegistrationRepository clientRegistrations;

	private final OAuth2AuthorizationRequestResolver authorizationRequestResolver;

	private final OAuth2AuthorizedClientRepository authorizedClients;

	private final MoonSsoTokenRevoker revoker;

	private final MoonSsoAccessTokenDecoder accessTokenDecoder;

	private SimpleUrlAuthenticationFailureHandler failureHandler;

	MoonSsoSecurityConfigurer(MoonSsoProperties properties, MoonSsoDiscovery discovery,
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

	/** Login URL that starts the authorization code flow. */
	public String loginUrl() {
		return "/oauth2/authorization/" + this.properties.getRegistrationId();
	}

	@Override
	public void init(HttpSecurity http) {
		MoonSsoProperties.Login login = this.properties.getLogin();
		this.failureHandler = new SimpleUrlAuthenticationFailureHandler(login.getFailureUrl());
		http.oauth2Login((oauth2) -> {
			oauth2.clientRegistrationRepository(this.clientRegistrations);
			oauth2.authorizedClientRepository(this.authorizedClients);
			oauth2.authorizationEndpoint((endpoint) -> endpoint.authorizationRequestResolver(this.authorizationRequestResolver));
			if (StringUtils.hasText(login.getProcessingUrl())) {
				oauth2.loginProcessingUrl(login.getProcessingUrl());
			}
			oauth2.failureHandler(this.failureHandler);
		});
		http.oauth2Client((client) -> {
			client.clientRegistrationRepository(this.clientRegistrations);
			client.authorizedClientRepository(this.authorizedClients);
			client.authorizationCodeGrant((grant) -> grant.authorizationRequestResolver(this.authorizationRequestResolver));
		});
		http.exceptionHandling((exceptions) -> exceptions.authenticationEntryPoint(entryPoint()));
		HttpSessionRequestCache requestCache = new HttpSessionRequestCache();
		requestCache.setRequestMatcher(savedRequestMatcher());
		http.requestCache((cache) -> cache.requestCache(requestCache));
		http.logout((logout) -> {
			if (login.isRevokeOnLogout()) {
				logout.addLogoutHandler(new RevokeTokensLogoutHandler(this.properties.getRegistrationId(),
						this.authorizedClients, this.revoker));
			}
			OidcClientInitiatedLogoutSuccessHandler success = new OidcClientInitiatedLogoutSuccessHandler(
					this.clientRegistrations);
			if (StringUtils.hasText(this.properties.getPostLogoutRedirectUri())) {
				success.setPostLogoutRedirectUri(this.properties.getPostLogoutRedirectUri());
			}
			logout.logoutSuccessHandler(success);
		});
		if (this.properties.getResourceServer().isEnabled()) {
			http.oauth2ResourceServer((rs) -> rs.jwt((jwt) -> jwt.decoder(this.accessTokenDecoder)));
		}
	}

	@Override
	public void configure(HttpSecurity http) {
		String processing = this.properties.getLogin().getProcessingUrl();
		RequestMatcher callback = PathPatternRequestMatcher.withDefaults()
			.matcher(StringUtils.hasText(processing) ? processing : DEFAULT_CALLBACK_PATTERN);
		http.addFilterBefore(new AuthorizationResponseIssuerFilter(callback, this.discovery, this.failureHandler),
				OAuth2LoginAuthenticationFilter.class);
	}

	private AuthenticationEntryPoint entryPoint() {
		LinkedHashMap<RequestMatcher, AuthenticationEntryPoint> entryPoints = new LinkedHashMap<>();
		if (this.properties.getResourceServer().isEnabled()) {
			entryPoints.put(MoonSsoSecurityConfigurer::hasBearerToken, new BearerTokenAuthenticationEntryPoint());
		}
		entryPoints.put(MoonSsoSecurityConfigurer::isXhr, new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED));
		AuthenticationEntryPoint login = new LoginUrlAuthenticationEntryPoint(loginUrl());
		DelegatingAuthenticationEntryPoint.Builder builder = DelegatingAuthenticationEntryPoint.builder();
		for (Map.Entry<RequestMatcher, AuthenticationEntryPoint> e : entryPoints.entrySet()) {
			builder.addEntryPointFor(e.getValue(), e.getKey());
		}
		AuthenticationEntryPoint delegating = builder.defaultEntryPoint(login).build();
		if (!this.properties.getLogin().isHtmx()) {
			return delegating;
		}
		return new HtmxAwareAuthenticationEntryPoint(loginUrl(), delegating);
	}

	private static RequestMatcher savedRequestMatcher() {
		return (request) -> "GET".equals(request.getMethod()) && !HtmxAwareAuthenticationEntryPoint.HTMX_REQUEST.matches(request)
				&& !isXhr(request) && !hasBearerToken(request) && !request.getRequestURI().endsWith("/favicon.ico");
	}

	private static boolean isXhr(HttpServletRequest request) {
		return "XMLHttpRequest".equals(request.getHeader("X-Requested-With"));
	}

	private static boolean hasBearerToken(HttpServletRequest request) {
		String authorization = request.getHeader("Authorization");
		return authorization != null && authorization.regionMatches(true, 0, "Bearer ", 0, 7);
	}

}
