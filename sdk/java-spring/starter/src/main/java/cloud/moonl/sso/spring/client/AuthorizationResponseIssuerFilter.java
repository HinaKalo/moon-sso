package cloud.moonl.sso.spring.client;

import java.io.IOException;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import cloud.moonl.sso.spring.core.MoonSsoDiscovery;
import cloud.moonl.sso.spring.core.MoonSsoException;

import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Validates the RFC 9207 {@code iss} parameter of authorization responses before Spring
 * Security's {@code OAuth2LoginAuthenticationFilter} redeems the code. A response whose
 * {@code iss} differs from the configured issuer is rejected; a missing {@code iss} is
 * rejected when the server advertises {@code authorization_response_iss_parameter_supported}
 * (Moon SSO always does). This defends against mix-up attacks.
 */
public final class AuthorizationResponseIssuerFilter extends OncePerRequestFilter {

	private static final Log logger = LogFactory.getLog(AuthorizationResponseIssuerFilter.class);

	private final RequestMatcher callbackMatcher;

	private final MoonSsoDiscovery discovery;

	private final AuthenticationFailureHandler failureHandler;

	public AuthorizationResponseIssuerFilter(RequestMatcher callbackMatcher, MoonSsoDiscovery discovery,
			AuthenticationFailureHandler failureHandler) {
		this.callbackMatcher = callbackMatcher;
		this.discovery = discovery;
		this.failureHandler = failureHandler;
	}

	@Override
	protected boolean shouldNotFilter(HttpServletRequest request) {
		boolean authorizationResponse = StringUtils.hasText(request.getParameter("state"))
				&& (StringUtils.hasText(request.getParameter("code"))
						|| StringUtils.hasText(request.getParameter("error")));
		return !authorizationResponse || !this.callbackMatcher.matches(request);
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws ServletException, IOException {
		String[] values = request.getParameterValues("iss");
		String iss = (values != null && values.length == 1) ? values[0] : null;
		String expected = this.discovery.issuer();
		if (values != null && values.length > 1) {
			reject(request, response, "duplicate iss parameter");
			return;
		}
		if (iss == null) {
			boolean required;
			try {
				required = this.discovery.metadata().authorizationResponseIssParameterSupported();
			}
			catch (MoonSsoException ex) {
				required = true;
			}
			if (required) {
				reject(request, response, "authorization response lacks the iss parameter");
				return;
			}
		}
		else if (!expected.equals(iss)) {
			reject(request, response, "authorization response iss does not match the issuer");
			return;
		}
		chain.doFilter(request, response);
	}

	private void reject(HttpServletRequest request, HttpServletResponse response, String reason)
			throws IOException, ServletException {
		logger.warn("Rejected authorization response: " + reason);
		this.failureHandler.onAuthenticationFailure(request, response,
				new OAuth2AuthenticationException(new OAuth2Error("invalid_request", reason, null)));
	}

}
