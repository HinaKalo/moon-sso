package cloud.moonl.sso.spring.web;

import java.io.IOException;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.RequestMatcher;

/**
 * Entry point that understands <a href="https://htmx.org/">HTMX</a>: an HTMX request
 * ({@code HX-Request: true}) that needs authentication gets {@code 200} with an
 * {@code HX-Redirect} header pointing at the login URL, so HTMX navigates the whole page
 * instead of swapping the login page into a fragment. Other requests go to the delegate
 * (normally a redirect to {@code /oauth2/authorization/moon-sso}).
 */
public final class HtmxAwareAuthenticationEntryPoint implements AuthenticationEntryPoint {

	/** Matches requests sent by HTMX. */
	public static final RequestMatcher HTMX_REQUEST = (request) -> "true".equalsIgnoreCase(request.getHeader("HX-Request"));

	private final String loginUrl;

	private final AuthenticationEntryPoint delegate;

	/**
	 * @param loginUrl login URL; a path is prefixed with the context path, an absolute URL is
	 * used as is
	 * @param delegate entry point for non-HTMX requests
	 */
	public HtmxAwareAuthenticationEntryPoint(String loginUrl, AuthenticationEntryPoint delegate) {
		this.loginUrl = loginUrl;
		this.delegate = delegate;
	}

	@Override
	public void commence(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException authException) throws IOException, ServletException {
		if (HTMX_REQUEST.matches(request)) {
			String target = this.loginUrl.startsWith("/") ? request.getContextPath() + this.loginUrl : this.loginUrl;
			response.setStatus(HttpServletResponse.SC_OK);
			response.setHeader("HX-Redirect", target);
			response.setHeader("Cache-Control", "no-store");
			return;
		}
		this.delegate.commence(request, response, authException);
	}

}
