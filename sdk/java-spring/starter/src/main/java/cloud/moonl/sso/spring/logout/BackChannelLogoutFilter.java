package cloud.moonl.sso.spring.logout;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import cloud.moonl.sso.spring.core.ReplayCache;

import org.springframework.context.ApplicationEventPublisher;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * OpenID Connect Back-Channel Logout endpoint ({@code POST}, form field {@code logout_token}).
 *
 * <p>The token is validated by {@link LogoutTokenValidator}, its {@code jti} must not have been
 * seen within the replay window, then every local session matching {@code sid}/{@code sub} is
 * invalidated and a {@link MoonSsoBackChannelLogoutEvent} is published. Errors are answered
 * with {@code 400 {"error":"invalid_request"}} as the specification requires.
 *
 * <p>The filter is registered in front of Spring Security, so the endpoint needs neither
 * authentication nor a CSRF token.
 */
public final class BackChannelLogoutFilter extends OncePerRequestFilter {

	private static final Log logger = LogFactory.getLog(BackChannelLogoutFilter.class);

	static final String REPLAY_NAMESPACE = "logout-jti";

	private final String path;

	private final LogoutTokenValidator validator;

	private final ReplayCache replayCache;

	private final MoonSsoSessionRegistry registry;

	private final ApplicationEventPublisher publisher;

	public BackChannelLogoutFilter(String path, LogoutTokenValidator validator, ReplayCache replayCache,
			MoonSsoSessionRegistry registry, ApplicationEventPublisher publisher) {
		this.path = path;
		this.validator = validator;
		this.replayCache = replayCache;
		this.registry = registry;
		this.publisher = publisher;
	}

	@Override
	protected boolean shouldNotFilter(HttpServletRequest request) {
		String uri = request.getRequestURI().substring(request.getContextPath().length());
		return !this.path.equals(uri);
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws ServletException, IOException {
		response.setHeader(HttpHeaders.CACHE_CONTROL, "no-store");
		if (!"POST".equals(request.getMethod())) {
			response.setHeader(HttpHeaders.ALLOW, "POST");
			error(response, HttpServletResponse.SC_METHOD_NOT_ALLOWED, "method not allowed");
			return;
		}
		String contentType = request.getContentType();
		if (contentType == null || !MediaType.APPLICATION_FORM_URLENCODED.isCompatibleWith(MediaType.parseMediaType(contentType))) {
			error(response, HttpServletResponse.SC_BAD_REQUEST, "expected application/x-www-form-urlencoded");
			return;
		}
		LogoutTokenValidator.LogoutToken token;
		try {
			token = this.validator.validate(request.getParameter("logout_token"));
		}
		catch (LogoutTokenValidator.InvalidLogoutTokenException ex) {
			logger.debug("Rejected back-channel logout token: " + ex.getMessage());
			error(response, HttpServletResponse.SC_BAD_REQUEST, ex.getMessage());
			return;
		}
		if (!this.replayCache.markIfAbsent(REPLAY_NAMESPACE, token.jti())) {
			logger.debug("Rejected replayed back-channel logout token");
			error(response, HttpServletResponse.SC_BAD_REQUEST, "logout token replayed");
			return;
		}
		int ended;
		try {
			ended = this.registry.logout(token.sub(), token.sid());
		}
		catch (RuntimeException ex) {
			this.replayCache.forget(REPLAY_NAMESPACE, token.jti());
			throw ex;
		}
		this.publisher.publishEvent(new MoonSsoBackChannelLogoutEvent(token.sub(), token.sid(), ended));
		response.setStatus(HttpServletResponse.SC_OK);
	}

	private static void error(HttpServletResponse response, int status, String description) throws IOException {
		response.setStatus(status);
		response.setContentType(MediaType.APPLICATION_JSON_VALUE);
		String body = "{\"error\":\"invalid_request\",\"error_description\":\"" + jsonEscape(description) + "\"}";
		response.getOutputStream().write(body.getBytes(StandardCharsets.UTF_8));
	}

	static String jsonEscape(String s) {
		StringBuilder sb = new StringBuilder(s.length() + 8);
		for (char c : s.toCharArray()) {
			switch (c) {
				case '"' -> sb.append("\\\"");
				case '\\' -> sb.append("\\\\");
				case '\n' -> sb.append("\\n");
				case '\r' -> sb.append("\\r");
				case '\t' -> sb.append("\\t");
				default -> {
					if (c < 0x20) {
						sb.append(String.format("\\u%04x", (int) c));
					}
					else {
						sb.append(c);
					}
				}
			}
		}
		return sb.toString();
	}

}
