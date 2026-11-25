package cloud.moonl.sso.spring.web;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.web.WebAttributes;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.HtmlUtils;

/**
 * Minimal "sign-in failed" page (default {@code moon-sso.login.failure-url}). With a single
 * provider Spring Security does not render its own login page, so without this page a failed
 * login would immediately bounce back to the authorization server. Only the OAuth error code
 * is shown; descriptions and tokens are never echoed.
 */
public final class LoginErrorPageFilter extends OncePerRequestFilter {

	/** Path served by this filter. */
	public static final String PATH = "/moon-sso/login-error";

	private final String loginUrl;

	public LoginErrorPageFilter(String loginUrl) {
		this.loginUrl = loginUrl;
	}

	@Override
	protected boolean shouldNotFilter(HttpServletRequest request) {
		String uri = request.getRequestURI().substring(request.getContextPath().length());
		return !PATH.equals(uri);
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws ServletException, IOException {
		String code = "login_failed";
		HttpSession session = request.getSession(false);
		if (session != null) {
			Object ex = session.getAttribute(WebAttributes.AUTHENTICATION_EXCEPTION);
			session.removeAttribute(WebAttributes.AUTHENTICATION_EXCEPTION);
			if (ex instanceof OAuth2AuthenticationException oauth) {
				code = oauth.getError().getErrorCode();
			}
			else if (ex instanceof AuthenticationException) {
				code = "authentication_failed";
			}
		}
		String retry = request.getContextPath() + this.loginUrl;
		String html = "<!DOCTYPE html><html lang=\"zh-CN\"><head><meta charset=\"UTF-8\">"
				+ "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>登录失败</title></head>"
				+ "<body style=\"font-family:system-ui,sans-serif;max-width:480px;margin:48px auto;padding:0 16px\">"
				+ "<h1>登录失败</h1><p>错误代码：<code>" + HtmlUtils.htmlEscape(code) + "</code></p>"
				+ "<p><a href=\"" + HtmlUtils.htmlEscape(retry) + "\">重新登录</a></p></body></html>";
		response.setStatus(HttpServletResponse.SC_OK);
		response.setHeader(HttpHeaders.CACHE_CONTROL, "no-store");
		response.setContentType(MediaType.TEXT_HTML_VALUE + ";charset=UTF-8");
		response.getOutputStream().write(html.getBytes(StandardCharsets.UTF_8));
	}

}
