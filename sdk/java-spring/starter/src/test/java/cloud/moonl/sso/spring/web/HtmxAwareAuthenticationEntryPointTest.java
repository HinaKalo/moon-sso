package cloud.moonl.sso.spring.web;

import org.junit.jupiter.api.Test;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

import static org.assertj.core.api.Assertions.assertThat;

class HtmxAwareAuthenticationEntryPointTest {

	private final HtmxAwareAuthenticationEntryPoint entryPoint = new HtmxAwareAuthenticationEntryPoint(
			"/oauth2/authorization/moon-sso", new LoginUrlAuthenticationEntryPoint("/oauth2/authorization/moon-sso"));

	@Test
	void htmxRequestGets200WithHxRedirect() throws Exception {
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/app/fragments/cart");
		request.setContextPath("/app");
		request.addHeader("HX-Request", "true");
		MockHttpServletResponse response = new MockHttpServletResponse();

		this.entryPoint.commence(request, response, new InsufficientAuthenticationException("login"));

		assertThat(response.getStatus()).isEqualTo(200);
		assertThat(response.getHeader("HX-Redirect")).isEqualTo("/app/oauth2/authorization/moon-sso");
		assertThat(response.getRedirectedUrl()).isNull();
	}

	@Test
	void htmxHeaderIsCaseInsensitive() throws Exception {
		MockHttpServletRequest request = new MockHttpServletRequest("POST", "/x");
		request.addHeader("HX-Request", "TRUE");
		MockHttpServletResponse response = new MockHttpServletResponse();
		this.entryPoint.commence(request, response, new InsufficientAuthenticationException("login"));
		assertThat(response.getStatus()).isEqualTo(200);
		assertThat(response.getHeader("HX-Redirect")).isEqualTo("/oauth2/authorization/moon-sso");
	}

	@Test
	void regularRequestIsRedirected() throws Exception {
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/profile");
		MockHttpServletResponse response = new MockHttpServletResponse();

		this.entryPoint.commence(request, response, new InsufficientAuthenticationException("login"));

		assertThat(response.getStatus()).isEqualTo(302);
		assertThat(response.getRedirectedUrl()).endsWith("/oauth2/authorization/moon-sso");
		assertThat(response.getHeader("HX-Redirect")).isNull();
	}

	@Test
	void hxRequestFalseIsNotHtmx() throws Exception {
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/profile");
		request.addHeader("HX-Request", "false");
		MockHttpServletResponse response = new MockHttpServletResponse();
		this.entryPoint.commence(request, response, new InsufficientAuthenticationException("login"));
		assertThat(response.getStatus()).isEqualTo(302);
	}

	@Test
	void absoluteLoginUrlIsKept() throws Exception {
		HtmxAwareAuthenticationEntryPoint absolute = new HtmxAwareAuthenticationEntryPoint(
				"https://app.example.test/login", new LoginUrlAuthenticationEntryPoint("/login"));
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/x");
		request.setContextPath("/ctx");
		request.addHeader("HX-Request", "true");
		MockHttpServletResponse response = new MockHttpServletResponse();
		absolute.commence(request, response, new InsufficientAuthenticationException("login"));
		assertThat(response.getHeader("HX-Redirect")).isEqualTo("https://app.example.test/login");
	}

}
