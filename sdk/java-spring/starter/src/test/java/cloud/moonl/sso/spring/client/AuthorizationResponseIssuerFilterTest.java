package cloud.moonl.sso.spring.client;

import java.time.Clock;
import java.time.Duration;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import cloud.moonl.sso.spring.StubServer;
import cloud.moonl.sso.spring.StubServer.Reply;
import cloud.moonl.sso.spring.core.MoonSsoDiscovery;
import cloud.moonl.sso.spring.core.MoonSsoHttp;

import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;

import static org.assertj.core.api.Assertions.assertThat;

class AuthorizationResponseIssuerFilterTest {

	private final StubServer server;

	private final AuthorizationResponseIssuerFilter filter;

	AuthorizationResponseIssuerFilterTest() throws Exception {
		this.server = new StubServer();
		String issuer = this.server.baseUrl();
		this.server.route("GET /.well-known/openid-configuration", (r) -> Reply.json(200,
				"{\"issuer\":\"" + issuer + "\",\"authorization_response_iss_parameter_supported\":true}"));
		MoonSsoDiscovery discovery = new MoonSsoDiscovery(issuer,
				new MoonSsoHttp(Duration.ofSeconds(5), Duration.ofSeconds(5)), Duration.ofHours(1), Clock.systemUTC());
		this.filter = new AuthorizationResponseIssuerFilter(
				PathPatternRequestMatcher.withDefaults().matcher("/login/oauth2/code/*"), discovery,
				new SimpleUrlAuthenticationFailureHandler("/login?error"));
	}

	@AfterEach
	void stop() {
		this.server.close();
	}

	private MockHttpServletResponse callback(String iss, MockFilterChain chain) throws Exception {
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/login/oauth2/code/moon-sso");
		request.addParameter("code", "c1");
		request.addParameter("state", "s1");
		if (iss != null) {
			request.addParameter("iss", iss);
		}
		MockHttpServletResponse response = new MockHttpServletResponse();
		this.filter.doFilter(request, response, chain);
		return response;
	}

	@Test
	void matchingIssuerContinues() throws Exception {
		MockFilterChain chain = new MockFilterChain();
		MockHttpServletResponse response = callback(this.server.baseUrl(), chain);
		assertThat(chain.getRequest()).isNotNull();
		assertThat(response.getRedirectedUrl()).isNull();
	}

	@Test
	void mismatchingIssuerIsRejected() throws Exception {
		MockFilterChain chain = new MockFilterChain();
		MockHttpServletResponse response = callback("https://attacker.example.test", chain);
		assertThat(chain.getRequest()).isNull();
		assertThat(response.getRedirectedUrl()).isEqualTo("/login?error");
	}

	@Test
	void missingIssuerIsRejectedWhenAdvertised() throws Exception {
		MockFilterChain chain = new MockFilterChain();
		MockHttpServletResponse response = callback(null, chain);
		assertThat(chain.getRequest()).isNull();
		assertThat(response.getRedirectedUrl()).isEqualTo("/login?error");
	}

	@Test
	void unrelatedRequestsAreIgnored() throws Exception {
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/somewhere");
		request.addParameter("code", "c1");
		request.addParameter("state", "s1");
		MockFilterChain chain = new MockFilterChain();
		this.filter.doFilter(request, new MockHttpServletResponse(), chain);
		assertThat(chain.getRequest()).isSameAs(request);
	}

}
