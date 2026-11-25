package cloud.moonl.sso.spring.it;

import java.net.URI;
import java.util.LinkedHashMap;
import java.util.Map;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import cloud.moonl.sso.spring.account.MoonSsoAccountClient;
import cloud.moonl.sso.spring.account.MoonSsoProfile;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Import;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Browser login with MockMvc against {@code test-web}: /oauth2/authorization/moon-sso →
 * (testbed completes the login) → callback → authenticated.
 */
@Tag("testbed")
@SpringBootTest(classes = LoginFlowIT.App.class)
@AutoConfigureMockMvc
class LoginFlowIT {

	@DynamicPropertySource
	static void properties(DynamicPropertyRegistry registry) {
		registry.add("moon-sso.issuer", () -> Testbed.URL);
		registry.add("moon-sso.client-id", () -> Testbed.WEB_CLIENT);
		registry.add("moon-sso.client-secret", () -> Testbed.WEB_SECRET);
		registry.add("moon-sso.redirect-uri", () -> Testbed.WEB_REDIRECT);
		registry.add("moon-sso.login.processing-url", () -> "/callback");
		registry.add("moon-sso.post-logout-redirect-uri", () -> "http://127.0.0.1:18700/");
	}

	@BeforeAll
	static void requireTestbed() {
		assertThat(Testbed.reachable()).as("Moon SSO testbed reachable at " + Testbed.URL).isTrue();
	}

	@Autowired
	MockMvc mvc;

	@Test
	void loginThroughAuthorizationCodeFlowLandsAuthenticated() throws Exception {
		MockHttpSession session = new MockHttpSession();

		// unauthenticated: redirected to the login entry point
		this.mvc.perform(get("/me").session(session))
			.andExpect(status().isFound())
			.andExpect(header().string("Location", org.hamcrest.Matchers.endsWith("/oauth2/authorization/moon-sso")));

		// the authorization request carries PKCE S256, state and nonce
		MvcResult start = this.mvc.perform(get("/oauth2/authorization/moon-sso").session(session))
			.andExpect(status().isFound())
			.andReturn();
		URI authorize = URI.create(start.getResponse().getRedirectedUrl());
		assertThat(authorize.toString()).startsWith(Testbed.URL + "/oauth/authorize?");
		Map<String, String> params = Testbed.query(authorize);
		assertThat(params).containsEntry("client_id", Testbed.WEB_CLIENT)
			.containsEntry("redirect_uri", Testbed.WEB_REDIRECT)
			.containsEntry("response_type", "code")
			.containsEntry("code_challenge_method", "S256")
			.containsKeys("state", "nonce", "code_challenge");
		assertThat(params.get("scope").split(" ")).contains("openid", "profile", "offline_access");

		// the testbed plays the browser + login form
		Testbed.User user = Testbed.createUser();
		Testbed.Authorized authorized = Testbed.authorize(params, user);
		URI callback = URI.create(authorized.redirect());
		assertThat(Testbed.query(callback)).containsEntry("iss", Testbed.URL).containsKey("code");

		MvcResult login = this.mvc.perform(get(callback).session(session)).andExpect(status().isFound()).andReturn();
		assertThat(login.getResponse().getRedirectedUrl()).contains("/me");
		MockHttpSession authenticated = (MockHttpSession) login.getRequest().getSession(false);

		this.mvc.perform(get("/me").session(authenticated))
			.andExpect(status().isOk())
			.andExpect(jsonPath("$.sub").value(user.publicSub()))
			.andExpect(jsonPath("$.username").value(user.username()))
			.andExpect(jsonPath("$.sid").isNotEmpty());

		// the account API works with the session's authorized client
		this.mvc.perform(get("/me/profile").session(authenticated))
			.andExpect(status().isOk())
			.andExpect(jsonPath("$.preferred_username").value(user.username()))
			.andExpect(jsonPath("$.sub").value(user.publicSub()));
	}

	@Test
	void authorizationResponseWithForeignIssuerIsRejected() throws Exception {
		MockHttpSession session = new MockHttpSession();
		MvcResult start = this.mvc.perform(get("/oauth2/authorization/moon-sso").session(session)).andReturn();
		Map<String, String> params = Testbed.query(URI.create(start.getResponse().getRedirectedUrl()));
		Testbed.Authorized authorized = Testbed.authorize(params, Testbed.createUser());
		Map<String, String> callback = new LinkedHashMap<>(authorized.callbackParams());
		callback.put("iss", "https://attacker.example.test");
		URI forged = URI.create(Testbed.WEB_REDIRECT + "?" + Testbed.form(callback));

		this.mvc.perform(get(forged).session(session))
			.andExpect(status().isFound())
			.andExpect(header().string("Location", "/moon-sso/login-error"));
		this.mvc.perform(get("/me").session(session)).andExpect(status().isFound());
		// the failure page is served by the starter (no redirect loop back to the SSO)
		this.mvc.perform(get("/moon-sso/login-error").session(session))
			.andExpect(status().isOk())
			.andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.content()
				.string(org.hamcrest.Matchers.allOf(org.hamcrest.Matchers.containsString("invalid_request"),
						org.hamcrest.Matchers.containsString("/oauth2/authorization/moon-sso"))));
	}

	@Test
	void htmxRequestGetsHxRedirect() throws Exception {
		this.mvc.perform(get("/me").header("HX-Request", "true"))
			.andExpect(status().isOk())
			.andExpect(header().string("HX-Redirect", "/oauth2/authorization/moon-sso"));
	}

	@SpringBootConfiguration
	@EnableAutoConfiguration
	@Import(MeController.class)
	static class App {

	}

	@RestController
	static class MeController {

		private final MoonSsoAccountClient account;

		MeController(MoonSsoAccountClient account) {
			this.account = account;
		}

		@GetMapping("/me")
		Map<String, Object> me(@AuthenticationPrincipal OidcUser user) {
			Map<String, Object> out = new LinkedHashMap<>();
			out.put("sub", user.getSubject());
			out.put("username", user.getPreferredUsername());
			out.put("sid", user.getIdToken().getClaimAsString("sid"));
			return out;
		}

		@GetMapping("/me/profile")
		MoonSsoProfile profile() {
			return this.account.getProfile();
		}

	}

}
