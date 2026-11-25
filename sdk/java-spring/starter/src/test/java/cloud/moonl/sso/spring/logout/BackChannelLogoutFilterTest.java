package cloud.moonl.sso.spring.logout;

import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Test;

import cloud.moonl.sso.spring.TestKeys;
import cloud.moonl.sso.spring.core.ReplayCache;

import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;

import static org.assertj.core.api.Assertions.assertThat;

class BackChannelLogoutFilterTest {

	static final String ISSUER = "https://sso.example.test";

	static final String CLIENT = "client-1";

	static final String PATH = "/moon-sso/backchannel-logout";

	private final TestKeys keys = new TestKeys();

	private final InMemoryMoonSsoSessionRegistry registry = new InMemoryMoonSsoSessionRegistry();

	private final List<Object> events = new ArrayList<>();

	private final BackChannelLogoutFilter filter = new BackChannelLogoutFilter(PATH,
			new LogoutTokenValidator(this.keys.jwkSource(), ISSUER, CLIENT, Duration.ofSeconds(60), Clock.systemUTC()),
			new ReplayCache.InMemory(Duration.ofMinutes(5), 1000, Clock.systemUTC()), this.registry, this.events::add);

	private MockHttpServletResponse post(String token) throws Exception {
		MockHttpServletRequest request = new MockHttpServletRequest("POST", PATH);
		request.setContentType("application/x-www-form-urlencoded");
		request.addParameter("logout_token", token);
		MockHttpServletResponse response = new MockHttpServletResponse();
		MockFilterChain chain = new MockFilterChain();
		this.filter.doFilter(request, response, chain);
		assertThat(chain.getRequest()).as("endpoint must not continue the chain").isNull();
		return response;
	}

	@Test
	void validTokenInvalidatesSessionsBySidAndPublishesEvent() throws Exception {
		MockHttpSession target = new MockHttpSession();
		MockHttpSession otherSid = new MockHttpSession();
		MockHttpSession otherUser = new MockHttpSession();
		this.registry.register("sid-1", "user-sub", target);
		this.registry.register("sid-2", "user-sub", otherSid);
		this.registry.register("sid-3", "someone-else", otherUser);

		MockHttpServletResponse response = post(this.keys.signRs256("logout+jwt",
				TestKeys.logoutClaims(ISSUER, CLIENT, (b) -> {
				})));

		assertThat(response.getStatus()).isEqualTo(200);
		assertThat(response.getHeader("Cache-Control")).isEqualTo("no-store");
		assertThat(target.isInvalid()).isTrue();
		assertThat(otherSid.isInvalid()).isFalse();
		assertThat(otherUser.isInvalid()).isFalse();
		assertThat(this.events).singleElement()
			.isEqualTo(new MoonSsoBackChannelLogoutEvent("user-sub", "sid-1", 1));
	}

	@Test
	void subOnlyTokenEndsAllSessionsOfTheUser() throws Exception {
		MockHttpSession a = new MockHttpSession();
		MockHttpSession b = new MockHttpSession();
		MockHttpSession c = new MockHttpSession();
		this.registry.register("sid-1", "user-sub", a);
		this.registry.register("sid-2", "user-sub", b);
		this.registry.register("sid-3", "someone-else", c);

		MockHttpServletResponse response = post(this.keys.signEs256("logout+jwt",
				TestKeys.logoutClaims(ISSUER, CLIENT, (builder) -> builder.claim("sid", null))));

		assertThat(response.getStatus()).isEqualTo(200);
		assertThat(a.isInvalid()).isTrue();
		assertThat(b.isInvalid()).isTrue();
		assertThat(c.isInvalid()).isFalse();
	}

	@Test
	void replayedJtiIsRejected() throws Exception {
		String token = this.keys.signRs256("logout+jwt", TestKeys.logoutClaims(ISSUER, CLIENT, (b) -> b.jwtID("same")));
		assertThat(post(token).getStatus()).isEqualTo(200);
		MockHttpServletResponse replay = post(token);
		assertThat(replay.getStatus()).isEqualTo(400);
		assertThat(replay.getContentAsString()).contains("\"error\":\"invalid_request\"").contains("replayed");
		assertThat(this.events).hasSize(1);
	}

	@Test
	void invalidTokenAnswers400() throws Exception {
		MockHttpServletResponse response = post(this.keys.signRs256("logout+jwt",
				TestKeys.logoutClaims(ISSUER, CLIENT, (b) -> b.claim("nonce", "x"))));
		assertThat(response.getStatus()).isEqualTo(400);
		assertThat(response.getContentType()).isEqualTo("application/json");
		assertThat(response.getContentAsString()).contains("invalid_request").contains("nonce");
		assertThat(this.events).isEmpty();
	}

	@Test
	void onlyPostIsAllowed() throws Exception {
		MockHttpServletRequest request = new MockHttpServletRequest("GET", PATH);
		MockHttpServletResponse response = new MockHttpServletResponse();
		this.filter.doFilter(request, response, new MockFilterChain());
		assertThat(response.getStatus()).isEqualTo(405);
	}

	@Test
	void otherPathsPassThrough() throws Exception {
		MockHttpServletRequest request = new MockHttpServletRequest("POST", "/somewhere");
		MockHttpServletResponse response = new MockHttpServletResponse();
		MockFilterChain chain = new MockFilterChain();
		this.filter.doFilter(request, response, chain);
		assertThat(chain.getRequest()).isSameAs(request);
	}

}
