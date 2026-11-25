package cloud.moonl.sso.spring.it;

import java.io.IOException;
import java.net.CookieManager;
import java.net.CookiePolicy;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Clock;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import cloud.moonl.sso.spring.MoonSsoProperties;
import cloud.moonl.sso.spring.core.MoonSsoDiscovery;
import cloud.moonl.sso.spring.core.MoonSsoException;
import cloud.moonl.sso.spring.core.MoonSsoHttp;
import cloud.moonl.sso.spring.logout.MoonSsoBackChannelLogoutEvent;
import cloud.moonl.sso.spring.registration.ClientInformation;
import cloud.moonl.sso.spring.registration.ClientMetadata;
import cloud.moonl.sso.spring.registration.MoonSsoRegistrationClient;
import cloud.moonl.sso.spring.webhook.MoonSsoEvent;
import cloud.moonl.sso.spring.webhook.UserUpdatedEvent;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.event.EventListener;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Runs the application on a real port with its own DCR-registered client: webhook delivery
 * to {@code /moon-sso/webhooks} and back-channel logout to {@code /moon-sso/backchannel-logout}.
 */
@Tag("testbed")
@SpringBootTest(classes = WebhookAndBackchannelIT.App.class, webEnvironment = SpringBootTest.WebEnvironment.DEFINED_PORT)
class WebhookAndBackchannelIT {

	static final int PORT = Testbed.freePort();

	static final String BASE = "http://127.0.0.1:" + PORT;

	static ClientInformation client;

	static String webhookSecret;

	static MoonSsoRegistrationClient registrationClient;

	@DynamicPropertySource
	static void properties(DynamicPropertyRegistry registry) {
		registerClient();
		registry.add("server.port", () -> PORT);
		registry.add("server.address", () -> "127.0.0.1");
		registry.add("moon-sso.issuer", () -> Testbed.URL);
		registry.add("moon-sso.client-id", () -> client.clientId());
		registry.add("moon-sso.client-secret", () -> client.clientSecret());
		registry.add("moon-sso.webhook.secret", () -> webhookSecret);
	}

	static synchronized void registerClient() {
		if (client != null) {
			return;
		}
		MoonSsoHttp http = new MoonSsoHttp(Duration.ofSeconds(10), Duration.ofSeconds(30));
		MoonSsoProperties properties = new MoonSsoProperties();
		properties.setIssuer(Testbed.URL);
		registrationClient = new MoonSsoRegistrationClient(properties,
				new MoonSsoDiscovery(Testbed.URL, http, Duration.ofHours(1), Clock.systemUTC()), http);
		ClientMetadata metadata = ClientMetadata.builder()
			.clientName("java-spring-it-" + Testbed.randomLower(6))
			.redirectUris(List.of(BASE + "/login/oauth2/code/moon-sso"))
			.postLogoutRedirectUris(List.of(BASE + "/"))
			.grantTypes(List.of("authorization_code", "refresh_token"))
			.tokenEndpointAuthMethod("client_secret_basic")
			.applicationType("web")
			.scope("openid profile offline_access")
			.build();
		// The testbed issues every initial access token for alice, whose developer quota
		// (max_clients_per_developer, default 10) is shared by all SDK suites: wait for a slot.
		long deadline = System.nanoTime() + Duration.ofMinutes(3).toNanos();
		while (true) {
			try {
				client = registrationClient.registerClient(Testbed.initialAccessToken(), metadata);
				break;
			}
			catch (MoonSsoException ex) {
				if (ex.getStatus() != 403 || System.nanoTime() > deadline) {
					throw ex;
				}
				sleep(Duration.ofSeconds(5));
			}
		}
		Testbed.trust(client.clientId());
		webhookSecret = Testbed.webhook(client.clientId(), BASE + "/moon-sso/webhooks");
		Testbed.backchannel(client.clientId(), BASE + "/moon-sso/backchannel-logout");
	}

	@AfterAll
	static void deleteClient() {
		if (client != null && client.registrationAccessToken() != null) {
			registrationClient.deleteClient(client.clientId(), client.registrationAccessToken());
		}
	}

	private static void sleep(Duration d) {
		try {
			Thread.sleep(d.toMillis());
		}
		catch (InterruptedException ex) {
			Thread.currentThread().interrupt();
			throw new IllegalStateException(ex);
		}
	}

	@BeforeAll
	static void requireTestbed() {
		assertThat(Testbed.reachable()).as("Moon SSO testbed reachable at " + Testbed.URL).isTrue();
	}

	@Autowired
	Events events;

	@Test
	void dynamicRegistrationReturnedUsableCredentials() {
		assertThat(client.isActive()).isTrue();
		assertThat(client.clientSecret()).isNotBlank();
		assertThat(client.registrationAccessToken()).isNotBlank();
		assertThat(client.toString()).doesNotContain(client.clientSecret());
		ClientInformation read = registrationClient.readClient(client.clientId(), client.registrationAccessToken());
		assertThat(read.clientId()).isEqualTo(client.clientId());
		assertThat(read.redirectUris()).containsExactly(BASE + "/login/oauth2/code/moon-sso");
		assertThat(read.clientSecret()).isNull();
	}

	@Test
	void webhookDeliveryIsVerifiedAndPublished() throws Exception {
		Testbed.User user = Testbed.createUser();
		Browser browser = Browser.login(user);
		assertThat(browser.get("/me").statusCode()).isEqualTo(200);

		String displayName = "Hook " + Testbed.randomLower(6);
		Testbed.setDisplayName(user, displayName);

		MoonSsoEvent event = this.events.awaitUserEvent(user.publicSub(), displayName, Duration.ofSeconds(45));
		assertThat(event).isInstanceOf(UserUpdatedEvent.class);
		assertThat(event.source()).isEqualTo(MoonSsoEvent.Source.WEBHOOK);
		assertThat(event.id()).startsWith("evt_");
		assertThat(event.data().preferredUsername()).isEqualTo(user.username());
		assertThat(event.data().status()).isEqualTo("active");
	}

	@Test
	void backchannelLogoutEndsTheLocalSession() throws Exception {
		Testbed.User user = Testbed.createUser();
		Browser browser = Browser.login(user);
		HttpResponse<String> me = browser.get("/me");
		assertThat(me.statusCode()).isEqualTo(200);
		assertThat(me.body()).contains(user.publicSub());

		Testbed.logout(browser.sessionToken);

		MoonSsoBackChannelLogoutEvent logout = this.events.awaitLogout(user.publicSub(), Duration.ofSeconds(45));
		assertThat(logout.sid()).isNotBlank();
		assertThat(me.body()).contains(logout.sid());
		assertThat(logout.sessionsEnded()).isEqualTo(1);

		HttpResponse<String> after = browser.get("/me");
		assertThat(after.statusCode()).isEqualTo(302);
		assertThat(after.headers().firstValue("Location")).hasValueSatisfying(
				(location) -> assertThat(location).endsWith("/oauth2/authorization/moon-sso"));
	}

	@Test
	void backchannelEndpointRejectsForgedTokens() throws Exception {
		HttpResponse<String> response = HttpClient.newHttpClient()
			.send(HttpRequest.newBuilder(URI.create(BASE + "/moon-sso/backchannel-logout"))
				.header("Content-Type", "application/x-www-form-urlencoded")
				.POST(HttpRequest.BodyPublishers.ofString("logout_token=eyJhbGciOiJub25lIn0.e30."))
				.build(), HttpResponse.BodyHandlers.ofString());
		assertThat(response.statusCode()).isEqualTo(400);
		assertThat(response.body()).contains("invalid_request");

		HttpResponse<String> unsigned = HttpClient.newHttpClient()
			.send(HttpRequest.newBuilder(URI.create(BASE + "/moon-sso/webhooks"))
				.header("Content-Type", "application/json")
				.header("webhook-id", "evt_forged")
				.header("webhook-timestamp", Long.toString(System.currentTimeMillis() / 1000))
				.header("webhook-signature", "v1,AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
				.POST(HttpRequest.BodyPublishers.ofString("{\"id\":\"evt_forged\",\"type\":\"user.deleted\"}"))
				.build(), HttpResponse.BodyHandlers.ofString());
		assertThat(unsigned.statusCode()).isEqualTo(401);
	}

	/** A cookie-keeping HTTP client that signs in through the running application. */
	static final class Browser {

		final HttpClient http = HttpClient.newBuilder()
			.version(HttpClient.Version.HTTP_1_1)
			.cookieHandler(new CookieManager(null, CookiePolicy.ACCEPT_ALL))
			.followRedirects(HttpClient.Redirect.NEVER)
			.build();

		String sessionToken;

		static Browser login(Testbed.User user) throws Exception {
			Browser browser = new Browser();
			HttpResponse<String> protectedPage = browser.get("/me");
			assertThat(protectedPage.statusCode()).isEqualTo(302);
			HttpResponse<String> start = browser.get("/oauth2/authorization/moon-sso");
			assertThat(start.statusCode()).isEqualTo(302);
			URI authorize = URI.create(start.headers().firstValue("Location").orElseThrow());
			Map<String, String> params = Testbed.query(authorize);
			assertThat(params).containsEntry("code_challenge_method", "S256");
			Testbed.Authorized authorized = Testbed.authorize(params, user);
			browser.sessionToken = authorized.sessionToken();
			HttpResponse<String> callback = browser.send(URI.create(authorized.redirect()));
			assertThat(callback.statusCode()).as("callback: " + callback.body()).isEqualTo(302);
			assertThat(callback.headers().firstValue("Location").orElseThrow()).doesNotContain("error");
			return browser;
		}

		HttpResponse<String> get(String path) throws IOException, InterruptedException {
			return send(URI.create(BASE + path));
		}

		HttpResponse<String> send(URI uri) throws IOException, InterruptedException {
			return this.http.send(HttpRequest.newBuilder(uri).GET().build(), HttpResponse.BodyHandlers.ofString());
		}

	}

	/** Collects the starter's application events. */
	static final class Events {

		final BlockingQueue<MoonSsoEvent> userEvents = new LinkedBlockingQueue<>();

		final BlockingQueue<MoonSsoBackChannelLogoutEvent> logouts = new LinkedBlockingQueue<>();

		@EventListener
		void on(MoonSsoEvent event) {
			this.userEvents.add(event);
		}

		@EventListener
		void on(MoonSsoBackChannelLogoutEvent event) {
			this.logouts.add(event);
		}

		MoonSsoEvent awaitUserEvent(String sub, String nickname, Duration timeout) throws InterruptedException {
			long deadline = System.nanoTime() + timeout.toNanos();
			while (System.nanoTime() < deadline) {
				MoonSsoEvent e = this.userEvents.poll(500, TimeUnit.MILLISECONDS);
				if (e != null && sub.equals(e.sub()) && nickname.equals(e.data().nickname())) {
					return e;
				}
			}
			throw new AssertionError("no webhook event for " + sub + " within " + timeout);
		}

		MoonSsoBackChannelLogoutEvent awaitLogout(String sub, Duration timeout) throws InterruptedException {
			long deadline = System.nanoTime() + timeout.toNanos();
			while (System.nanoTime() < deadline) {
				MoonSsoBackChannelLogoutEvent e = this.logouts.poll(500, TimeUnit.MILLISECONDS);
				if (e != null && sub.equals(e.sub())) {
					return e;
				}
			}
			throw new AssertionError("no back-channel logout for " + sub + " within " + timeout);
		}

	}

	@SpringBootConfiguration
	@EnableAutoConfiguration
	@Import(MeController.class)
	static class App {

		@Bean
		Events events() {
			return new Events();
		}

	}

	@RestController
	static class MeController {

		@GetMapping("/me")
		Map<String, Object> me(@AuthenticationPrincipal OidcUser user) {
			return Map.of("sub", user.getSubject(), "sid", user.getIdToken().getClaimAsString("sid"));
		}

	}

}
