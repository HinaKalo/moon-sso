package cloud.moonl.sso.spring.autoconfigure;

import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import cloud.moonl.sso.spring.StubServer;
import cloud.moonl.sso.spring.StubServer.Reply;
import cloud.moonl.sso.spring.account.MoonSsoAccountClient;
import cloud.moonl.sso.spring.client.MoonSsoAuthorizedClientManager;
import cloud.moonl.sso.spring.client.MoonSsoClientRegistrationRepository;
import cloud.moonl.sso.spring.jwt.MoonSsoAccessTokenDecoder;
import cloud.moonl.sso.spring.logout.MoonSsoSessionRegistry;
import cloud.moonl.sso.spring.registration.MoonSsoRegistrationClient;
import cloud.moonl.sso.spring.sync.MoonSsoSyncHandler;
import cloud.moonl.sso.spring.sync.MoonSsoUserSnapshot;
import cloud.moonl.sso.spring.sync.MoonSsoUserSync;
import cloud.moonl.sso.spring.web.MoonSsoSecurity;
import cloud.moonl.sso.spring.webhook.MoonSsoEvent;
import cloud.moonl.sso.spring.webhook.UserUpdatedEvent;

import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.security.autoconfigure.SecurityAutoConfiguration;
import org.springframework.boot.security.autoconfigure.web.servlet.ServletWebSecurityAutoConfiguration;
import org.springframework.boot.security.oauth2.client.autoconfigure.OAuth2ClientAutoConfiguration;
import org.springframework.boot.security.oauth2.client.autoconfigure.servlet.OAuth2ClientWebSecurityAutoConfiguration;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.web.SecurityFilterChain;

import static org.assertj.core.api.Assertions.assertThat;

class MoonSsoAutoConfigurationTest {

	private final StubServer server;

	private final WebApplicationContextRunner runner;

	MoonSsoAutoConfigurationTest() throws Exception {
		this.server = new StubServer();
		String iss = this.server.baseUrl();
		this.server.route("GET /.well-known/openid-configuration", (r) -> Reply.json(200, """
				{"issuer":"%1$s","authorization_endpoint":"%1$s/oauth/authorize","token_endpoint":"%1$s/oauth/token",
				 "jwks_uri":"%1$s/.well-known/jwks.json","userinfo_endpoint":"%1$s/oauth/userinfo",
				 "end_session_endpoint":"%1$s/oauth/end_session","revocation_endpoint":"%1$s/oauth/revoke",
				 "registration_endpoint":"%1$s/oauth/register","authorization_response_iss_parameter_supported":true,
				 "moon_api_audience":"%1$s/api"}""".formatted(iss)));
		this.runner = new WebApplicationContextRunner()
			.withConfiguration(AutoConfigurations.of(MoonSsoAutoConfiguration.class, SecurityAutoConfiguration.class,
					ServletWebSecurityAutoConfiguration.class, OAuth2ClientAutoConfiguration.class,
					OAuth2ClientWebSecurityAutoConfiguration.class))
			.withPropertyValues("moon-sso.issuer=" + iss, "moon-sso.client-id=app-1",
					"moon-sso.client-secret=secret-1", "moon-sso.webhook.secret=whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw");
	}

	@AfterEach
	void stop() {
		this.server.close();
	}

	@Test
	void contributesAllComponents() {
		this.runner.run((context) -> {
			assertThat(context).hasNotFailed();
			assertThat(context).hasSingleBean(ClientRegistrationRepository.class);
			assertThat(context).hasSingleBean(MoonSsoAuthorizedClientManager.class);
			assertThat(context).hasSingleBean(MoonSsoAccountClient.class);
			assertThat(context).hasSingleBean(MoonSsoUserSync.class);
			assertThat(context).hasSingleBean(MoonSsoRegistrationClient.class);
			assertThat(context).hasSingleBean(MoonSsoAccessTokenDecoder.class);
			assertThat(context).hasSingleBean(MoonSsoSessionRegistry.class);
			assertThat(context).hasSingleBean(MoonSsoSecurity.class);
			assertThat(context).hasSingleBean(SecurityFilterChain.class);
			assertThat(context.getBeansOfType(FilterRegistrationBean.class)).containsKeys("moonSsoWebhookFilter",
					"moonSsoBackChannelLogoutFilter");

			ClientRegistration login = context.getBean(ClientRegistrationRepository.class).findByRegistrationId("moon-sso");
			assertThat(login).isNotNull();
			assertThat(login.getClientSettings().isRequireProofKey()).isTrue();
			assertThat(login.getAuthorizationGrantType()).isEqualTo(AuthorizationGrantType.AUTHORIZATION_CODE);
			assertThat(login.getScopes()).containsExactlyInAnyOrder("openid", "profile", "offline_access");
			assertThat(login.getProviderDetails().getTokenUri()).isEqualTo(this.server.baseUrl() + "/oauth/token");
			ClientRegistration sync = context.getBean(ClientRegistrationRepository.class)
				.findByRegistrationId("moon-sso" + MoonSsoClientRegistrationRepository.SYNC_SUFFIX);
			assertThat(sync.getAuthorizationGrantType()).isEqualTo(AuthorizationGrantType.CLIENT_CREDENTIALS);
			assertThat(sync.getScopes()).containsExactly("users:sync");
		});
	}

	@Test
	void backsOffFromDefaultChainWhenApplicationDefinesOne() {
		this.runner.withPropertyValues("moon-sso.login.default-security-filter-chain=false").run((context) -> {
			assertThat(context).hasNotFailed();
			assertThat(context).hasSingleBean(MoonSsoSecurity.class);
		});
	}

	@Test
	void publicClientHasNoSyncBean() {
		new WebApplicationContextRunner()
			.withConfiguration(AutoConfigurations.of(MoonSsoAutoConfiguration.class, SecurityAutoConfiguration.class,
					ServletWebSecurityAutoConfiguration.class))
			.withPropertyValues("moon-sso.issuer=" + this.server.baseUrl(), "moon-sso.client-id=public-app")
			.run((context) -> {
				assertThat(context).hasNotFailed();
				assertThat(context).doesNotHaveBean(MoonSsoUserSync.class);
				assertThat(context).doesNotHaveBean("moonSsoWebhookFilter");
				ClientRegistration login = context.getBean(ClientRegistrationRepository.class)
					.findByRegistrationId("moon-sso");
				assertThat(login.getClientAuthenticationMethod().getValue()).isEqualTo("none");
			});
	}

	@Test
	void emptyPlaceholdersCountAsUnset() {
		new WebApplicationContextRunner()
			.withConfiguration(AutoConfigurations.of(MoonSsoAutoConfiguration.class, SecurityAutoConfiguration.class,
					ServletWebSecurityAutoConfiguration.class))
			.withPropertyValues("moon-sso.issuer=" + this.server.baseUrl(), "moon-sso.client-id=app-1",
					"moon-sso.client-secret=", "moon-sso.webhook.secret=")
			.run((context) -> {
				assertThat(context).hasNotFailed();
				assertThat(context).doesNotHaveBean(MoonSsoUserSync.class);
				assertThat(context).doesNotHaveBean("moonSsoWebhookFilter");
				assertThat(context).hasBean("moonSsoBackChannelLogoutFilter");
			});
		new WebApplicationContextRunner()
			.withConfiguration(AutoConfigurations.of(MoonSsoAutoConfiguration.class, SecurityAutoConfiguration.class,
					ServletWebSecurityAutoConfiguration.class))
			.withPropertyValues("moon-sso.issuer=")
			.run((context) -> assertThat(context).doesNotHaveBean(MoonSsoSecurity.class));
	}

	@Test
	void expiredCursorTriggersFullSyncThenContinuesFromWatermark() {
		this.server.route("POST /oauth/token", (r) -> Reply.json(200,
				"{\"access_token\":\"cc-token\",\"token_type\":\"Bearer\",\"expires_in\":900,\"scope\":\"users:sync\"}"));
		this.server.route("GET /api/v1/users/changes", (r) -> {
			if (r.query().contains("cursor=5&") || r.query().endsWith("cursor=5")) {
				return Reply.json(410, "{\"error\":\"cursor_expired\",\"error_description\":\"too old\"}");
			}
			if (r.query().contains("cursor=100")) {
				return Reply.json(200, """
						{"events":[{"id":"evt_101","seq":101,"type":"user.updated","occurred_at":"2026-11-20T08:00:00Z",
						"data":{"sub":"s1","status":"active","preferred_username":"u1","name":"N","nickname":"N",
						"picture":null,"profile_version":4,"updated_at":1,"changed":["nickname"]}}],
						"next_cursor":"101","has_more":false}""");
			}
			return Reply.json(500, "{}");
		});
		this.server.route("GET /api/v1/users", (r) -> {
			if (r.query() == null || !r.query().contains("cursor=")) {
				return Reply.json(200, """
						{"users":[{"sub":"s1","preferred_username":"u1","name":"u1","nickname":"","picture":null,
						"updated_at":1,"profile_version":3,"status":"active"}],
						"has_more":true,"watermark":"100","next_cursor":"0000000000000000000000000000000a"}""");
			}
			return Reply.json(200, """
					{"users":[{"sub":"s2","preferred_username":"u2","name":"u2","nickname":"","picture":null,
					"updated_at":1,"profile_version":1,"status":"disabled"}],"has_more":false,"watermark":"100"}""");
		});
		this.runner.run((context) -> {
			MoonSsoUserSync sync = context.getBean(MoonSsoUserSync.class);
			List<String> calls = new ArrayList<>();
			String cursor = sync.synchronize("5", new MoonSsoSyncHandler() {

				@Override
				public void onFullSyncStart(String watermark) {
					calls.add("start:" + watermark);
				}

				@Override
				public void onUser(MoonSsoUserSnapshot user) {
					calls.add("user:" + user.sub() + ":" + user.status());
				}

				@Override
				public void onFullSyncComplete(String watermark) {
					calls.add("complete:" + watermark);
				}

				@Override
				public void onEvent(MoonSsoEvent event) {
					calls.add("event:" + event.getClass().getSimpleName() + ":" + event.sub());
				}

				@Override
				public void onCursor(String c) {
					calls.add("cursor:" + c);
				}

			});
			assertThat(cursor).isEqualTo("101");
			assertThat(calls).containsExactly("start:100", "user:s1:active", "user:s2:disabled", "complete:100",
					"cursor:100", "event:" + UserUpdatedEvent.class.getSimpleName() + ":s1", "cursor:101");
			// one client_credentials token, reused for all calls
			assertThat(this.server.count("/oauth/token")).isEqualTo(1);
			assertThat(this.server.requests.stream().filter((r) -> r.path().equals("/oauth/token")).findFirst().orElseThrow().body())
				.contains("grant_type=client_credentials")
				.contains("scope=users%3Async");
		});
	}

}
