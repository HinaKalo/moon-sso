package cloud.moonl.sso.spring.core;

import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import cloud.moonl.sso.spring.StubServer;
import cloud.moonl.sso.spring.StubServer.Reply;

import org.springframework.security.oauth2.client.endpoint.OAuth2RefreshTokenGrantRequest;
import org.springframework.security.oauth2.client.endpoint.RestClientRefreshTokenTokenResponseClient;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class TokenEndpointRetryTest {

	private final StubServer server;

	private final RestClientRefreshTokenTokenResponseClient client = new RestClientRefreshTokenTokenResponseClient();

	TokenEndpointRetryTest() throws Exception {
		this.server = new StubServer();
		this.client.setRestClient(new MoonSsoHttp(Duration.ofSeconds(5), Duration.ofSeconds(5)).tokenEndpointRestClient());
	}

	@AfterEach
	void stop() {
		this.server.close();
	}

	private OAuth2RefreshTokenGrantRequest request() {
		ClientRegistration registration = ClientRegistration.withRegistrationId("moon-sso")
			.clientId("c1")
			.clientSecret("s1")
			.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
			.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
			.redirectUri("http://127.0.0.1/cb")
			.authorizationUri(this.server.baseUrl() + "/oauth/authorize")
			.tokenUri(this.server.baseUrl() + "/oauth/token")
			.build();
		OAuth2AccessToken access = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "old-at",
				Instant.now().minusSeconds(600), Instant.now().minusSeconds(1));
		return new OAuth2RefreshTokenGrantRequest(registration, access, new OAuth2RefreshToken("rt-1", Instant.now()));
	}

	private static final String TOKENS = "{\"access_token\":\"new-at\",\"token_type\":\"Bearer\",\"expires_in\":900,"
			+ "\"refresh_token\":\"rt-2\",\"scope\":\"openid profile\"}";

	@Test
	void retriesOnceAfter503WithSameParameters() {
		AtomicInteger calls = new AtomicInteger();
		this.server.route("POST /oauth/token",
				(r) -> (calls.incrementAndGet() == 1) ? Reply.json(503, "{}") : Reply.json(200, TOKENS));

		OAuth2AccessTokenResponse response = this.client.getTokenResponse(request());

		assertThat(response.getAccessToken().getTokenValue()).isEqualTo("new-at");
		assertThat(response.getRefreshToken().getTokenValue()).isEqualTo("rt-2");
		assertThat(this.server.requests).hasSize(2);
		assertThat(this.server.requests.get(0).body()).isEqualTo(this.server.requests.get(1).body())
			.contains("grant_type=refresh_token")
			.contains("refresh_token=rt-1");
		assertThat(this.server.requests.get(0).headers().get("User-agent")).singleElement()
			.asString()
			.startsWith("moon-sso-sdk-java/");
	}

	@Test
	void retriesOnlyOnce() {
		this.server.route("POST /oauth/token", (r) -> Reply.json(502, "{}"));
		assertThatThrownBy(() -> this.client.getTokenResponse(request()))
			.isInstanceOf(OAuth2AuthorizationException.class);
		assertThat(this.server.requests).hasSize(2);
	}

	@Test
	void doesNotRetryInvalidGrant() {
		this.server.route("POST /oauth/token",
				(r) -> Reply.json(400, "{\"error\":\"invalid_grant\",\"error_description\":\"revoked\"}"));
		assertThatThrownBy(() -> this.client.getTokenResponse(request()))
			.isInstanceOfSatisfying(OAuth2AuthorizationException.class,
					(ex) -> assertThat(ex.getError().getErrorCode()).isEqualTo("invalid_grant"));
		assertThat(this.server.requests).hasSize(1);
	}

	@Test
	void doesNotRetryInvalidClient() {
		this.server.route("POST /oauth/token", (r) -> Reply.json(401, "{\"error\":\"invalid_client\"}"));
		assertThatThrownBy(() -> this.client.getTokenResponse(request()))
			.isInstanceOf(OAuth2AuthorizationException.class);
		assertThat(this.server.requests).hasSize(1);
	}

}
