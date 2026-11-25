package cloud.moonl.sso.spring.it;

import java.awt.Color;
import java.awt.Graphics2D;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import javax.imageio.ImageIO;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import cloud.moonl.sso.spring.account.CurrentUserTokenSource;
import cloud.moonl.sso.spring.account.MoonSsoAccountClient;
import cloud.moonl.sso.spring.account.MoonSsoProfile;
import cloud.moonl.sso.spring.account.MoonSsoProfileChangedEvent;
import cloud.moonl.sso.spring.account.MoonSsoTokenSource;
import cloud.moonl.sso.spring.account.PasswordChangeResult;
import cloud.moonl.sso.spring.account.ProfileUpdate;
import cloud.moonl.sso.spring.autoconfigure.MoonSsoAutoConfiguration;
import cloud.moonl.sso.spring.client.MoonSsoAuthorizedClientManager;
import cloud.moonl.sso.spring.core.MoonSsoDiscovery;
import cloud.moonl.sso.spring.core.MoonSsoException;
import cloud.moonl.sso.spring.core.MoonSsoHttp;
import cloud.moonl.sso.spring.core.MoonSsoSessionExpiredEvent;
import cloud.moonl.sso.spring.core.MoonSsoSessionExpiredException;

import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.security.autoconfigure.SecurityAutoConfiguration;
import org.springframework.boot.security.autoconfigure.web.servlet.ServletWebSecurityAutoConfiguration;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationListener;
import org.springframework.context.PayloadApplicationEvent;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.ClientAuthorizationRequiredException;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Account API with tokens of a fresh user obtained through the first-party challenge on
 * {@code test-native}, plus silent refresh through the authorized client manager.
 */
@Tag("testbed")
class AccountApiIT {

	static final String SCOPES = "openid profile offline_access profile:write password:write";

	private final MoonSsoHttp http = new MoonSsoHttp(Duration.ofSeconds(10), Duration.ofSeconds(30));

	private final MoonSsoDiscovery discovery = new MoonSsoDiscovery(Testbed.URL, this.http, Duration.ofHours(1),
			Clock.systemUTC());

	private final List<Object> published = new ArrayList<>();

	@BeforeAll
	static void requireTestbed() {
		assertThat(Testbed.reachable()).as("Moon SSO testbed reachable at " + Testbed.URL).isTrue();
	}

	@AfterEach
	void clearContext() {
		SecurityContextHolder.clearContext();
		RequestContextHolder.resetRequestAttributes();
	}

	private MoonSsoAccountClient client(MoonSsoTokenSource tokens) {
		return new MoonSsoAccountClient(this.discovery, this.http, tokens, this.published::add);
	}

	@Test
	void profileAvatarAndPasswordLifecycle() throws Exception {
		Testbed.User user = Testbed.createUser();
		Map<String, Object> tokens = Testbed.challengeLogin(Testbed.NATIVE_CLIENT, user, SCOPES);
		MoonSsoAccountClient account = client(MoonSsoTokenSource.of((String) tokens.get("access_token")));

		MoonSsoProfile profile = account.getProfile();
		assertThat(profile.sub()).isEqualTo(user.publicSub());
		assertThat(profile.preferredUsername()).isEqualTo(user.username());
		assertThat(profile.totpEnabled()).isFalse();
		assertThat(profile.picture()).isNull();

		// display name with optimistic concurrency
		String displayName = "Java " + Testbed.randomLower(5);
		MoonSsoProfile renamed = account.updateProfile(ProfileUpdate.displayName(displayName), profile.profileVersion());
		assertThat(renamed.nickname()).isEqualTo(displayName);
		assertThat(renamed.name()).isEqualTo(displayName);
		assertThat(renamed.profileVersion()).isGreaterThan(profile.profileVersion());
		assertThat(this.published).last().isEqualTo(new MoonSsoProfileChangedEvent(renamed));

		assertThatThrownBy(() -> account.updateProfile(ProfileUpdate.displayName("stale"), profile.profileVersion()))
			.isInstanceOfSatisfying(MoonSsoException.class, (ex) -> {
				assertThat(ex.isVersionConflict()).isTrue();
				assertThat(ex.getStatus()).isEqualTo(412);
				assertThat(ex.getError()).isEqualTo("version_conflict");
			});

		// username change
		String newUsername = "t_" + Testbed.randomLower(8);
		MoonSsoProfile newName = account.updateProfile(ProfileUpdate.username(newUsername));
		assertThat(newName.preferredUsername()).isEqualTo(newUsername);

		// validation error carries the field
		assertThatThrownBy(() -> account.updateProfile(ProfileUpdate.username("!")))
			.isInstanceOfSatisfying(MoonSsoException.class, (ex) -> {
				assertThat(ex.getStatus()).isEqualTo(422);
				assertThat(ex.getField()).isEqualTo("username");
			});

		// avatar
		MoonSsoProfile withAvatar = account.uploadAvatar(png(), MediaType.IMAGE_PNG);
		assertThat(withAvatar.picture()).startsWith(Testbed.URL + "/avatars/");
		MoonSsoProfile withoutAvatar = account.deleteAvatar();
		assertThat(withoutAvatar.picture()).isNull();
		assertThat(this.published).hasSize(4);

		// password
		String newPassword = "Tb-" + Testbed.random(12) + "-8";
		PasswordChangeResult changed = account.changePassword(user.password(), newPassword, true);
		assertThat(changed.changed()).isTrue();
		assertThat(changed.otherSessionsRevoked()).isTrue();
		assertThatThrownBy(() -> account.changePassword("wrong-password-1", "Another-Pass-77", true))
			.isInstanceOf(MoonSsoException.class);
		// the session of this token was kept
		assertThat(account.getProfile().preferredUsername()).isEqualTo(newUsername);
		// the new password works
		Testbed.User renamedUser = new Testbed.User(newUsername, newPassword, user.publicSub());
		assertThat(Testbed.challengeLogin(Testbed.NATIVE_CLIENT, renamedUser, "openid profile")).containsKey("access_token");
	}

	@Test
	void unauthorizedResponseForcesOneRefreshAndReplay() {
		Testbed.User user = Testbed.createUser();
		String accessToken = (String) Testbed.challengeLogin(Testbed.NATIVE_CLIENT, user, "openid profile")
			.get("access_token");
		AtomicInteger calls = new AtomicInteger();
		List<Boolean> forced = new ArrayList<>();
		MoonSsoAccountClient account = client((force) -> {
			calls.incrementAndGet();
			forced.add(force);
			return force ? accessToken : "not-a-valid-token";
		});
		assertThat(account.getProfile().sub()).isEqualTo(user.publicSub());
		assertThat(forced).containsExactly(false, true);

		MoonSsoAccountClient alwaysBad = client((force) -> "still-invalid");
		assertThatThrownBy(alwaysBad::getProfile).isInstanceOfSatisfying(MoonSsoException.class,
				(ex) -> assertThat(ex.getStatus()).isEqualTo(401));
	}

	@Test
	void authorizedClientManagerRefreshesSilently() {
		Testbed.User user = Testbed.createUser();
		Map<String, Object> tokens = Testbed.challengeLogin(Testbed.NATIVE_CLIENT, user, SCOPES);
		new WebApplicationContextRunner()
			.withConfiguration(AutoConfigurations.of(MoonSsoAutoConfiguration.class, SecurityAutoConfiguration.class,
					ServletWebSecurityAutoConfiguration.class))
			.withPropertyValues("moon-sso.issuer=" + Testbed.URL, "moon-sso.client-id=" + Testbed.NATIVE_CLIENT,
					"moon-sso.scopes=" + SCOPES.replace(' ', ','))
			.withBean("sessionExpiredCollector", ApplicationListener.class,
					() -> (ApplicationListener<ApplicationEvent>) (e) -> {
						if (e instanceof PayloadApplicationEvent<?> payload) {
							this.published.add(payload.getPayload());
						}
					})
			.run((context) -> {
				MoonSsoAuthorizedClientManager manager = context.getBean(MoonSsoAuthorizedClientManager.class);
				OAuth2AuthorizedClientRepository repository = context.getBean(OAuth2AuthorizedClientRepository.class);
				ClientRegistration registration = context.getBean(ClientRegistrationRepository.class)
					.findByRegistrationId("moon-sso");
				assertThat(registration.getClientAuthenticationMethod().getValue()).isEqualTo("none");

				MockHttpServletRequest request = new MockHttpServletRequest();
				MockHttpServletResponse response = new MockHttpServletResponse();
				RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request, response));
				TestingAuthenticationToken principal = new TestingAuthenticationToken(user.publicSub(), null, "ROLE_USER");
				SecurityContextHolder.getContext().setAuthentication(principal);

				// access token that expires within the 120 s refresh window
				String firstAccess = (String) tokens.get("access_token");
				String firstRefresh = (String) tokens.get("refresh_token");
				OAuth2AccessToken nearlyExpired = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, firstAccess,
						Instant.now().minusSeconds(800), Instant.now().plusSeconds(60));
				repository.saveAuthorizedClient(new OAuth2AuthorizedClient(registration, principal.getName(),
						nearlyExpired, new OAuth2RefreshToken(firstRefresh, Instant.now())), principal, request, response);

				OAuth2AuthorizedClient refreshed = manager
					.authorize(OAuth2AuthorizeRequest.withClientRegistrationId("moon-sso").principal(principal).build());
				assertThat(refreshed.getAccessToken().getTokenValue()).isNotEqualTo(firstAccess);
				assertThat(refreshed.getRefreshToken().getTokenValue()).as("refresh token rotated")
					.isNotEqualTo(firstRefresh);
				assertThat(repository.loadAuthorizedClient("moon-sso", principal, request).getAccessToken().getTokenValue())
					.isEqualTo(refreshed.getAccessToken().getTokenValue());

				// a fresh token is reused, not refreshed
				OAuth2AuthorizedClient again = manager
					.authorize(OAuth2AuthorizeRequest.withClientRegistrationId("moon-sso").principal(principal).build());
				assertThat(again.getAccessToken().getTokenValue()).isEqualTo(refreshed.getAccessToken().getTokenValue());

				// forced refresh (after a 401)
				OAuth2AuthorizedClient forced = manager.forceRefresh(again, principal);
				assertThat(forced.getAccessToken().getTokenValue()).isNotEqualTo(again.getAccessToken().getTokenValue());
				// a stale caller gets the already refreshed client without another rotation
				assertThat(manager.forceRefresh(again, principal).getAccessToken().getTokenValue())
					.isEqualTo(forced.getAccessToken().getTokenValue());

				// the account client of the current user uses the manager
				MoonSsoAccountClient account = context.getBean(MoonSsoAccountClient.class);
				assertThat(account.getProfile().preferredUsername()).isEqualTo(user.username());
				assertThat(account.cachedProfile()).isNotNull();
				assertThat(account.getProfile()).as("304 served from the session cache").isEqualTo(account.cachedProfile());

				// invalid_grant ends the session: tokens dropped, SessionExpired raised
				OAuth2AccessToken expired = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "expired",
						Instant.now().minusSeconds(900), Instant.now().minusSeconds(1));
				repository.saveAuthorizedClient(new OAuth2AuthorizedClient(registration, principal.getName(), expired,
						new OAuth2RefreshToken("revoked-or-unknown-refresh-token", Instant.now())), principal, request,
						response);
				CurrentUserTokenSource tokenSource = new CurrentUserTokenSource(manager, "moon-sso");
				assertThatThrownBy(() -> tokenSource.accessToken(false))
					.isInstanceOf(MoonSsoSessionExpiredException.class)
					.hasRootCauseInstanceOf(org.springframework.security.oauth2.core.OAuth2AuthorizationException.class)
					.satisfies((ex) -> assertThat(ex.getCause()).isInstanceOf(ClientAuthorizationRequiredException.class));
				OAuth2AuthorizedClient removed = repository.loadAuthorizedClient("moon-sso", principal, request);
				assertThat(removed).isNull();
				assertThat(this.published).contains(new MoonSsoSessionExpiredEvent(principal.getName(), "moon-sso"));
			});
	}

	private static byte[] png() throws IOException {
		BufferedImage image = new BufferedImage(64, 64, BufferedImage.TYPE_INT_RGB);
		Graphics2D g = image.createGraphics();
		g.setColor(new Color(0x3366cc));
		g.fillRect(0, 0, 64, 64);
		g.setColor(Color.WHITE);
		g.fillOval(16, 16, 32, 32);
		g.dispose();
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		ImageIO.write(image, "png", out);
		return out.toByteArray();
	}

}
