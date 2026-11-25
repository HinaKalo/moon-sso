package cloud.moonl.sso.spring.it;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import cloud.moonl.sso.spring.autoconfigure.MoonSsoAutoConfiguration;
import cloud.moonl.sso.spring.jwt.MoonSsoAccessTokenDecoder;
import cloud.moonl.sso.spring.sync.ChangesPage;
import cloud.moonl.sso.spring.sync.MoonSsoSyncHandler;
import cloud.moonl.sso.spring.sync.MoonSsoUserSnapshot;
import cloud.moonl.sso.spring.sync.MoonSsoUserSync;
import cloud.moonl.sso.spring.webhook.MoonSsoEvent;
import cloud.moonl.sso.spring.webhook.UserUpdatedEvent;

import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.security.autoconfigure.SecurityAutoConfiguration;
import org.springframework.boot.security.autoconfigure.web.servlet.ServletWebSecurityAutoConfiguration;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;

import static org.assertj.core.api.Assertions.assertThat;

/** client_credentials + changes feed against the testbed's {@code test-web} client. */
@Tag("testbed")
class UserSyncIT {

	private final WebApplicationContextRunner runner = new WebApplicationContextRunner()
		.withConfiguration(AutoConfigurations.of(MoonSsoAutoConfiguration.class, SecurityAutoConfiguration.class,
				ServletWebSecurityAutoConfiguration.class))
		.withPropertyValues("moon-sso.issuer=" + Testbed.URL, "moon-sso.client-id=" + Testbed.WEB_CLIENT,
				"moon-sso.client-secret=" + Testbed.WEB_SECRET, "moon-sso.sync.page-size=500");

	@BeforeAll
	static void requireTestbed() {
		assertThat(Testbed.reachable()).as("Moon SSO testbed reachable at " + Testbed.URL).isTrue();
	}

	@Test
	void clientCredentialsTokenAndChangesFeed() {
		this.runner.run((context) -> {
			MoonSsoUserSync sync = context.getBean(MoonSsoUserSync.class);

			// client_credentials token with users:sync for the API audience
			String token = sync.accessToken(false);
			assertThat(token).isNotBlank();
			MoonSsoAccessTokenDecoder apiDecoder = new MoonSsoAccessTokenDecoder(
					context.getBean(cloud.moonl.sso.spring.jwt.MoonSsoJwkSource.class), Testbed.URL,
					List.of(Testbed.URL + "/api"), Duration.ofSeconds(60), java.time.Clock.systemUTC());
			assertThat(apiDecoder.decode(token).getClaimAsString("scope")).contains("users:sync");
			assertThat(sync.accessToken(false)).as("token is cached").isEqualTo(token);

			Testbed.User user = Testbed.createUser();
			Testbed.grantTestWeb(user);

			MoonSsoUserSync.FullSync full = sync.fullSync();
			String watermark = full.watermark();
			assertThat(watermark).isNotBlank();
			boolean found = false;
			for (MoonSsoUserSnapshot snapshot : full) {
				if (user.publicSub().equals(snapshot.sub())) {
					found = true;
					assertThat(snapshot.preferredUsername()).isEqualTo(user.username());
					assertThat(snapshot.status()).isEqualTo("active");
				}
			}
			assertThat(found).as("granted user is part of the full sync").isTrue();
			assertThat(sync.getUser(user.publicSub())).isNotNull()
				.extracting(MoonSsoUserSnapshot::preferredUsername)
				.isEqualTo(user.username());
			assertThat(sync.getUser("no-such-subject-" + Testbed.randomLower(6))).isNull();

			String displayName = "Sync " + Testbed.randomLower(6);
			Testbed.setDisplayName(user, displayName);

			// poll the feed from the watermark until the change appears
			Optional<MoonSsoEvent> event = Optional.empty();
			String cursor = watermark;
			Instant deadline = Instant.now().plusSeconds(30);
			while (event.isEmpty() && Instant.now().isBefore(deadline)) {
				ChangesPage page = sync.syncChanges(cursor);
				event = page.events()
					.stream()
					.filter((e) -> e instanceof UserUpdatedEvent && user.publicSub().equals(e.sub())
							&& displayName.equals(e.data().nickname()))
					.findFirst();
				cursor = page.nextCursor();
				if (event.isEmpty() && !page.hasMore()) {
					Thread.sleep(500);
				}
			}
			assertThat(event).as("user.updated for the renamed user").isPresent();
			MoonSsoEvent updated = event.get();
			assertThat(updated.source()).isEqualTo(MoonSsoEvent.Source.CHANGES_FEED);
			assertThat(updated.data().preferredUsername()).isEqualTo(user.username());
			assertThat(updated.data().profileVersion()).isPositive();
			assertThat(updated.data().changed()).isNotEmpty();

			// synchronize() from the watermark delivers the same event and returns a newer cursor
			List<MoonSsoEvent> seen = new ArrayList<>();
			List<String> cursors = new ArrayList<>();
			String next = sync.synchronize(watermark, new MoonSsoSyncHandler() {

				@Override
				public void onEvent(MoonSsoEvent e) {
					seen.add(e);
				}

				@Override
				public void onCursor(String c) {
					cursors.add(c);
				}

			});
			assertThat(seen).anyMatch((e) -> e.id().equals(updated.id()));
			assertThat(Long.parseLong(next)).isGreaterThanOrEqualTo(updated.seq());
			assertThat(cursors).isNotEmpty().last().isEqualTo(next);
		});
	}

}
