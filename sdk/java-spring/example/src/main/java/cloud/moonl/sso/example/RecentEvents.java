package cloud.moonl.sso.example;

import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import cloud.moonl.sso.spring.logout.MoonSsoBackChannelLogoutEvent;
import cloud.moonl.sso.spring.webhook.ConsentRevokedEvent;
import cloud.moonl.sso.spring.webhook.MoonSsoEvent;
import cloud.moonl.sso.spring.webhook.UserDeletedEvent;
import cloud.moonl.sso.spring.webhook.UserUpdatedEvent;

import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

/**
 * Webhook listener: keeps the last events in memory and shows how to react to specific types.
 * A real application would update its user table, keyed by {@code sub}, and ignore events
 * whose {@code profile_version} is older than the stored one.
 */
@Component
class RecentEvents {

	private static final Log logger = LogFactory.getLog(RecentEvents.class);

	private final Deque<Entry> entries = new ArrayDeque<>();

	record Entry(Instant receivedAt, String type, String sub, String summary) {
	}

	@EventListener
	void onAny(MoonSsoEvent event) {
		add(event.type(), event.sub(), event.data().preferredUsername() + " / " + event.data().name() + " (v"
				+ event.data().profileVersion() + ")");
	}

	@EventListener
	void onUpdated(UserUpdatedEvent event) {
		logger.info("Profile of " + event.sub() + " changed: " + event.data().changed());
	}

	@EventListener
	void onDeleted(UserDeletedEvent event) {
		logger.info("User " + event.sub() + " was deleted; remove local data");
	}

	@EventListener
	void onConsentRevoked(ConsentRevokedEvent event) {
		logger.info("User " + event.sub() + " revoked this application's access");
	}

	@EventListener
	void onBackChannelLogout(MoonSsoBackChannelLogoutEvent event) {
		add("backchannel-logout", event.sub(), event.sessionsEnded() + " local session(s) ended");
	}

	private synchronized void add(String type, String sub, String summary) {
		this.entries.addFirst(new Entry(Instant.now(), type, sub, summary));
		while (this.entries.size() > 50) {
			this.entries.removeLast();
		}
	}

	synchronized List<Entry> list() {
		return List.copyOf(this.entries);
	}

}
