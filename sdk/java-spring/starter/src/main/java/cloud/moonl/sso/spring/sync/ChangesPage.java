package cloud.moonl.sso.spring.sync;

import java.util.List;

import cloud.moonl.sso.spring.webhook.MoonSsoEvent;

/**
 * One page of the changes feed.
 *
 * @param events events in sequence order
 * @param nextCursor cursor to persist and pass to the next call
 * @param hasMore whether more events are available right now
 */
public record ChangesPage(List<MoonSsoEvent> events, String nextCursor, boolean hasMore) {

	public ChangesPage {
		events = List.copyOf(events);
	}

}
