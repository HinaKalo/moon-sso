package cloud.moonl.sso.spring.core;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Remembers identifiers (logout token {@code jti}, {@code webhook-id}) for a time window so
 * duplicates can be rejected. The in-memory implementation is bounded; applications running
 * several instances can provide a shared implementation (e.g. backed by Redis) as a bean.
 */
public interface ReplayCache {

	/**
	 * Records an identifier.
	 * @return {@code true} if the identifier was not seen within the window, {@code false}
	 * for a replay
	 */
	boolean markIfAbsent(String namespace, String id);

	/** Forgets an identifier, e.g. because processing it failed and a retry must be accepted. */
	void forget(String namespace, String id);

	/** Bounded, in-memory {@link ReplayCache}. */
	final class InMemory implements ReplayCache {

		private final Duration window;

		private final int maxEntries;

		private final Clock clock;

		private final Map<String, Instant> entries = new ConcurrentHashMap<>();

		public InMemory(Duration window, int maxEntries, Clock clock) {
			this.window = window;
			this.maxEntries = maxEntries;
			this.clock = clock;
		}

		@Override
		public boolean markIfAbsent(String namespace, String id) {
			Instant now = this.clock.instant();
			if (this.entries.size() >= this.maxEntries) {
				purge(now);
			}
			String key = namespace + '\u0000' + id;
			Instant expiry = now.plus(this.window);
			boolean[] fresh = { false };
			this.entries.compute(key, (k, existing) -> {
				if (existing == null || !existing.isAfter(now)) {
					fresh[0] = true;
					return expiry;
				}
				return existing;
			});
			return fresh[0];
		}

		@Override
		public void forget(String namespace, String id) {
			this.entries.remove(namespace + '\u0000' + id);
		}

		private void purge(Instant now) {
			for (Iterator<Map.Entry<String, Instant>> it = this.entries.entrySet().iterator(); it.hasNext();) {
				if (!it.next().getValue().isAfter(now)) {
					it.remove();
				}
			}
			// still full: drop arbitrary entries rather than grow without bound
			Iterator<String> keys = this.entries.keySet().iterator();
			while (this.entries.size() >= this.maxEntries && keys.hasNext()) {
				keys.next();
				keys.remove();
			}
		}

	}

}
