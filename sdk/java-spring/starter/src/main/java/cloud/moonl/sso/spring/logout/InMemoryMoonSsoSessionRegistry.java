package cloud.moonl.sso.spring.logout;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

import jakarta.servlet.http.HttpSession;
import jakarta.servlet.http.HttpSessionEvent;
import jakarta.servlet.http.HttpSessionListener;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jspecify.annotations.Nullable;

/**
 * In-memory {@link MoonSsoSessionRegistry}. Registered as an {@link HttpSessionListener} (Spring
 * Boot does so automatically for listener beans) so entries disappear with their sessions.
 */
public class InMemoryMoonSsoSessionRegistry implements MoonSsoSessionRegistry, HttpSessionListener {

	private static final Log logger = LogFactory.getLog(InMemoryMoonSsoSessionRegistry.class);

	static final String KEY_ATTRIBUTE = InMemoryMoonSsoSessionRegistry.class.getName() + ".KEY";

	private final Map<String, Entry> entries = new ConcurrentHashMap<>();

	@Override
	public void register(@Nullable String sid, String sub, HttpSession session) {
		Object existing = session.getAttribute(KEY_ATTRIBUTE);
		String key = (existing instanceof String s) ? s : UUID.randomUUID().toString();
		session.setAttribute(KEY_ATTRIBUTE, key);
		this.entries.put(key, new Entry(sid, sub, session));
	}

	@Override
	public int logout(@Nullable String sub, @Nullable String sid) {
		List<Map.Entry<String, Entry>> matches = new ArrayList<>();
		for (Map.Entry<String, Entry> e : this.entries.entrySet()) {
			if (matches(e.getValue(), sub, sid)) {
				matches.add(e);
			}
		}
		int ended = 0;
		for (Map.Entry<String, Entry> e : matches) {
			if (this.entries.remove(e.getKey(), e.getValue())) {
				try {
					e.getValue().session().invalidate();
					ended++;
				}
				catch (IllegalStateException ex) {
					// already invalidated
				}
			}
		}
		if (logger.isDebugEnabled()) {
			logger.debug("Back-channel logout ended " + ended + " local session(s)");
		}
		return ended;
	}

	private static boolean matches(Entry entry, @Nullable String sub, @Nullable String sid) {
		if (sid != null && !sid.isBlank()) {
			return sid.equals(entry.sid()) && (sub == null || sub.isBlank() || sub.equals(entry.sub()));
		}
		return sub != null && sub.equals(entry.sub());
	}

	/** Number of tracked sessions. */
	public int size() {
		return this.entries.size();
	}

	@Override
	public void sessionDestroyed(HttpSessionEvent event) {
		Object key;
		try {
			key = event.getSession().getAttribute(KEY_ATTRIBUTE);
		}
		catch (IllegalStateException ex) {
			key = null;
		}
		if (key instanceof String s) {
			this.entries.remove(s);
		}
		else {
			HttpSession session = event.getSession();
			this.entries.values().removeIf((e) -> Objects.equals(e.session().getId(), session.getId()));
		}
	}

	private record Entry(@Nullable String sid, String sub, HttpSession session) {
	}

}
