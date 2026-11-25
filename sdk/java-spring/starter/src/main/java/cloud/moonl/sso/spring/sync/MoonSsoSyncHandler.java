package cloud.moonl.sso.spring.sync;

import cloud.moonl.sso.spring.webhook.MoonSsoEvent;

/**
 * Callbacks of {@link MoonSsoUserSync#synchronize(String, MoonSsoSyncHandler)}. Persist the
 * cursor in {@link #onCursor(String)}, in the same transaction as the applied changes when
 * possible.
 */
public interface MoonSsoSyncHandler {

	/** A full snapshot starts (no cursor yet, or the cursor expired). */
	default void onFullSyncStart(String watermark) {
	}

	/** One user of the snapshot. */
	default void onUser(MoonSsoUserSnapshot user) {
	}

	/** The snapshot is complete; changes continue from {@code watermark}. */
	default void onFullSyncComplete(String watermark) {
	}

	/** One event of the changes feed. */
	default void onEvent(MoonSsoEvent event) {
	}

	/** Everything up to {@code cursor} has been handed to this handler. */
	default void onCursor(String cursor) {
	}

}
