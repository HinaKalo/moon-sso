package cloud.moonl.sso.spring.sync;

import org.jspecify.annotations.Nullable;

import cloud.moonl.sso.spring.core.MoonSsoException;

/**
 * The changes feed answered 410: the cursor is older than the server's retention. Run
 * {@link MoonSsoUserSync#fullSync()} and continue from its watermark
 * ({@link MoonSsoUserSync#synchronize} does this automatically).
 */
public class MoonSsoCursorExpiredException extends MoonSsoException {

	private static final long serialVersionUID = 1L;

	public MoonSsoCursorExpiredException(@Nullable String errorDescription) {
		super("cursor_expired", errorDescription, 410, null);
	}

}
