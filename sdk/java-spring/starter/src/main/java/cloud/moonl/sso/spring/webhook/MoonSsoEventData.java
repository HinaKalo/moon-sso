package cloud.moonl.sso.spring.webhook;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.jspecify.annotations.Nullable;

/**
 * The {@code data} of an event: the user's snapshot as seen by this client.
 *
 * @param sub client-specific subject
 * @param status {@code active}, {@code disabled} or {@code deleted}
 * @param preferredUsername username (absent for deleted users)
 * @param name display name, falling back to the username
 * @param nickname display name as set by the user
 * @param picture avatar URL or {@code null}
 * @param profileVersion monotonically increasing profile version; discard events older than
 * what you stored
 * @param updatedAt unix seconds of the last profile change
 * @param changed names of the changed fields, when known
 * @param clientId client id (only in {@code ping} test deliveries)
 */
public record MoonSsoEventData(@Nullable String sub, @Nullable String status,
		@JsonProperty("preferred_username") @Nullable String preferredUsername, @Nullable String name,
		@Nullable String nickname, @Nullable String picture,
		@JsonProperty("profile_version") @Nullable Long profileVersion,
		@JsonProperty("updated_at") @Nullable Long updatedAt, @Nullable List<String> changed,
		@JsonProperty("client_id") @Nullable String clientId) {

	static final MoonSsoEventData EMPTY = new MoonSsoEventData(null, null, null, null, null, null, null, null, null,
			null);

	public MoonSsoEventData {
		changed = (changed != null) ? List.copyOf(changed) : List.of();
	}

}
