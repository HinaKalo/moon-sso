package cloud.moonl.sso.spring.sync;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.jspecify.annotations.Nullable;

/**
 * Current state of a user who granted this client ({@code GET /api/v1/users}).
 *
 * @param sub client-specific subject
 * @param status {@code active} or {@code disabled}
 * @param preferredUsername username
 * @param name display name, falling back to the username
 * @param nickname display name as set by the user
 * @param picture avatar URL or {@code null}
 * @param updatedAt unix seconds of the last change
 * @param profileVersion profile version
 */
public record MoonSsoUserSnapshot(String sub, @Nullable String status,
		@JsonProperty("preferred_username") @Nullable String preferredUsername, @Nullable String name,
		@Nullable String nickname, @Nullable String picture, @JsonProperty("updated_at") @Nullable Long updatedAt,
		@JsonProperty("profile_version") @Nullable Long profileVersion) {
}
