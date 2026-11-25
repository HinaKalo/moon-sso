package cloud.moonl.sso.spring.account;

import java.io.Serializable;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.jspecify.annotations.Nullable;

/**
 * The signed-in user's profile as seen by this client ({@code GET /api/v1/me}).
 *
 * @param sub client-specific subject
 * @param preferredUsername username
 * @param name display name, falling back to the username
 * @param nickname display name as set by the user (may be empty)
 * @param picture avatar URL or {@code null}
 * @param updatedAt unix seconds of the last change
 * @param profileVersion version used for {@code ETag}/{@code If-Match}
 * @param totpEnabled whether two-factor authentication is enabled
 */
public record MoonSsoProfile(String sub, @JsonProperty("preferred_username") @Nullable String preferredUsername,
		@Nullable String name, @Nullable String nickname, @Nullable String picture,
		@JsonProperty("updated_at") long updatedAt, @JsonProperty("profile_version") long profileVersion,
		@JsonProperty("totp_enabled") boolean totpEnabled) implements Serializable {

	private static final long serialVersionUID = 1L;

	/** The entity tag of this version, {@code "pv-<n>"}. */
	public String etag() {
		return "\"pv-" + this.profileVersion + "\"";
	}

}
