package cloud.moonl.sso.spring.account;

import java.util.LinkedHashMap;
import java.util.Map;

import org.jspecify.annotations.Nullable;

/**
 * Changes for {@code PATCH /api/v1/me}; {@code null} fields are left unchanged.
 *
 * @param username new username
 * @param displayName new display name (nickname); an empty string clears it
 */
public record ProfileUpdate(@Nullable String username, @Nullable String displayName) {

	public static ProfileUpdate username(String username) {
		return new ProfileUpdate(username, null);
	}

	public static ProfileUpdate displayName(String displayName) {
		return new ProfileUpdate(null, displayName);
	}

	Map<String, Object> toJson() {
		Map<String, Object> body = new LinkedHashMap<>();
		if (this.username != null) {
			body.put("username", this.username);
		}
		if (this.displayName != null) {
			body.put("display_name", this.displayName);
		}
		return body;
	}

}
