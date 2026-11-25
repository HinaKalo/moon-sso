package cloud.moonl.sso.spring.account;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Result of {@code POST /api/v1/me/password}.
 *
 * @param changed whether the password was changed
 * @param otherSessionsRevoked whether the user's other sessions were signed out
 */
public record PasswordChangeResult(boolean changed,
		@JsonProperty("other_sessions_revoked") boolean otherSessionsRevoked) {
}
