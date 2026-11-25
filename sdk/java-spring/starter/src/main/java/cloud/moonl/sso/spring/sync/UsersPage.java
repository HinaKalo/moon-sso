package cloud.moonl.sso.spring.sync;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.jspecify.annotations.Nullable;

/**
 * One page of {@code GET /api/v1/users}.
 *
 * @param users user snapshots
 * @param hasMore whether another page follows
 * @param watermark changes feed cursor to continue from after a full sync (use the value of
 * the first page)
 * @param nextCursor cursor of the next page
 */
public record UsersPage(List<MoonSsoUserSnapshot> users, @JsonProperty("has_more") boolean hasMore,
		String watermark, @JsonProperty("next_cursor") @Nullable String nextCursor) {

	public UsersPage {
		users = (users != null) ? List.copyOf(users) : List.of();
	}

}
