package cloud.moonl.sso.spring.sync;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.function.Function;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.jspecify.annotations.Nullable;

import cloud.moonl.sso.spring.account.CurrentUserTokenSource;
import cloud.moonl.sso.spring.core.MoonSsoDiscovery;
import cloud.moonl.sso.spring.core.MoonSsoException;
import cloud.moonl.sso.spring.core.MoonSsoHttp;
import cloud.moonl.sso.spring.webhook.MoonSsoEvent;
import cloud.moonl.sso.spring.webhook.MoonSsoEventPayload;

import org.springframework.context.ApplicationEventPublisher;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.util.Assert;
import org.springframework.web.client.RestClient;
import org.springframework.web.util.UriComponentsBuilder;

/**
 * Server-side user synchronisation: a client_credentials token with scope {@code users:sync},
 * the ordered changes feed ({@code /api/v1/users/changes}) and the snapshot API
 * ({@code /api/v1/users}).
 *
 * <p>Typical use from a scheduled job:
 *
 * <pre>{@code
 * String cursor = store.loadCursor();           // null on first run
 * cursor = userSync.synchronize(cursor, new MoonSsoSyncHandler() {
 *     public void onUser(MoonSsoUserSnapshot u) { users.upsert(u); }
 *     public void onEvent(MoonSsoEvent e)      { users.apply(e); }
 *     public void onCursor(String c)           { store.saveCursor(c); }
 * });
 * }</pre>
 *
 * A missing cursor or a 410 (cursor older than the retention) triggers a full snapshot,
 * after which the feed continues from the snapshot's watermark.
 */
public final class MoonSsoUserSync {

	private static final int MAX_LIMIT = 500;

	private final MoonSsoDiscovery discovery;

	private final MoonSsoHttp http;

	private final OAuth2AuthorizedClientManager clientManager;

	private final OAuth2AuthorizedClientService clientService;

	private final String registrationId;

	private final int pageSize;

	private final @Nullable ApplicationEventPublisher publisher;

	private final Authentication principal;

	public MoonSsoUserSync(MoonSsoDiscovery discovery, MoonSsoHttp http, OAuth2AuthorizedClientManager clientManager,
			OAuth2AuthorizedClientService clientService, String registrationId, String clientId, int pageSize,
			@Nullable ApplicationEventPublisher publisher) {
		this.discovery = discovery;
		this.http = http;
		this.clientManager = clientManager;
		this.clientService = clientService;
		this.registrationId = registrationId;
		this.pageSize = Math.max(1, Math.min(pageSize, MAX_LIMIT));
		this.publisher = publisher;
		this.principal = new ClientPrincipal(clientId);
	}

	/** One page of the changes feed after {@code cursor} (null or empty starts at the beginning). */
	public ChangesPage syncChanges(@Nullable String cursor) {
		return syncChanges(cursor, this.pageSize);
	}

	/**
	 * One page of the changes feed.
	 * @throws MoonSsoCursorExpiredException when the cursor is older than the retention
	 */
	public ChangesPage syncChanges(@Nullable String cursor, int limit) {
		UriComponentsBuilder uri = UriComponentsBuilder.fromUriString(api("/users/changes"))
			.queryParam("limit", clamp(limit));
		if (cursor != null && !cursor.isBlank()) {
			uri.queryParam("cursor", cursor);
		}
		String url = uri.build().encode().toUriString();
		MoonSsoHttp.Response response = call((token) -> get(url, token));
		if (response.status() == 410) {
			throw new MoonSsoCursorExpiredException(this.http.error(response).getErrorDescription());
		}
		if (!response.is2xx()) {
			throw this.http.error(response);
		}
		ChangesResponse body = this.http.read(response, ChangesResponse.class);
		List<MoonSsoEvent> events = new ArrayList<>();
		if (body.events() != null) {
			for (MoonSsoEventPayload payload : body.events()) {
				events.add(MoonSsoEvent.of(payload, MoonSsoEvent.Source.CHANGES_FEED));
			}
		}
		String next = (body.nextCursor() != null && !body.nextCursor().isBlank()) ? body.nextCursor()
				: (cursor != null ? cursor : "0");
		return new ChangesPage(events, next, body.hasMore());
	}

	/** One page of the user snapshot. */
	public UsersPage listUsers(@Nullable String cursor, int limit) {
		UriComponentsBuilder uri = UriComponentsBuilder.fromUriString(api("/users")).queryParam("limit", clamp(limit));
		if (cursor != null && !cursor.isBlank()) {
			uri.queryParam("cursor", cursor);
		}
		String url = uri.build().encode().toUriString();
		MoonSsoHttp.Response response = call((token) -> get(url, token));
		if (!response.is2xx()) {
			throw this.http.error(response);
		}
		return this.http.read(response, UsersPage.class);
	}

	/**
	 * Snapshot of one user who granted this client.
	 * @return the user, or {@code null} if the subject is unknown or did not grant this client
	 */
	public @Nullable MoonSsoUserSnapshot getUser(String sub) {
		Assert.hasText(sub, "sub must not be empty");
		String url = UriComponentsBuilder.fromUriString(api("/users/{sub}")).buildAndExpand(sub).encode().toUriString();
		MoonSsoHttp.Response response = call((token) -> get(url, token));
		if (response.status() == 404) {
			return null;
		}
		if (!response.is2xx()) {
			throw this.http.error(response);
		}
		return this.http.read(response, MoonSsoUserSnapshot.class);
	}

	/**
	 * Starts a full sync: the first page is fetched immediately so {@link FullSync#watermark()}
	 * is known; further pages are fetched while iterating.
	 */
	public FullSync fullSync() {
		return new FullSync(listUsers(null, this.pageSize));
	}

	/**
	 * Brings the caller up to date: a full sync when {@code cursor} is empty or expired, then
	 * every page of the changes feed until no more events are available.
	 * @return the cursor to persist (also reported through {@link MoonSsoSyncHandler#onCursor})
	 */
	public String synchronize(@Nullable String cursor, MoonSsoSyncHandler handler) {
		Assert.notNull(handler, "handler must not be null");
		String current = cursor;
		if (current == null || current.isBlank()) {
			current = runFullSync(handler);
		}
		while (true) {
			ChangesPage page;
			try {
				page = syncChanges(current, this.pageSize);
			}
			catch (MoonSsoCursorExpiredException ex) {
				current = runFullSync(handler);
				continue;
			}
			for (MoonSsoEvent event : page.events()) {
				handler.onEvent(event);
			}
			current = page.nextCursor();
			handler.onCursor(current);
			if (!page.hasMore() || page.events().isEmpty()) {
				return current;
			}
		}
	}

	/**
	 * {@link #synchronize} that publishes each event as a Spring application event (source
	 * {@link MoonSsoEvent.Source#CHANGES_FEED}); full-sync snapshots are passed to
	 * {@code onUser}.
	 */
	public String pollAndPublish(@Nullable String cursor, java.util.function.Consumer<MoonSsoUserSnapshot> onUser) {
		Assert.state(this.publisher != null, "no ApplicationEventPublisher configured");
		return synchronize(cursor, new MoonSsoSyncHandler() {

			@Override
			public void onUser(MoonSsoUserSnapshot user) {
				onUser.accept(user);
			}

			@Override
			public void onEvent(MoonSsoEvent event) {
				MoonSsoUserSync.this.publisher.publishEvent(event);
			}

		});
	}

	private String runFullSync(MoonSsoSyncHandler handler) {
		FullSync full = fullSync();
		handler.onFullSyncStart(full.watermark());
		for (MoonSsoUserSnapshot user : full) {
			handler.onUser(user);
		}
		handler.onFullSyncComplete(full.watermark());
		handler.onCursor(full.watermark());
		return full.watermark();
	}

	/** A client_credentials access token for {@code users:sync} (cached until it nearly expires). */
	public String accessToken(boolean forceRefresh) {
		if (forceRefresh) {
			this.clientService.removeAuthorizedClient(this.registrationId, this.principal.getName());
		}
		OAuth2AuthorizedClient client;
		try {
			client = this.clientManager.authorize(
					OAuth2AuthorizeRequest.withClientRegistrationId(this.registrationId).principal(this.principal).build());
		}
		catch (OAuth2AuthorizationException ex) {
			throw CurrentUserTokenSource.translate(ex, this.registrationId);
		}
		if (client == null) {
			throw new MoonSsoException("unauthorized_client", "client_credentials token unavailable", 0, null);
		}
		return client.getAccessToken().getTokenValue();
	}

	private MoonSsoHttp.Response call(Function<String, RestClient.RequestHeadersSpec<?>> request) {
		MoonSsoHttp.Response response = this.http.execute(request.apply(accessToken(false)));
		if (response.status() == 401) {
			response = this.http.execute(request.apply(accessToken(true)));
		}
		return response;
	}

	private RestClient.RequestHeadersSpec<?> get(String url, String token) {
		return this.http.restClient()
			.get()
			.uri(java.net.URI.create(url))
			.accept(MediaType.APPLICATION_JSON)
			.header(HttpHeaders.AUTHORIZATION, "Bearer " + token);
	}

	private String api(String path) {
		return this.discovery.metadata().apiBase() + path;
	}

	private static int clamp(int limit) {
		return Math.max(1, Math.min(limit, MAX_LIMIT));
	}

	/** Lazily paged iteration over all users of a full sync. */
	public final class FullSync implements Iterable<MoonSsoUserSnapshot> {

		private final UsersPage first;

		FullSync(UsersPage first) {
			this.first = first;
		}

		/** Cursor of the changes feed to continue from once the snapshot has been stored. */
		public String watermark() {
			return this.first.watermark();
		}

		@Override
		public Iterator<MoonSsoUserSnapshot> iterator() {
			return new Iterator<>() {

				private UsersPage page = FullSync.this.first;

				private int index;

				@Override
				public boolean hasNext() {
					while (this.index >= this.page.users().size()) {
						if (!this.page.hasMore() || this.page.nextCursor() == null) {
							return false;
						}
						this.page = listUsers(this.page.nextCursor(), MoonSsoUserSync.this.pageSize);
						this.index = 0;
					}
					return true;
				}

				@Override
				public MoonSsoUserSnapshot next() {
					if (!hasNext()) {
						throw new NoSuchElementException();
					}
					return this.page.users().get(this.index++);
				}

			};
		}

	}

	record ChangesResponse(List<MoonSsoEventPayload> events, @JsonProperty("next_cursor") String nextCursor,
			@JsonProperty("has_more") boolean hasMore) {
	}

	/** Principal under which the client_credentials token is cached. */
	static final class ClientPrincipal extends AbstractAuthenticationToken {

		private static final long serialVersionUID = 1L;

		private final String clientId;

		ClientPrincipal(String clientId) {
			super(AuthorityUtils.NO_AUTHORITIES);
			this.clientId = clientId;
			setAuthenticated(true);
		}

		@Override
		public Object getCredentials() {
			return "";
		}

		@Override
		public Object getPrincipal() {
			return this.clientId;
		}

	}

}
