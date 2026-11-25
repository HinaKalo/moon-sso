package cloud.moonl.sso.spring.account;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.Function;

import jakarta.servlet.http.HttpSession;
import org.jspecify.annotations.Nullable;

import cloud.moonl.sso.spring.core.MoonSsoDiscovery;
import cloud.moonl.sso.spring.core.MoonSsoException;
import cloud.moonl.sso.spring.core.MoonSsoHttp;

import org.springframework.context.ApplicationEventPublisher;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.util.Assert;
import org.springframework.web.client.RestClient;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

/**
 * Account API of the signed-in user ({@code /api/v1/me}).
 *
 * <p>The bean injected by the starter uses the access token of the user of the current
 * request; tokens are refreshed silently, and a 401 from the API triggers one forced refresh
 * and one replay of the request. Successful reads and changes are cached in the HTTP session
 * (used for conditional {@code If-None-Match} requests) and every change publishes a
 * {@link MoonSsoProfileChangedEvent}.
 *
 * <p>Required scopes: {@code profile} for reading, {@code profile:write} for profile and
 * avatar changes, {@code password:write} for password changes.
 */
public final class MoonSsoAccountClient {

	/** Session attribute holding the last known {@link MoonSsoProfile}. */
	public static final String PROFILE_SESSION_ATTRIBUTE = MoonSsoAccountClient.class.getName() + ".PROFILE";

	/** Maximum avatar size accepted by the server. */
	public static final int MAX_AVATAR_BYTES = 5 * 1024 * 1024;

	private final MoonSsoDiscovery discovery;

	private final MoonSsoHttp http;

	private final MoonSsoTokenSource tokens;

	private final @Nullable ApplicationEventPublisher publisher;

	private final boolean sessionCache;

	public MoonSsoAccountClient(MoonSsoDiscovery discovery, MoonSsoHttp http, MoonSsoTokenSource tokens,
			@Nullable ApplicationEventPublisher publisher) {
		this(discovery, http, tokens, publisher, tokens instanceof CurrentUserTokenSource);
	}

	private MoonSsoAccountClient(MoonSsoDiscovery discovery, MoonSsoHttp http, MoonSsoTokenSource tokens,
			@Nullable ApplicationEventPublisher publisher, boolean sessionCache) {
		this.discovery = discovery;
		this.http = http;
		this.tokens = tokens;
		this.publisher = publisher;
		this.sessionCache = sessionCache;
	}

	/**
	 * A client that uses another token source, e.g. {@link MoonSsoTokenSource#of(String)} for a
	 * token obtained outside a browser session. Such clients do not use the session cache.
	 */
	public MoonSsoAccountClient withTokenSource(MoonSsoTokenSource tokenSource) {
		return new MoonSsoAccountClient(this.discovery, this.http, tokenSource, this.publisher, false);
	}

	/** {@code GET /api/v1/me}. */
	public MoonSsoProfile getProfile() {
		MoonSsoProfile cached = cachedProfile();
		MoonSsoHttp.Response response = call((token) -> {
			RestClient.RequestHeadersSpec<?> spec = this.http.restClient()
				.get()
				.uri(api("/me"))
				.accept(MediaType.APPLICATION_JSON)
				.header(HttpHeaders.AUTHORIZATION, "Bearer " + token);
			if (cached != null) {
				spec.header(HttpHeaders.IF_NONE_MATCH, cached.etag());
			}
			return spec;
		});
		if (response.status() == 304 && cached != null) {
			return cached;
		}
		MoonSsoProfile profile = this.http.read(response, MoonSsoProfile.class);
		cache(profile);
		return profile;
	}

	/** {@code PATCH /api/v1/me} without a version check. */
	public MoonSsoProfile updateProfile(ProfileUpdate update) {
		return updateProfile(update, null);
	}

	/**
	 * {@code PATCH /api/v1/me}.
	 * @param update fields to change
	 * @param expectedProfileVersion when set, sent as {@code If-Match: "pv-<n>"}; a concurrent
	 * change makes the call fail with {@link MoonSsoException#isVersionConflict()}
	 */
	public MoonSsoProfile updateProfile(ProfileUpdate update, @Nullable Long expectedProfileVersion) {
		Assert.notNull(update, "update must not be null");
		byte[] body = this.http.write(update.toJson());
		MoonSsoHttp.Response response = call((token) -> {
			RestClient.RequestBodySpec spec = this.http.restClient()
				.patch()
				.uri(api("/me"))
				.contentType(MediaType.APPLICATION_JSON)
				.accept(MediaType.APPLICATION_JSON)
				.header(HttpHeaders.AUTHORIZATION, "Bearer " + token);
			if (expectedProfileVersion != null) {
				spec.header(HttpHeaders.IF_MATCH, "\"pv-" + expectedProfileVersion + "\"");
			}
			return spec.body(body);
		});
		return changed(this.http.read(response, MoonSsoProfile.class));
	}

	/**
	 * {@code PUT /api/v1/me/avatar} with the raw image bytes (PNG, JPEG, GIF or WebP, at most
	 * 5 MB).
	 */
	public MoonSsoProfile uploadAvatar(byte[] image, MediaType contentType) {
		Assert.notNull(image, "image must not be null");
		Assert.notNull(contentType, "contentType must not be null");
		Assert.isTrue("image".equals(contentType.getType()), "contentType must be an image type");
		if (image.length == 0 || image.length > MAX_AVATAR_BYTES) {
			throw new MoonSsoException("avatar_invalid", "Avatar must be between 1 byte and 5 MB", 0, "avatar");
		}
		MoonSsoHttp.Response response = call((token) -> this.http.restClient()
			.put()
			.uri(api("/me/avatar"))
			.contentType(contentType)
			.accept(MediaType.APPLICATION_JSON)
			.header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
			.body(image));
		return changed(this.http.read(response, MoonSsoProfile.class));
	}

	/** {@code DELETE /api/v1/me/avatar}. */
	public MoonSsoProfile deleteAvatar() {
		MoonSsoHttp.Response response = call((token) -> this.http.restClient()
			.delete()
			.uri(api("/me/avatar"))
			.accept(MediaType.APPLICATION_JSON)
			.header(HttpHeaders.AUTHORIZATION, "Bearer " + token));
		return changed(this.http.read(response, MoonSsoProfile.class));
	}

	/**
	 * {@code POST /api/v1/me/password}. The user's other sessions are signed out; this
	 * session stays signed in unless {@code keepThisDevice} is {@code false}.
	 */
	public PasswordChangeResult changePassword(String currentPassword, String newPassword, boolean keepThisDevice) {
		Assert.hasText(currentPassword, "currentPassword must not be empty");
		Assert.hasText(newPassword, "newPassword must not be empty");
		Map<String, Object> json = new LinkedHashMap<>();
		json.put("current_password", currentPassword);
		json.put("new_password", newPassword);
		json.put("keep_this_device", keepThisDevice);
		byte[] body = this.http.write(json);
		MoonSsoHttp.Response response = call((token) -> this.http.restClient()
			.post()
			.uri(api("/me/password"))
			.contentType(MediaType.APPLICATION_JSON)
			.accept(MediaType.APPLICATION_JSON)
			.header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
			.body(body));
		return this.http.read(response, PasswordChangeResult.class);
	}

	/** The profile cached in the current HTTP session, if any. */
	public @Nullable MoonSsoProfile cachedProfile() {
		if (!this.sessionCache) {
			return null;
		}
		HttpSession session = currentSession(false);
		Object value = (session != null) ? session.getAttribute(PROFILE_SESSION_ATTRIBUTE) : null;
		return (value instanceof MoonSsoProfile p) ? p : null;
	}

	private MoonSsoProfile changed(MoonSsoProfile profile) {
		cache(profile);
		if (this.publisher != null) {
			this.publisher.publishEvent(new MoonSsoProfileChangedEvent(profile));
		}
		return profile;
	}

	private void cache(MoonSsoProfile profile) {
		if (!this.sessionCache) {
			return;
		}
		HttpSession session = currentSession(true);
		if (session != null) {
			session.setAttribute(PROFILE_SESSION_ATTRIBUTE, profile);
		}
	}

	private static @Nullable HttpSession currentSession(boolean create) {
		RequestAttributes attributes = RequestContextHolder.getRequestAttributes();
		if (attributes instanceof ServletRequestAttributes servlet) {
			try {
				return servlet.getRequest().getSession(create);
			}
			catch (IllegalStateException ex) {
				return null;
			}
		}
		return null;
	}

	/**
	 * Runs a request with the current access token; on 401 forces one refresh and replays it
	 * once. Non-2xx responses (other than 304) become {@link MoonSsoException}.
	 */
	private MoonSsoHttp.Response call(Function<String, RestClient.RequestHeadersSpec<?>> request) {
		MoonSsoHttp.Response response = this.http.execute(request.apply(this.tokens.accessToken(false)));
		if (response.status() == 401) {
			response = this.http.execute(request.apply(this.tokens.accessToken(true)));
		}
		if (!response.is2xx() && response.status() != 304) {
			throw this.http.error(response);
		}
		return response;
	}

	private String api(String path) {
		return this.discovery.metadata().apiBase() + path;
	}

}
