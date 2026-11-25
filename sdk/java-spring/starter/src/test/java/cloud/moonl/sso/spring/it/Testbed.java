package cloud.moonl.sso.spring.it;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.stream.Collectors;

import tools.jackson.databind.json.JsonMapper;

/**
 * Helpers for the shared Moon SSO testbed (docs/sdk-spec.md §8). Only fresh random users and
 * clients registered by these tests are modified.
 */
public final class Testbed {

	public static final String URL = System.getProperty("moon-sso.testbed", "http://127.0.0.1:18601");

	public static final String WEB_CLIENT = "test-web";

	public static final String WEB_SECRET = "test-web-secret-0123456789abcdef";

	public static final String WEB_REDIRECT = "http://127.0.0.1:18700/callback";

	public static final String NATIVE_CLIENT = "test-native";

	private static final SecureRandom RANDOM = new SecureRandom();

	private static final JsonMapper JSON = JsonMapper.builder().build();

	private static final HttpClient HTTP = HttpClient.newBuilder()
		.version(HttpClient.Version.HTTP_1_1)
		.connectTimeout(Duration.ofSeconds(10))
		.followRedirects(HttpClient.Redirect.NEVER)
		.build();

	private Testbed() {
	}

	/** A created test user. */
	public record User(String username, String password, String publicSub) {
	}

	/** Result of {@code /__test/authorize}. */
	public record Authorized(String redirect, String sessionToken) {

		public Map<String, String> callbackParams() {
			return query(URI.create(this.redirect));
		}

	}

	/** PKCE pair. */
	public record Pkce(String verifier, String challenge) {

		public static Pkce create() {
			String verifier = random(48);
			try {
				byte[] digest = MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(StandardCharsets.US_ASCII));
				return new Pkce(verifier, Base64.getUrlEncoder().withoutPadding().encodeToString(digest));
			}
			catch (Exception ex) {
				throw new IllegalStateException(ex);
			}
		}

	}

	public static String random(int bytes) {
		byte[] b = new byte[bytes];
		RANDOM.nextBytes(b);
		return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
	}

	public static String randomLower(int length) {
		String alphabet = "abcdefghijklmnopqrstuvwxyz0123456789";
		StringBuilder sb = new StringBuilder(length);
		for (int i = 0; i < length; i++) {
			sb.append(alphabet.charAt(RANDOM.nextInt(alphabet.length())));
		}
		return sb.toString();
	}

	/** True when the testbed answers discovery. */
	public static boolean reachable() {
		try {
			return get("/.well-known/openid-configuration").statusCode() == 200;
		}
		catch (RuntimeException ex) {
			return false;
		}
	}

	/** Creates a fresh random user ({@code t_<8 random>}). */
	public static User createUser() {
		String username = "t_" + randomLower(8);
		String password = "Tb-" + random(12) + "-9";
		Map<String, Object> out = json(postJson("/__test/users", Map.of("username", username, "password", password)),
				200);
		return new User(username, password, (String) out.get("public_sub"));
	}

	/** Completes an authorization request as the given user, as a browser would. */
	public static Authorized authorize(Map<String, String> authorizationParams, User user) {
		Map<String, String> form = new LinkedHashMap<>(authorizationParams);
		form.put("username", user.username());
		form.put("password", user.password());
		Map<String, Object> out = json(postForm("/__test/authorize", form, null), 200);
		return new Authorized((String) out.get("redirect"), (String) out.get("session_token"));
	}

	/**
	 * First-party login of a public client ({@code /oauth/authorize-challenge}) and code
	 * exchange; returns the token response.
	 */
	public static Map<String, Object> challengeLogin(String clientId, User user, String scope) {
		Pkce pkce = Pkce.create();
		Map<String, String> form = new LinkedHashMap<>();
		form.put("client_id", clientId);
		form.put("username", user.username());
		form.put("password", user.password());
		form.put("scope", scope);
		form.put("code_challenge", pkce.challenge());
		form.put("code_challenge_method", "S256");
		Map<String, Object> challenge = json(postForm("/oauth/authorize-challenge", form, null), 200);
		Map<String, String> token = new LinkedHashMap<>();
		token.put("grant_type", "authorization_code");
		token.put("code", (String) challenge.get("authorization_code"));
		token.put("code_verifier", pkce.verifier());
		token.put("client_id", clientId);
		return json(postForm("/oauth/token", token, null), 200);
	}

	/** Exchanges an authorization code of a confidential client (client_secret_basic). */
	public static Map<String, Object> exchangeCode(String clientId, String secret, String code, String redirectUri,
			String verifier) {
		Map<String, String> form = new LinkedHashMap<>();
		form.put("grant_type", "authorization_code");
		form.put("code", code);
		form.put("redirect_uri", redirectUri);
		form.put("code_verifier", verifier);
		return json(postForm("/oauth/token", form, basic(clientId, secret)), 200);
	}

	/**
	 * Grants {@code test-web} access for a user through the browser flow, so the user appears
	 * in test-web's sync feed.
	 */
	public static Map<String, Object> grantTestWeb(User user) {
		Pkce pkce = Pkce.create();
		Map<String, String> params = new LinkedHashMap<>();
		params.put("client_id", WEB_CLIENT);
		params.put("redirect_uri", WEB_REDIRECT);
		params.put("response_type", "code");
		params.put("scope", "openid profile");
		params.put("state", random(16));
		params.put("nonce", random(16));
		params.put("code_challenge", pkce.challenge());
		params.put("code_challenge_method", "S256");
		Authorized authorized = authorize(params, user);
		String code = authorized.callbackParams().get("code");
		return exchangeCode(WEB_CLIENT, WEB_SECRET, code, WEB_REDIRECT, pkce.verifier());
	}

	/** Changes a user's display name server-side (emits user.updated). */
	public static void setDisplayName(User user, String displayName) {
		json(postJson("/__test/users/" + user.username() + "/profile", Map.of("display_name", displayName)), 200);
	}

	/** A single-use initial access token for DCR. */
	public static String initialAccessToken() {
		return (String) json(postJson("/__test/iat", Map.of()), 200).get("token");
	}

	public static void trust(String clientId) {
		json(postJson("/__test/clients/" + clientId + "/trust", Map.of()), 200);
	}

	/** Points a client's webhook at {@code url}; returns the new {@code whsec_} secret. */
	public static String webhook(String clientId, String url) {
		return (String) json(postJson("/__test/clients/" + clientId + "/webhook", Map.of("url", url)), 200).get("secret");
	}

	public static void backchannel(String clientId, String url) {
		json(postJson("/__test/clients/" + clientId + "/backchannel", Map.of("url", url)), 200);
	}

	/** Ends an SSO session (triggers back-channel logout). */
	public static void logout(String sessionToken) {
		json(post("/__test/logout?session_token=" + enc(sessionToken), HttpRequest.BodyPublishers.noBody(), null,
				null), 200);
	}

	/** A free loopback TCP port. */
	public static int freePort() {
		try (ServerSocket socket = new ServerSocket(0)) {
			socket.setReuseAddress(true);
			return socket.getLocalPort();
		}
		catch (IOException ex) {
			throw new IllegalStateException(ex);
		}
	}

	// ------------------------------------------------------------------ HTTP

	public static HttpResponse<String> get(String path) {
		return send(HttpRequest.newBuilder(URI.create(URL + path)).GET().build());
	}

	public static HttpResponse<String> postJson(String path, Object body) {
		return post(path, HttpRequest.BodyPublishers.ofByteArray(JSON.writeValueAsBytes(body)), "application/json",
				null);
	}

	public static HttpResponse<String> postForm(String path, Map<String, String> form, String authorization) {
		return post(path, HttpRequest.BodyPublishers.ofString(form(form)), "application/x-www-form-urlencoded",
				authorization);
	}

	private static HttpResponse<String> post(String path, HttpRequest.BodyPublisher body, String contentType,
			String authorization) {
		HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(URL + path)).POST(body);
		if (contentType != null) {
			b.header("Content-Type", contentType);
		}
		if (authorization != null) {
			b.header("Authorization", authorization);
		}
		return send(b.build());
	}

	public static HttpResponse<String> send(HttpRequest request) {
		try {
			return HTTP.send(request, HttpResponse.BodyHandlers.ofString());
		}
		catch (IOException ex) {
			throw new IllegalStateException("testbed request failed: " + request.uri(), ex);
		}
		catch (InterruptedException ex) {
			Thread.currentThread().interrupt();
			throw new IllegalStateException(ex);
		}
	}

	@SuppressWarnings("unchecked")
	public static Map<String, Object> json(HttpResponse<String> response, int expectedStatus) {
		if (response.statusCode() != expectedStatus) {
			throw new IllegalStateException(response.request().method() + " " + response.request().uri().getPath()
					+ " answered " + response.statusCode() + ": " + response.body());
		}
		return JSON.readValue(response.body(), Map.class);
	}

	public static String form(Map<String, String> form) {
		return form.entrySet().stream().map((e) -> enc(e.getKey()) + "=" + enc(e.getValue())).collect(Collectors.joining("&"));
	}

	public static String enc(String s) {
		return URLEncoder.encode(s, StandardCharsets.UTF_8);
	}

	public static String basic(String id, String secret) {
		return "Basic " + Base64.getEncoder()
			.encodeToString((enc(id) + ":" + enc(secret)).getBytes(StandardCharsets.UTF_8));
	}

	public static Map<String, String> query(URI uri) {
		Map<String, String> out = new LinkedHashMap<>();
		String raw = uri.getRawQuery();
		if (raw == null) {
			return out;
		}
		for (String pair : raw.split("&")) {
			int eq = pair.indexOf('=');
			String k = URLDecoder.decode((eq < 0) ? pair : pair.substring(0, eq), StandardCharsets.UTF_8);
			String v = (eq < 0) ? "" : URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8);
			out.put(k, v);
		}
		return out;
	}

}
