package cloud.moonl.sso.spring;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Configuration of the Moon SSO starter ({@code moon-sso.*}).
 *
 * <p>Only {@code moon-sso.issuer} and {@code moon-sso.client-id} are required. Every
 * endpoint is discovered from {@code <issuer>/.well-known/openid-configuration}.
 */
@ConfigurationProperties(prefix = "moon-sso")
public class MoonSsoProperties {

	/** Issuer URL, e.g. {@code https://sso.moonl.cloud}. All endpoints are discovered from it. */
	private String issuer;

	/** OAuth client_id of this application. */
	private String clientId;

	/** OAuth client secret (confidential clients). Leave empty for public clients. */
	private String clientSecret;

	/** Scopes requested at login. */
	private List<String> scopes = new ArrayList<>(List.of("openid", "profile", "offline_access"));

	/** Spring Security client registration id; also used in {@code /oauth2/authorization/{id}}. */
	private String registrationId = "moon-sso";

	/**
	 * Redirect URI registered for this client. Supports the Spring Security placeholders
	 * {@code {baseUrl}} and {@code {registrationId}}.
	 */
	private String redirectUri = "{baseUrl}/login/oauth2/code/{registrationId}";

	/**
	 * Token endpoint authentication: {@code client_secret_basic}, {@code client_secret_post}
	 * or {@code none}. Defaults to {@code client_secret_basic} when a secret is set,
	 * otherwise {@code none}.
	 */
	private String clientAuthenticationMethod;

	/**
	 * Where the authorization server sends the browser after RP-initiated logout. Must be
	 * registered as a post_logout_redirect_uri. Empty disables the parameter.
	 */
	private String postLogoutRedirectUri = "{baseUrl}/";

	/** Access tokens are refreshed when their remaining lifetime falls below this value. */
	private Duration refreshSkew = Duration.ofSeconds(120);

	/** Clock skew tolerated when validating JWT time claims. */
	private Duration clockSkew = Duration.ofSeconds(60);

	/** How long the discovery document is cached (a stale copy is used when refreshing fails). */
	private Duration discoveryTtl = Duration.ofHours(1);

	/** HTTP connect timeout for calls to the authorization server. */
	private Duration connectTimeout = Duration.ofSeconds(10);

	/** HTTP read timeout for calls to the authorization server. */
	private Duration readTimeout = Duration.ofSeconds(30);

	private final Login login = new Login();

	private final ResourceServer resourceServer = new ResourceServer();

	private final Webhook webhook = new Webhook();

	private final BackchannelLogout backchannelLogout = new BackchannelLogout();

	private final Sync sync = new Sync();

	public String getIssuer() {
		return this.issuer;
	}

	public void setIssuer(String issuer) {
		this.issuer = issuer;
	}

	public String getClientId() {
		return this.clientId;
	}

	public void setClientId(String clientId) {
		this.clientId = clientId;
	}

	public String getClientSecret() {
		return this.clientSecret;
	}

	public void setClientSecret(String clientSecret) {
		this.clientSecret = clientSecret;
	}

	public List<String> getScopes() {
		return this.scopes;
	}

	public void setScopes(List<String> scopes) {
		this.scopes = scopes;
	}

	public String getRegistrationId() {
		return this.registrationId;
	}

	public void setRegistrationId(String registrationId) {
		this.registrationId = registrationId;
	}

	public String getRedirectUri() {
		return this.redirectUri;
	}

	public void setRedirectUri(String redirectUri) {
		this.redirectUri = redirectUri;
	}

	public String getClientAuthenticationMethod() {
		return this.clientAuthenticationMethod;
	}

	public void setClientAuthenticationMethod(String clientAuthenticationMethod) {
		this.clientAuthenticationMethod = clientAuthenticationMethod;
	}

	public String getPostLogoutRedirectUri() {
		return this.postLogoutRedirectUri;
	}

	public void setPostLogoutRedirectUri(String postLogoutRedirectUri) {
		this.postLogoutRedirectUri = postLogoutRedirectUri;
	}

	public Duration getRefreshSkew() {
		return this.refreshSkew;
	}

	public void setRefreshSkew(Duration refreshSkew) {
		this.refreshSkew = refreshSkew;
	}

	public Duration getClockSkew() {
		return this.clockSkew;
	}

	public void setClockSkew(Duration clockSkew) {
		this.clockSkew = clockSkew;
	}

	public Duration getDiscoveryTtl() {
		return this.discoveryTtl;
	}

	public void setDiscoveryTtl(Duration discoveryTtl) {
		this.discoveryTtl = discoveryTtl;
	}

	public Duration getConnectTimeout() {
		return this.connectTimeout;
	}

	public void setConnectTimeout(Duration connectTimeout) {
		this.connectTimeout = connectTimeout;
	}

	public Duration getReadTimeout() {
		return this.readTimeout;
	}

	public void setReadTimeout(Duration readTimeout) {
		this.readTimeout = readTimeout;
	}

	public Login getLogin() {
		return this.login;
	}

	public ResourceServer getResourceServer() {
		return this.resourceServer;
	}

	public Webhook getWebhook() {
		return this.webhook;
	}

	public BackchannelLogout getBackchannelLogout() {
		return this.backchannelLogout;
	}

	public Sync getSync() {
		return this.sync;
	}

	/** True when a non-blank client secret is configured. */
	public boolean hasClientSecret() {
		return this.clientSecret != null && !this.clientSecret.isBlank();
	}

	/** Effective token endpoint authentication method. */
	public String effectiveClientAuthenticationMethod() {
		if (this.clientAuthenticationMethod != null && !this.clientAuthenticationMethod.isBlank()) {
			return this.clientAuthenticationMethod;
		}
		return hasClientSecret() ? "client_secret_basic" : "none";
	}

	/** Issuer without a trailing slash. */
	public String normalizedIssuer() {
		String iss = this.issuer == null ? "" : this.issuer.trim();
		while (iss.endsWith("/")) {
			iss = iss.substring(0, iss.length() - 1);
		}
		return iss;
	}

	/** OAuth 2.0 login (authorization code + PKCE) settings. */
	public static class Login {

		/** Whether the starter contributes a default SecurityFilterChain when the application defines none. */
		private boolean defaultSecurityFilterChain = true;

		/**
		 * Path that receives the authorization response. {@code null} keeps Spring Security's
		 * {@code /login/oauth2/code/*}. Must match the path of {@code moon-sso.redirect-uri}.
		 */
		private String processingUrl;

		/**
		 * Where authentication failures (including an invalid {@code iss} parameter) are
		 * redirected. The default is a minimal page served by the starter.
		 */
		private String failureUrl = "/moon-sso/login-error";

		/** Claim used as the principal name. */
		private String userNameAttribute = "sub";

		/** Paths the default SecurityFilterChain leaves public. */
		private List<String> permitAll = new ArrayList<>(List.of("/error", "/favicon.ico"));

		/** Answer HTMX requests (HX-Request: true) that need login with 200 + HX-Redirect instead of 302. */
		private boolean htmx = true;

		/** Revoke the refresh token at the authorization server on local logout. */
		private boolean revokeOnLogout = true;

		public boolean isDefaultSecurityFilterChain() {
			return this.defaultSecurityFilterChain;
		}

		public void setDefaultSecurityFilterChain(boolean defaultSecurityFilterChain) {
			this.defaultSecurityFilterChain = defaultSecurityFilterChain;
		}

		public String getProcessingUrl() {
			return this.processingUrl;
		}

		public void setProcessingUrl(String processingUrl) {
			this.processingUrl = processingUrl;
		}

		public String getFailureUrl() {
			return this.failureUrl;
		}

		public void setFailureUrl(String failureUrl) {
			this.failureUrl = failureUrl;
		}

		public String getUserNameAttribute() {
			return this.userNameAttribute;
		}

		public void setUserNameAttribute(String userNameAttribute) {
			this.userNameAttribute = userNameAttribute;
		}

		public List<String> getPermitAll() {
			return this.permitAll;
		}

		public void setPermitAll(List<String> permitAll) {
			this.permitAll = permitAll;
		}

		public boolean isHtmx() {
			return this.htmx;
		}

		public void setHtmx(boolean htmx) {
			this.htmx = htmx;
		}

		public boolean isRevokeOnLogout() {
			return this.revokeOnLogout;
		}

		public void setRevokeOnLogout(boolean revokeOnLogout) {
			this.revokeOnLogout = revokeOnLogout;
		}

	}

	/** Resource server (Bearer access token) settings. */
	public static class ResourceServer {

		/** Accept Bearer access tokens issued by Moon SSO in the starter's security configuration. */
		private boolean enabled = false;

		/** Accepted audiences; the token's {@code aud} must contain one. Defaults to the client id. */
		private List<String> audiences = new ArrayList<>();

		public boolean isEnabled() {
			return this.enabled;
		}

		public void setEnabled(boolean enabled) {
			this.enabled = enabled;
		}

		public List<String> getAudiences() {
			return this.audiences;
		}

		public void setAudiences(List<String> audiences) {
			this.audiences = audiences;
		}

	}

	/** Standard Webhooks receiver settings. */
	public static class Webhook {

		/** Whether the webhook endpoint is active (also requires a secret). */
		private boolean enabled = true;

		/** Path of the webhook endpoint. */
		private String path = "/moon-sso/webhooks";

		/** Signing secret ({@code whsec_...}) shown when the webhook was configured. */
		private String secret;

		/** Maximum allowed difference between {@code webhook-timestamp} and now. */
		private Duration tolerance = Duration.ofMinutes(5);

		/** Maximum accepted request body size in bytes. */
		private int maxBodyBytes = 256 * 1024;

		public boolean isEnabled() {
			return this.enabled;
		}

		public void setEnabled(boolean enabled) {
			this.enabled = enabled;
		}

		public String getPath() {
			return this.path;
		}

		public void setPath(String path) {
			this.path = path;
		}

		public String getSecret() {
			return this.secret;
		}

		public void setSecret(String secret) {
			this.secret = secret;
		}

		public Duration getTolerance() {
			return this.tolerance;
		}

		public void setTolerance(Duration tolerance) {
			this.tolerance = tolerance;
		}

		public int getMaxBodyBytes() {
			return this.maxBodyBytes;
		}

		public void setMaxBodyBytes(int maxBodyBytes) {
			this.maxBodyBytes = maxBodyBytes;
		}

	}

	/** OpenID Connect Back-Channel Logout receiver settings. */
	public static class BackchannelLogout {

		/** Whether the back-channel logout endpoint is active. */
		private boolean enabled = true;

		/** Path of the endpoint; register {@code <app>/<path>} as backchannel_logout_uri. */
		private String path = "/moon-sso/backchannel-logout";

		/** How long logout token {@code jti} values are remembered to reject replays. */
		private Duration replayWindow = Duration.ofMinutes(5);

		public boolean isEnabled() {
			return this.enabled;
		}

		public void setEnabled(boolean enabled) {
			this.enabled = enabled;
		}

		public String getPath() {
			return this.path;
		}

		public void setPath(String path) {
			this.path = path;
		}

		public Duration getReplayWindow() {
			return this.replayWindow;
		}

		public void setReplayWindow(Duration replayWindow) {
			this.replayWindow = replayWindow;
		}

	}

	/** Users sync (client_credentials + changes feed) settings. */
	public static class Sync {

		/** Scope requested with client_credentials. */
		private String scope = "users:sync";

		/** Page size for the changes feed and the snapshot API (max 500). */
		private int pageSize = 100;

		public String getScope() {
			return this.scope;
		}

		public void setScope(String scope) {
			this.scope = scope;
		}

		public int getPageSize() {
			return this.pageSize;
		}

		public void setPageSize(int pageSize) {
			this.pageSize = pageSize;
		}

	}

}
