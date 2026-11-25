package cloud.moonl.sso.spring.jwt;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;

import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.Resource;
import com.nimbusds.jose.util.ResourceRetriever;
import org.jspecify.annotations.Nullable;

import cloud.moonl.sso.spring.core.MoonSsoDiscovery;
import cloud.moonl.sso.spring.core.MoonSsoException;
import cloud.moonl.sso.spring.core.MoonSsoHttp;

import org.springframework.http.MediaType;

/**
 * JWK set of the authorization server, located through discovery.
 *
 * <p>Keys are cached for one hour. A token signed with an unknown {@code kid} forces a
 * refetch, at most once every 30 seconds; when the server is unreachable the last known keys
 * stay in use.
 */
public final class MoonSsoJwkSource implements JWKSource<SecurityContext> {

	private static final long CACHE_TTL_MS = Duration.ofHours(1).toMillis();

	private static final long REFRESH_TIMEOUT_MS = Duration.ofSeconds(15).toMillis();

	private static final long MIN_REFETCH_INTERVAL_MS = Duration.ofSeconds(30).toMillis();

	private final MoonSsoDiscovery discovery;

	private final MoonSsoHttp http;

	private volatile @Nullable Delegate delegate;

	public MoonSsoJwkSource(MoonSsoDiscovery discovery, MoonSsoHttp http) {
		this.discovery = discovery;
		this.http = http;
	}

	@Override
	public List<JWK> get(JWKSelector jwkSelector, @Nullable SecurityContext context) throws KeySourceException {
		JWKSource<SecurityContext> source;
		try {
			source = delegate();
		}
		catch (MoonSsoException ex) {
			throw new KeySourceException("Moon SSO discovery unavailable: " + ex.getError(), ex);
		}
		return source.get(jwkSelector, context);
	}

	private JWKSource<SecurityContext> delegate() {
		String jwksUri = this.discovery.metadata().jwksUri();
		Delegate current = this.delegate;
		if (current != null && current.uri().equals(jwksUri)) {
			return current.source();
		}
		synchronized (this) {
			current = this.delegate;
			if (current != null && current.uri().equals(jwksUri)) {
				return current.source();
			}
			URL url;
			try {
				url = URI.create(jwksUri).toURL();
			}
			catch (MalformedURLException | IllegalArgumentException ex) {
				throw new MoonSsoException(MoonSsoException.INVALID_RESPONSE, "Invalid jwks_uri", 0, null, ex);
			}
			JWKSource<SecurityContext> source = JWKSourceBuilder.<SecurityContext>create(url, new Retriever(this.http))
				.cache(CACHE_TTL_MS, REFRESH_TIMEOUT_MS)
				.rateLimited(MIN_REFETCH_INTERVAL_MS)
				.retrying(true)
				.outageTolerant(CACHE_TTL_MS * 24)
				.build();
			this.delegate = new Delegate(jwksUri, source);
			return source;
		}
	}

	private record Delegate(String uri, JWKSource<SecurityContext> source) {
	}

	/** Fetches the JWK set through the SDK HTTP client (User-Agent, timeouts). */
	private static final class Retriever implements ResourceRetriever {

		private final MoonSsoHttp http;

		Retriever(MoonSsoHttp http) {
			this.http = http;
		}

		@Override
		public Resource retrieveResource(URL url) throws IOException {
			MoonSsoHttp.Response response;
			try {
				response = this.http.execute(this.http.restClient()
					.get()
					.uri(URI.create(url.toString()))
					.accept(MediaType.APPLICATION_JSON, MediaType.parseMediaType("application/jwk-set+json")));
			}
			catch (MoonSsoException ex) {
				throw new IOException("Fetching JWK set failed: " + ex.getError(), ex);
			}
			if (!response.is2xx()) {
				throw new IOException("Fetching JWK set failed: HTTP " + response.status());
			}
			MediaType type = response.headers().getContentType();
			return new Resource(new String(response.body(), StandardCharsets.UTF_8),
					(type != null) ? type.toString() : MediaType.APPLICATION_JSON_VALUE);
		}

	}

}
