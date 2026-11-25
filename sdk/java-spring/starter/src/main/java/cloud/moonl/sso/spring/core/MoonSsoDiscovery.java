package cloud.moonl.sso.spring.core;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.locks.ReentrantLock;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jspecify.annotations.Nullable;

import org.springframework.http.MediaType;

/**
 * Fetches and caches the discovery document of the configured issuer.
 *
 * <p>The document is cached for {@code ttl} (one hour by default). When a refresh fails the
 * previous, expired copy keeps being used. Concurrent callers share a single fetch. The
 * {@code issuer} inside the document must equal the configured issuer exactly.
 */
public final class MoonSsoDiscovery {

	private static final Log logger = LogFactory.getLog(MoonSsoDiscovery.class);

	private final String issuer;

	private final MoonSsoHttp http;

	private final Duration ttl;

	private final Clock clock;

	private final ReentrantLock lock = new ReentrantLock();

	private volatile @Nullable Cached cached;

	public MoonSsoDiscovery(String issuer, MoonSsoHttp http, Duration ttl, Clock clock) {
		this.issuer = issuer;
		this.http = http;
		this.ttl = ttl;
		this.clock = clock;
	}

	public String issuer() {
		return this.issuer;
	}

	/** Returns the provider metadata, fetching it when absent or older than the TTL. */
	public MoonSsoProviderMetadata metadata() {
		Cached current = this.cached;
		Instant now = this.clock.instant();
		if (current != null && now.isBefore(current.expiresAt())) {
			return current.metadata();
		}
		this.lock.lock();
		try {
			current = this.cached;
			now = this.clock.instant();
			if (current != null && now.isBefore(current.expiresAt())) {
				return current.metadata();
			}
			try {
				MoonSsoProviderMetadata fresh = fetch();
				this.cached = new Cached(fresh, now.plus(this.ttl));
				return fresh;
			}
			catch (MoonSsoException ex) {
				if (current != null) {
					logger.warn("Refreshing Moon SSO discovery failed (" + ex.getError()
							+ "); using the cached document");
					// try again in a minute instead of on every call
					this.cached = new Cached(current.metadata(), now.plus(Duration.ofMinutes(1)));
					return current.metadata();
				}
				throw ex;
			}
		}
		finally {
			this.lock.unlock();
		}
	}

	/** Drops the cached document so the next call fetches it again. */
	public void invalidate() {
		this.cached = null;
	}

	@SuppressWarnings("unchecked")
	private MoonSsoProviderMetadata fetch() {
		MoonSsoHttp.Response response = this.http.execute(this.http.restClient()
			.get()
			.uri(this.issuer + "/.well-known/openid-configuration")
			.accept(MediaType.APPLICATION_JSON));
		if (!response.is2xx()) {
			throw this.http.error(response);
		}
		Map<String, Object> raw = this.http.read(response, Map.class);
		MoonSsoProviderMetadata metadata = new MoonSsoProviderMetadata(raw);
		if (!this.issuer.equals(metadata.issuer())) {
			throw new MoonSsoException(MoonSsoException.INVALID_RESPONSE,
					"Discovery issuer " + metadata.issuer() + " does not match configured issuer " + this.issuer, 0,
					null);
		}
		return metadata;
	}

	private record Cached(MoonSsoProviderMetadata metadata, Instant expiresAt) {
	}

}
