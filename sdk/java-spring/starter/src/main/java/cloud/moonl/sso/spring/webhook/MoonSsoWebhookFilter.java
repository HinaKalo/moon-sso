package cloud.moonl.sso.spring.webhook;

import java.io.IOException;
import java.io.InputStream;
import java.util.LinkedHashMap;
import java.util.Map;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.json.JsonMapper;

import cloud.moonl.sso.spring.core.ReplayCache;

import org.springframework.context.ApplicationEventPublisher;
import org.springframework.http.HttpHeaders;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Receives Moon SSO webhooks ({@code POST}, Standard Webhooks headers), verifies the signature
 * and timestamp, drops duplicates ({@code webhook-id}) and stale events (lower
 * {@code profile_version} than already seen for the same {@code sub}) and publishes the typed
 * {@link MoonSsoEvent} as a Spring application event.
 *
 * <p>Answers: {@code 204} when the event was handled or is a duplicate, {@code 400} for a
 * malformed request, {@code 401} when verification fails, {@code 413} for an oversized body
 * and {@code 500} when a listener threw (the server then redelivers with backoff).
 *
 * <p>The filter is registered in front of Spring Security, so the endpoint needs neither
 * authentication nor a CSRF token.
 */
public final class MoonSsoWebhookFilter extends OncePerRequestFilter {

	private static final Log logger = LogFactory.getLog(MoonSsoWebhookFilter.class);

	static final String REPLAY_NAMESPACE = "webhook-id";

	private final String path;

	private final StandardWebhookVerifier verifier;

	private final ReplayCache replayCache;

	private final JsonMapper json;

	private final ApplicationEventPublisher publisher;

	private final int maxBodyBytes;

	private final Map<String, Long> profileVersions = new LinkedHashMap<>(256, 0.75f, true) {

		private static final long serialVersionUID = 1L;

		@Override
		protected boolean removeEldestEntry(Map.Entry<String, Long> eldest) {
			return size() > 10_000;
		}

	};

	public MoonSsoWebhookFilter(String path, StandardWebhookVerifier verifier, ReplayCache replayCache,
			JsonMapper json, ApplicationEventPublisher publisher, int maxBodyBytes) {
		this.path = path;
		this.verifier = verifier;
		this.replayCache = replayCache;
		this.json = json;
		this.publisher = publisher;
		this.maxBodyBytes = maxBodyBytes;
	}

	@Override
	protected boolean shouldNotFilter(HttpServletRequest request) {
		String uri = request.getRequestURI().substring(request.getContextPath().length());
		return !this.path.equals(uri);
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws ServletException, IOException {
		response.setHeader(HttpHeaders.CACHE_CONTROL, "no-store");
		if (!"POST".equals(request.getMethod())) {
			response.setHeader(HttpHeaders.ALLOW, "POST");
			response.setStatus(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
			return;
		}
		long declared = request.getContentLengthLong();
		if (declared > this.maxBodyBytes) {
			response.setStatus(HttpServletResponse.SC_REQUEST_ENTITY_TOO_LARGE);
			return;
		}
		byte[] body;
		try (InputStream in = request.getInputStream()) {
			body = in.readNBytes(this.maxBodyBytes + 1);
		}
		if (body.length > this.maxBodyBytes) {
			response.setStatus(HttpServletResponse.SC_REQUEST_ENTITY_TOO_LARGE);
			return;
		}
		String id = request.getHeader("webhook-id");
		try {
			this.verifier.verify(id, request.getHeader("webhook-timestamp"), request.getHeader("webhook-signature"),
					body);
		}
		catch (WebhookVerificationException ex) {
			logger.debug("Rejected webhook delivery: " + ex.getMessage());
			response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
			return;
		}
		MoonSsoEventPayload payload;
		try {
			payload = this.json.readValue(body, MoonSsoEventPayload.class);
		}
		catch (JacksonException ex) {
			logger.debug("Rejected webhook delivery with a malformed body");
			response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
			return;
		}
		if (payload == null || payload.type() == null) {
			response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
			return;
		}
		if (!this.replayCache.markIfAbsent(REPLAY_NAMESPACE, id)) {
			logger.debug("Ignoring duplicate webhook delivery " + id);
			response.setStatus(HttpServletResponse.SC_NO_CONTENT);
			return;
		}
		if (isStale(payload)) {
			logger.debug("Ignoring stale webhook event " + payload.id());
			response.setStatus(HttpServletResponse.SC_NO_CONTENT);
			return;
		}
		try {
			this.publisher.publishEvent(MoonSsoEvent.of(payload, MoonSsoEvent.Source.WEBHOOK));
		}
		catch (RuntimeException ex) {
			this.replayCache.forget(REPLAY_NAMESPACE, id);
			logger.warn("Webhook listener failed for event " + payload.id() + " (" + payload.type()
					+ "); the delivery will be retried", ex);
			response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
			return;
		}
		remember(payload);
		response.setStatus(HttpServletResponse.SC_NO_CONTENT);
	}

	private boolean isStale(MoonSsoEventPayload payload) {
		MoonSsoEventData data = payload.dataOrEmpty();
		if (data.sub() == null || data.profileVersion() == null) {
			return false;
		}
		synchronized (this.profileVersions) {
			Long seen = this.profileVersions.get(data.sub());
			return seen != null && data.profileVersion() < seen;
		}
	}

	private void remember(MoonSsoEventPayload payload) {
		MoonSsoEventData data = payload.dataOrEmpty();
		if (data.sub() == null || data.profileVersion() == null) {
			return;
		}
		synchronized (this.profileVersions) {
			this.profileVersions.merge(data.sub(), data.profileVersion(), Math::max);
		}
	}

}
