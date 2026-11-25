package cloud.moonl.sso.spring.core;

import java.io.InputStream;
import java.net.http.HttpClient;
import java.time.Duration;
import java.util.Map;

import org.jspecify.annotations.Nullable;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.DeserializationFeature;
import tools.jackson.databind.json.JsonMapper;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.security.oauth2.client.http.OAuth2ErrorResponseErrorHandler;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

/**
 * HTTP plumbing shared by every SDK component: one JDK {@link HttpClient} (HTTP/1.1, no
 * redirects), the SDK {@code User-Agent}, a lenient JSON mapper and uniform error mapping
 * to {@link MoonSsoException}.
 */
public final class MoonSsoHttp {

	private static final int MAX_BODY = 8 * 1024 * 1024;

	private final RestClient restClient;

	private final RestClient tokenEndpointRestClient;

	private final JsonMapper json;

	public MoonSsoHttp(Duration connectTimeout, Duration readTimeout) {
		HttpClient httpClient = HttpClient.newBuilder()
			.version(HttpClient.Version.HTTP_1_1)
			.followRedirects(HttpClient.Redirect.NEVER)
			.connectTimeout(connectTimeout)
			.build();
		JdkClientHttpRequestFactory factory = new JdkClientHttpRequestFactory(httpClient);
		factory.setReadTimeout(readTimeout);
		this.json = JsonMapper.builder().disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES).build();
		this.restClient = RestClient.builder()
			.requestFactory(factory)
			.defaultHeader(HttpHeaders.USER_AGENT, MoonSsoUserAgent.VALUE)
			.build();
		OAuth2ErrorResponseErrorHandler oauth2Errors = new OAuth2ErrorResponseErrorHandler();
		this.tokenEndpointRestClient = RestClient.builder()
			.requestFactory(factory)
			.defaultHeader(HttpHeaders.USER_AGENT, MoonSsoUserAgent.VALUE)
			.configureMessageConverters((converters) -> {
				converters.addCustomConverter(new FormHttpMessageConverter());
				converters.addCustomConverter(new OAuth2AccessTokenResponseHttpMessageConverter());
			})
			.defaultStatusHandler(HttpStatusCode::isError,
					(request, response) -> oauth2Errors.handleError(request.getURI(), request.getMethod(), response))
			.requestInterceptor(new RetryOnceInterceptor())
			.build();
	}

	/** Plain client (no retries) used for API, discovery, JWKS and revocation calls. */
	public RestClient restClient() {
		return this.restClient;
	}

	/**
	 * Client for Spring Security's token response clients: OAuth2 converters, OAuth2 error
	 * handling and a single retry on network errors and 502/503/504.
	 */
	public RestClient tokenEndpointRestClient() {
		return this.tokenEndpointRestClient;
	}

	public JsonMapper json() {
		return this.json;
	}

	/**
	 * Executes a request and buffers the response. Transport failures become
	 * {@link MoonSsoException} with error {@code network}.
	 */
	public Response execute(RestClient.RequestHeadersSpec<?> spec) {
		Response result;
		try {
			result = spec.exchange((request, response) -> {
				byte[] body;
				try (InputStream in = response.getBody()) {
					body = in.readNBytes(MAX_BODY + 1);
				}
				return new Response(response.getStatusCode().value(), response.getHeaders(), body);
			});
		}
		catch (RestClientException ex) {
			throw new MoonSsoException(MoonSsoException.NETWORK, ex.getClass().getSimpleName(), 0, null, ex);
		}
		if (result == null) {
			throw new MoonSsoException(MoonSsoException.INVALID_RESPONSE, "No response", 0, null);
		}
		if (result.body().length > MAX_BODY) {
			throw new MoonSsoException(MoonSsoException.INVALID_RESPONSE, "Response body too large", result.status(),
					null);
		}
		return result;
	}

	/** Deserializes a JSON body, mapping parse failures to {@code invalid_response}. */
	public <T> T read(Response response, Class<T> type) {
		T value;
		try {
			value = this.json.readValue(response.body(), type);
		}
		catch (JacksonException ex) {
			throw new MoonSsoException(MoonSsoException.INVALID_RESPONSE, "Malformed JSON response", response.status(),
					null, ex);
		}
		if (value == null) {
			throw new MoonSsoException(MoonSsoException.INVALID_RESPONSE, "Empty response body", response.status(),
					null);
		}
		return value;
	}

	/** Serializes a value to JSON. */
	public byte[] write(Object value) {
		return this.json.writeValueAsBytes(value);
	}

	/** Builds the SDK error for a non-successful response. */
	@SuppressWarnings("unchecked")
	public MoonSsoException error(Response response) {
		String error = null;
		String description = null;
		String field = null;
		if (response.body().length > 0) {
			try {
				Map<String, Object> map = this.json.readValue(response.body(), Map.class);
				if (map != null) {
					error = asString(map.get("error"));
					description = asString(map.get("error_description"));
					field = asString(map.get("field"));
				}
			}
			catch (JacksonException | ClassCastException ex) {
				// not a JSON error document
			}
		}
		if (error == null || error.isBlank()) {
			error = defaultError(response.status());
		}
		return new MoonSsoException(error, description, response.status(), field);
	}

	private static String defaultError(int status) {
		return switch (status) {
			case 400 -> "invalid_request";
			case 401 -> "invalid_token";
			case 403 -> "insufficient_scope";
			case 404 -> "not_found";
			case 409 -> "conflict";
			case 410 -> "cursor_expired";
			case 412 -> "version_conflict";
			case 413 -> "payload_too_large";
			case 422 -> "validation_failed";
			case 429 -> "rate_limited";
			default -> (status >= 500) ? "server_error" : MoonSsoException.INVALID_RESPONSE;
		};
	}

	private static @Nullable String asString(@Nullable Object o) {
		return (o == null) ? null : o.toString();
	}

	/** A fully buffered HTTP response. */
	public record Response(int status, HttpHeaders headers, byte[] body) {

		public boolean is2xx() {
			return this.status >= 200 && this.status < 300;
		}

	}

}
