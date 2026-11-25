package cloud.moonl.sso.spring.core;

import java.io.IOException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.http.HttpRequest;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;

/**
 * Retries a token endpoint request once, with identical parameters, after a network error
 * (connection reset, timeout...) or a 502/503/504 response.
 *
 * <p>This is safe for Moon SSO because the server answers a repeated refresh token within its
 * 60 second grace period with the same successor, and an authorization code that was not
 * redeemed is still valid. 401 ({@code invalid_client}) and 400 ({@code invalid_grant}) are
 * never retried.
 */
public final class RetryOnceInterceptor implements ClientHttpRequestInterceptor {

	private static final Log logger = LogFactory.getLog(RetryOnceInterceptor.class);

	@Override
	public ClientHttpResponse intercept(HttpRequest request, byte[] body, ClientHttpRequestExecution execution)
			throws IOException {
		ClientHttpResponse response;
		try {
			response = execution.execute(request, body);
		}
		catch (IOException ex) {
			logger.debug("Token endpoint request failed with a network error, retrying once: "
					+ ex.getClass().getSimpleName());
			return execution.execute(request, body);
		}
		int status = response.getStatusCode().value();
		if (status == 502 || status == 503 || status == 504) {
			response.close();
			logger.debug("Token endpoint answered HTTP " + status + ", retrying once");
			return execution.execute(request, body);
		}
		return response;
	}

}
