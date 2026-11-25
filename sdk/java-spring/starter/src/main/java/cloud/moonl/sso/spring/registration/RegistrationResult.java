package cloud.moonl.sso.spring.registration;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.jspecify.annotations.Nullable;

/**
 * Response of {@code POST /api/v1/register}. Continue with the normal login, passing
 * {@link #loginHint()} as {@code login_hint}.
 *
 * @param created whether the account was created
 * @param username normalised username
 * @param loginHint value for the {@code login_hint} authorization parameter
 * @param authorizationEndpoint authorization endpoint
 */
public record RegistrationResult(boolean created, String username,
		@JsonProperty("login_hint") @Nullable String loginHint,
		@JsonProperty("authorization_endpoint") @Nullable String authorizationEndpoint) {
}
