package cloud.moonl.sso.spring.registration;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.jspecify.annotations.Nullable;

/**
 * {@code GET /api/v1/registration}: whether self-service sign-up is open and the rules for new
 * accounts.
 *
 * @param registrationOpen whether new accounts can be created
 * @param passwordMinLength minimum password length
 * @param usernamePattern regular expression usernames must match
 * @param clientRegistration mode of developer client registration
 */
public record RegistrationInfo(@JsonProperty("registration_open") boolean registrationOpen,
		@JsonProperty("password_min_length") int passwordMinLength,
		@JsonProperty("username_pattern") @Nullable String usernamePattern,
		@JsonProperty("client_registration") @Nullable String clientRegistration) {
}
