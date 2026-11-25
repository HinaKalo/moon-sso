package moonsso

import (
	"errors"
	"fmt"
)

// Error is returned for OAuth and API errors. Code is the OAuth error code
// ("invalid_grant", "access_denied", ...), "network" for transport failures
// or "invalid_response" for unparsable answers.
type Error struct {
	Code        string
	Description string
	Status      int
	Field       string         // validation errors: the offending field
	Extra       map[string]any // the full error body
}

func (e *Error) Error() string {
	if e.Description != "" {
		return fmt.Sprintf("moonsso: %s: %s", e.Code, e.Description)
	}
	return "moonsso: " + e.Code
}

// ErrSessionExpired means the refresh token is no longer valid; the user
// must sign in again. It wraps the server's invalid_grant error.
var ErrSessionExpired = errors.New("moonsso: session expired, sign in again")

// ErrNotSignedIn is returned when no tokens are stored.
var ErrNotSignedIn = errors.New("moonsso: not signed in")

// OTPRequiredError is returned by first-party login when the account has
// two-factor authentication. Call Client.CompleteOTP with the user's code.
type OTPRequiredError struct {
	Challenge *Challenge
}

func (e *OTPRequiredError) Error() string { return "moonsso: one-time password required" }

// IsCode reports whether err is an *Error with the given code.
func IsCode(err error, code string) bool {
	var e *Error
	return errors.As(err, &e) && e.Code == code
}

// isRetryable reports transient failures worth one retry.
func isRetryable(err error) bool {
	var e *Error
	if !errors.As(err, &e) {
		return false
	}
	return e.Code == "network" || e.Status == 502 || e.Status == 503 || e.Status == 504
}
