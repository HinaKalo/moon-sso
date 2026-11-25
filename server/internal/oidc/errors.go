package oidc

import (
	"crypto/sha256"
	"net/http"

	"github.com/labstack/echo/v5"
)

var sha256New = sha256.New

// Error is an OAuth 2.0 error response (RFC 6749 §5.2).
type Error struct {
	Status      int
	Code        string
	Description string
	DPoPNonce   string
}

func (e *Error) Error() string { return e.Code + ": " + e.Description }

func errInvalidRequest(d string) *Error {
	return &Error{http.StatusBadRequest, "invalid_request", d, ""}
}
func errInvalidClient(d string) *Error {
	return &Error{http.StatusUnauthorized, "invalid_client", d, ""}
}
func errInvalidGrant(d string) *Error { return &Error{http.StatusBadRequest, "invalid_grant", d, ""} }
func errInvalidScope(d string) *Error { return &Error{http.StatusBadRequest, "invalid_scope", d, ""} }
func errUnauthorizedClient(d string) *Error {
	return &Error{http.StatusBadRequest, "unauthorized_client", d, ""}
}
func errUnsupportedGrant(d string) *Error {
	return &Error{http.StatusBadRequest, "unsupported_grant_type", d, ""}
}
func errInvalidDPoP(d string) *Error {
	return &Error{http.StatusBadRequest, "invalid_dpop_proof", d, ""}
}
func errServer(d string) *Error { return &Error{http.StatusInternalServerError, "server_error", d, ""} }
func errAccessDenied(d string) *Error {
	return &Error{http.StatusForbidden, "access_denied", d, ""}
}
func errTemporarilyUnavailable(d string) *Error {
	return &Error{http.StatusServiceUnavailable, "temporarily_unavailable", d, ""}
}

// writeError sends an OAuth JSON error with no-store caching.
func writeError(c *echo.Context, e *Error) error {
	h := c.Response().Header()
	h.Set("Cache-Control", "no-store")
	h.Set("Pragma", "no-cache")
	if e.DPoPNonce != "" {
		h.Set("DPoP-Nonce", e.DPoPNonce)
	}
	if e.Status == http.StatusUnauthorized && e.Code == "invalid_client" && c.Request().Header.Get("Authorization") != "" {
		h.Set("WWW-Authenticate", `Basic realm="moon-sso"`)
	}
	if e.Status == http.StatusServiceUnavailable {
		h.Set("Retry-After", "3")
	}
	return c.JSON(e.Status, map[string]string{"error": e.Code, "error_description": e.Description})
}

func writeJSON(c *echo.Context, status int, v any) error {
	h := c.Response().Header()
	h.Set("Cache-Control", "no-store")
	h.Set("Pragma", "no-cache")
	return c.JSON(status, v)
}
