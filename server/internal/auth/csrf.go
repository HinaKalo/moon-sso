package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/url"
	"time"

	"github.com/labstack/echo/v5"

	"moon-sso/server/internal/crypto"
)

const csrfCookie = "csrf"

// CSRF implements a signed double-submit token bound to a random cookie,
// plus Origin and Sec-Fetch-Site checks for every unsafe request.
type CSRF struct {
	Key     []byte
	Cookies Cookies
	Origin  string // expected origin, e.g. https://sso.moonl.cloud
}

func (c *CSRF) token(seed string) string {
	m := hmac.New(sha256.New, c.Key)
	m.Write([]byte(seed))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

// Token returns the form token for this request, creating the seed cookie if needed.
func (c *CSRF) Token(ec *echo.Context) string {
	if v, ok := ec.Get("csrf").(string); ok {
		return v
	}
	seed := ""
	if ck, err := ec.Cookie(c.Cookies.Name(csrfCookie)); err == nil && len(ck.Value) >= 32 && len(ck.Value) <= 64 {
		seed = ck.Value
	} else {
		seed = crypto.RandomToken(32)
		ec.SetCookie(c.Cookies.New(csrfCookie, seed, time.Now().Add(365*24*time.Hour)))
	}
	t := c.token(seed)
	ec.Set("csrf", t)
	return t
}

func (c *CSRF) sameOrigin(r *http.Request) bool {
	switch r.Header.Get("Sec-Fetch-Site") {
	case "", "same-origin", "none":
	default:
		return false
	}
	origin := r.Header.Get("Origin")
	if origin == "" || origin == "null" {
		// Older browsers omit Origin on same-origin form posts; fall back to Referer.
		ref := r.Header.Get("Referer")
		if ref == "" {
			return origin == ""
		}
		u, err := url.Parse(ref)
		if err != nil {
			return false
		}
		return u.Scheme+"://"+u.Host == c.Origin
	}
	return origin == c.Origin
}

// Valid reports whether an unsafe request carries a valid token and origin.
func (c *CSRF) Valid(ec *echo.Context) bool {
	r := ec.Request()
	if !c.sameOrigin(r) {
		return false
	}
	ck, err := ec.Cookie(c.Cookies.Name(csrfCookie))
	if err != nil || ck.Value == "" {
		return false
	}
	got := r.Header.Get("X-CSRF-Token")
	if got == "" {
		got = ec.FormValue("_csrf")
	}
	return hmac.Equal([]byte(got), []byte(c.token(ck.Value)))
}

// Middleware rejects unsafe requests without a valid token.
func (c *CSRF) Middleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(ec *echo.Context) error {
			r := ec.Request()
			switch r.Method {
			case http.MethodGet, http.MethodHead, http.MethodOptions:
				return next(ec)
			}
			if !c.sameOrigin(r) {
				return echo.NewHTTPError(http.StatusForbidden, "跨站请求被拒绝")
			}
			ck, err := ec.Cookie(c.Cookies.Name(csrfCookie))
			if err != nil || ck.Value == "" {
				return echo.NewHTTPError(http.StatusForbidden, "页面已过期，请刷新后重试")
			}
			got := r.Header.Get("X-CSRF-Token")
			if got == "" {
				got = ec.FormValue("_csrf")
			}
			if !hmac.Equal([]byte(got), []byte(c.token(ck.Value))) {
				return echo.NewHTTPError(http.StatusForbidden, "页面已过期，请刷新后重试")
			}
			return next(ec)
		}
	}
}
