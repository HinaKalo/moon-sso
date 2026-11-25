// Package httpx assembles Echo instances, shared middleware, listeners
// (including systemd socket activation) and graceful shutdown.
package httpx

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/labstack/echo/v5"

	"moon-sso/server/internal/crypto"
)

// ErrResponded is returned by helpers that already wrote an error response;
// it stops the handler without a second write or a 500 in the logs.
var ErrResponded = errors.New("response already written")

// NewEcho returns an Echo with the middleware every listener shares.
func NewEcho(log *slog.Logger, renderer echo.Renderer, errHandler echo.HTTPErrorHandler) *echo.Echo {
	e := echo.NewWithConfig(echo.Config{
		Logger:           log,
		HTTPErrorHandler: errHandler,
		Renderer:         renderer,
		// Caddy on loopback is the only proxy we trust for X-Forwarded-For.
		IPExtractor: echo.ExtractIPFromXFFHeader(echo.TrustLoopback(true), echo.TrustLinkLocal(false), echo.TrustPrivateNet(false)),
	})
	e.Use(RequestID(), Recover(log), AccessLog(log))
	return e
}

// RequestID propagates X-Request-ID (generated when absent).
func RequestID() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c *echo.Context) error {
			id := c.Request().Header.Get("X-Request-ID")
			if id == "" || len(id) > 64 {
				id = crypto.RandomToken(12)
			}
			c.Set("request_id", id)
			c.Response().Header().Set("X-Request-ID", id)
			return next(c)
		}
	}
}

func Recover(log *slog.Logger) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c *echo.Context) (err error) {
			defer func() {
				if p := recover(); p != nil {
					if p == http.ErrAbortHandler {
						panic(p)
					}
					log.Error("panic", "panic", fmt.Sprint(p), "path", c.Request().URL.Path, "stack", string(debug.Stack()))
					err = echo.NewHTTPError(http.StatusInternalServerError, "服务器内部错误")
				}
			}()
			return next(c)
		}
	}
}

// AccessLog logs server errors, client errors at debug, and slow requests.
// Logging every request would dominate CPU at high token-refresh rates.
func AccessLog(log *slog.Logger) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c *echo.Context) error {
			start := time.Now()
			err := next(c)
			status := 0
			if r, uerr := echo.UnwrapResponse(c.Response()); uerr == nil {
				status = r.Status
			}
			if err != nil && !errors.Is(err, ErrResponded) {
				if sc := echo.StatusCode(err); sc != 0 {
					status = sc
				} else {
					status = 500
				}
			}
			dur := time.Since(start)
			attrs := []any{"method", c.Request().Method, "path", c.Request().URL.Path, "status", status,
				"ms", dur.Milliseconds(), "ip", c.RealIP(), "rid", c.Get("request_id")}
			switch {
			case status >= 500:
				log.Error("request", append(attrs, "err", errString(err))...)
			case dur > time.Second && !strings.HasSuffix(c.Request().URL.Path, "/events"):
				log.Warn("slow request", attrs...)
			case status >= 400:
				log.Debug("request", attrs...)
			}
			Metrics.Observe(c.RouteInfo().Path, status, dur)
			return err
		}
	}
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// SecurityHeaders sets a strict CSP and the usual hardening headers for HTML.
func SecurityHeaders() echo.MiddlewareFunc {
	const csp = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data: https:; " +
		"connect-src 'self'; form-action 'self' https: http://127.0.0.1:* http://localhost:* http://[::1]:*; " +
		"frame-ancestors 'none'; base-uri 'none'; object-src 'none'"
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c *echo.Context) error {
			h := c.Response().Header()
			h.Set("Content-Security-Policy", csp)
			h.Set("X-Content-Type-Options", "nosniff")
			h.Set("X-Frame-Options", "DENY")
			h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
			h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
			h.Set("Cross-Origin-Opener-Policy", "same-origin")
			return next(c)
		}
	}
}

// HTMXPages keeps HTMX fragment rendering from leaking into full-page loads.
// Two kinds of htmx requests replace the whole <body> with the response and
// therefore must get the full page, never a fragment:
//   - boosted navigation (hx-boost on the console's body: every link click
//     and plain form post carries HX-Request: true and HX-Boosted: true);
//   - history restores (back/forward after hx-push-url without a snapshot).
//
// For them the HX-Request header is dropped before any handler looks at it.
// Vary tells caches that the same URL has fragment and full-page variants.
func HTMXPages() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c *echo.Context) error {
			h := c.Request().Header
			if h.Get("HX-Boosted") == "true" || h.Get("HX-History-Restore-Request") == "true" {
				h.Del("HX-Request")
			}
			c.Response().Header().Add("Vary", "HX-Request")
			return next(c)
		}
	}
}

// NoStore marks responses as non-cacheable (pages with personal data, tokens).
func NoStore() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c *echo.Context) error {
			c.Response().Header().Set("Cache-Control", "no-store")
			c.Response().Header().Set("Pragma", "no-cache")
			return next(c)
		}
	}
}

// BodyLimit rejects request bodies larger than n bytes.
func BodyLimit(n int64) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c *echo.Context) error {
			r := c.Request()
			if r.ContentLength > n {
				return echo.NewHTTPError(http.StatusRequestEntityTooLarge, "请求体过大")
			}
			r.Body = http.MaxBytesReader(c.Response(), r.Body, n)
			return next(c)
		}
	}
}

// ---- listeners ----

// Listeners returns listeners by name. Under systemd socket activation
// (LISTEN_FDS / LISTEN_FDNAMES) inherited sockets are used, so restarts never
// refuse connections; otherwise it binds the given addresses.
func Listeners(addrs map[string]string) (map[string]net.Listener, error) {
	out := map[string]net.Listener{}
	if pid, _ := strconv.Atoi(os.Getenv("LISTEN_PID")); pid == os.Getpid() {
		n, _ := strconv.Atoi(os.Getenv("LISTEN_FDS"))
		names := strings.Split(os.Getenv("LISTEN_FDNAMES"), ":")
		for i := 0; i < n; i++ {
			fd := 3 + i
			name := ""
			if i < len(names) {
				name = names[i]
			}
			f := os.NewFile(uintptr(fd), name)
			l, err := net.FileListener(f)
			f.Close()
			if err != nil {
				return nil, fmt.Errorf("socket activation fd %d: %w", fd, err)
			}
			out[name] = l
		}
		os.Unsetenv("LISTEN_PID")
		os.Unsetenv("LISTEN_FDS")
		os.Unsetenv("LISTEN_FDNAMES")
	}
	for name, addr := range addrs {
		if _, ok := out[name]; ok || addr == "" {
			continue
		}
		l, err := net.Listen("tcp", addr)
		if err != nil {
			return nil, fmt.Errorf("listen %s (%s): %w", name, addr, err)
		}
		out[name] = l
	}
	return out, nil
}

// Serve runs h on l until ctx is cancelled, then drains for up to grace.
func Serve(ctx context.Context, l net.Listener, h http.Handler, grace time.Duration, log *slog.Logger) error {
	srv := &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      0, // per-handler deadlines via http.ResponseController (SSE streams are long-lived)
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
	errCh := make(chan error, 1)
	go func() { errCh <- srv.Serve(l) }()
	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
	}
	sctx, cancel := context.WithTimeout(context.Background(), grace)
	defer cancel()
	err := srv.Shutdown(sctx)
	if errors.Is(err, context.DeadlineExceeded) {
		_ = srv.Close()
	}
	if serr := <-errCh; serr != nil && !errors.Is(serr, http.ErrServerClosed) {
		return serr
	}
	return err
}

// WriteDeadline extends the response write deadline for normal handlers.
func WriteDeadline(d time.Duration) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c *echo.Context) error {
			_ = http.NewResponseController(c.Response()).SetWriteDeadline(time.Now().Add(d))
			return next(c)
		}
	}
}

// ---- systemd notify ----

// Notify sends a state string (e.g. "READY=1") to systemd if NOTIFY_SOCKET is set.
func Notify(state string) error {
	sock := os.Getenv("NOTIFY_SOCKET")
	if sock == "" {
		return nil
	}
	if strings.HasPrefix(sock, "@") {
		sock = "\x00" + sock[1:]
	}
	conn, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: sock, Net: "unixgram"})
	if err != nil {
		return err
	}
	defer conn.Close()
	_, err = conn.Write([]byte(state))
	return err
}

// Watchdog pings systemd at half the WATCHDOG_USEC interval while healthy() is true.
func Watchdog(ctx context.Context, healthy func() bool) {
	usec, _ := strconv.Atoi(os.Getenv("WATCHDOG_USEC"))
	if usec <= 0 {
		return
	}
	t := time.NewTicker(time.Duration(usec) * time.Microsecond / 2)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if healthy() {
				_ = Notify("WATCHDOG=1")
			}
		}
	}
}
