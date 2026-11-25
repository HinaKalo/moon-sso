// Package safehttp is the only way the server makes outbound requests to
// URLs chosen by clients (webhooks, back-channel logout). It refuses to
// connect to loopback, private, link-local and other internal addresses after
// DNS resolution, so a registered URL cannot reach Caddy's admin API, MySQL,
// the admin listener or anything else on the host network.
package safehttp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"syscall"
	"time"
)

var ErrForbiddenAddress = errors.New("destination address is not allowed")

var blocked = func() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range []string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
		"192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
		"203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4", "255.255.255.255/32",
		"::/128", "::1/128", "::ffff:0:0/96", "64:ff9b::/96", "64:ff9b:1::/48", "100::/64", "2001::/23",
		"2001:db8::/32", "fc00::/7", "fe80::/10", "ff00::/8",
	} {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}()

// AddrAllowed reports whether ip is a public unicast address.
func AddrAllowed(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsValid() || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsMulticast() || ip.IsUnspecified() {
		return false
	}
	for _, p := range blocked {
		if p.Contains(ip) {
			return false
		}
	}
	return true
}

func control(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || !AddrAllowed(ip) {
		return fmt.Errorf("%w: %s", ErrForbiddenAddress, host)
	}
	return nil
}

// Client returns an HTTP client that enforces the address policy at dial
// time (defeating DNS rebinding), never follows redirects and never uses
// environment proxies.
func Client(timeout time.Duration) *http.Client {
	dialer := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second, Control: control}
	tr := &http.Transport{
		Proxy:                  nil,
		DialContext:            dialer.DialContext,
		ForceAttemptHTTP2:      true,
		MaxIdleConns:           100,
		MaxIdleConnsPerHost:    4,
		IdleConnTimeout:        60 * time.Second,
		TLSHandshakeTimeout:    5 * time.Second,
		ResponseHeaderTimeout:  timeout,
		ExpectContinueTimeout:  time.Second,
		MaxResponseHeaderBytes: 16 << 10,
	}
	return &http.Client{
		Transport:     tr,
		Timeout:       timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// ValidateURL checks a client-supplied callback URL at registration time.
// allowInsecure permits http:// (only settable by administrators).
func ValidateURL(raw string, allowInsecure bool) error {
	if raw == "" {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		return errors.New("URL 格式不正确")
	}
	if u.Scheme != "https" && !(allowInsecure && u.Scheme == "http") {
		return errors.New("只允许 https 地址")
	}
	if u.Host == "" || u.User != nil || u.Fragment != "" {
		return errors.New("URL 不能包含用户信息或片段")
	}
	host := u.Hostname()
	if ip, err := netip.ParseAddr(host); err == nil {
		if !AddrAllowed(ip) {
			return errors.New("不允许使用内网或本机地址")
		}
		return nil
	}
	lower := strings.ToLower(host)
	if lower == "localhost" || strings.HasSuffix(lower, ".localhost") || strings.HasSuffix(lower, ".local") ||
		strings.HasSuffix(lower, ".internal") || !strings.Contains(lower, ".") {
		return errors.New("不允许使用内网或本机地址")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil || len(addrs) == 0 {
		return errors.New("无法解析该域名")
	}
	for _, a := range addrs {
		if !AddrAllowed(a) {
			return errors.New("该域名解析到了内网或本机地址")
		}
	}
	return nil
}

// ReadLimited reads at most n bytes of a response body and discards the rest.
func ReadLimited(r io.Reader, n int64) []byte {
	b, _ := io.ReadAll(io.LimitReader(r, n))
	_, _ = io.Copy(io.Discard, io.LimitReader(r, 1<<20))
	return b
}
