package web_test

import (
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	moonsso "sso.moonl.cloud/sdk/go"
	"sso.moonl.cloud/sdk/go/web"
)

const testbed = "http://127.0.0.1:18601"

func TestRequireLoginCallbackAndHTMX(t *testing.T) {
	if resp, err := (&http.Client{Timeout: 3 * time.Second}).Get(testbed + "/readyz"); err != nil {
		t.Skip("testbed not running")
	} else {
		resp.Body.Close()
	}
	c, err := moonsso.NewClient(moonsso.Config{Issuer: testbed, ClientID: "test-web", ClientSecret: "test-web-secret-0123456789abcdef",
		RedirectURL: "http://127.0.0.1:18700/callback"})
	if err != nil {
		t.Fatal(err)
	}
	m, err := web.New(web.Options{Client: c})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle("/auth/", m.Routes())
	mux.Handle("/app", m.Require(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("hello " + web.Profile(r).PreferredUsername))
	})))
	srv := httptest.NewServer(mux)
	defer srv.Close()
	jar, _ := cookiejar.New(nil)
	hc := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	// HTMX requests get HX-Redirect instead of 302.
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/app", nil)
	req.Header.Set("HX-Request", "true")
	resp, err := hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.HasPrefix(resp.Header.Get("HX-Redirect"), testbed+"/oauth/authorize") {
		t.Fatalf("htmx: %d %q", resp.StatusCode, resp.Header.Get("HX-Redirect"))
	}

	resp, err = hc.Get(srv.URL + "/app")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	authURL, _ := url.Parse(resp.Header.Get("Location"))
	if !strings.HasPrefix(authURL.String(), testbed+"/oauth/authorize") {
		t.Fatalf("expected SSO redirect, got %s", authURL)
	}
	form := authURL.Query()
	form.Set("username", "alice")
	form.Set("password", "Wonderland-Pass-1")
	r2, err := http.Post(testbed+"/__test/authorize", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]string
	_ = json.NewDecoder(r2.Body).Decode(&out)
	r2.Body.Close()
	cb, _ := url.Parse(out["redirect"])
	resp, err = hc.Get(srv.URL + "/auth/callback?" + cb.RawQuery)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/app" {
		t.Fatalf("callback: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	resp, err = hc.Get(srv.URL + "/app")
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	n, _ := resp.Body.Read(buf)
	resp.Body.Close()
	if resp.StatusCode != 200 || string(buf[:n]) != "hello alice" {
		t.Fatalf("app: %d %q", resp.StatusCode, buf[:n])
	}
	// Logging out clears the session; the next visit goes back to the SSO.
	resp, err = hc.Get(srv.URL + "/auth/logout")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	resp, err = hc.Get(srv.URL + "/app")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if !strings.HasPrefix(resp.Header.Get("Location"), testbed+"/oauth/authorize") {
		t.Fatalf("after logout: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
}
