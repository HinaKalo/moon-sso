// Command web is a minimal server-side web app protected by Moon SSO, with
// a webhook receiver that keeps a local user table in sync.
//
//	MOON_CLIENT_ID=ms_xxx MOON_CLIENT_SECRET=mss_xxx MOON_WEBHOOK_SECRET=whsec_xxx \
//	  go run ./examples/web -addr 127.0.0.1:18700 -redirect http://127.0.0.1:18700/auth/callback
package main

import (
	"context"
	"flag"
	"fmt"
	"html"
	"log"
	"net/http"
	"os"
	"sync"

	moonsso "sso.moonl.cloud/sdk/go"
	"sso.moonl.cloud/sdk/go/web"
)

func main() {
	issuer := flag.String("issuer", "https://sso.moonl.cloud", "SSO issuer")
	addr := flag.String("addr", "127.0.0.1:18700", "listen address")
	redirect := flag.String("redirect", "http://127.0.0.1:18700/auth/callback", "registered redirect URI")
	flag.Parse()

	client, err := moonsso.NewClient(moonsso.Config{Issuer: *issuer, ClientID: os.Getenv("MOON_CLIENT_ID"),
		ClientSecret: os.Getenv("MOON_CLIENT_SECRET"), RedirectURL: *redirect})
	if err != nil {
		log.Fatal(err)
	}
	var mu sync.Mutex
	users := map[string]moonsso.Profile{} // local copy keyed by sub
	m, err := web.New(web.Options{Client: client, OnLogin: func(_ context.Context, p *moonsso.Profile) error {
		mu.Lock()
		users[p.Sub] = *p
		mu.Unlock()
		return nil
	}})
	if err != nil {
		log.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle("/auth/", m.Routes())
	mux.Handle("/", m.Require(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := web.Profile(r)
		fmt.Fprintf(w, "<h1>你好，%s</h1><p>sub: %s</p><p><a href=\"/auth/logout\">退出</a></p>", html.EscapeString(p.Name), html.EscapeString(p.Sub))
	})))
	if secret := os.Getenv("MOON_WEBHOOK_SECRET"); secret != "" {
		v, err := moonsso.NewWebhookVerifier(secret)
		if err != nil {
			log.Fatal(err)
		}
		mux.Handle("/hooks/sso", v.Handler(func(_ context.Context, e *moonsso.Event) error {
			mu.Lock()
			defer mu.Unlock()
			switch e.Type {
			case moonsso.EventUserDeleted:
				delete(users, e.Data.Sub)
			default:
				if old, ok := users[e.Data.Sub]; !ok || old.ProfileVersion < e.Data.ProfileVersion {
					users[e.Data.Sub] = *e.Data.Profile()
				}
			}
			log.Printf("sync %s %s v%d", e.Type, e.Data.Sub, e.Data.ProfileVersion)
			return nil
		}))
	}
	log.Printf("listening on http://%s", *addr)
	log.Fatal(http.ListenAndServe(*addr, mux))
}
