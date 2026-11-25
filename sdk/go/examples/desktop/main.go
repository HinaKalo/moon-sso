// Command desktop is a minimal desktop/CLI integration: it signs in through
// the system browser (or the app's own form for first-party apps), prints the
// profile and listens for live profile changes made in any other app.
//
//	go run ./examples/desktop -issuer https://sso.moonl.cloud -client ms_xxx
//	go run ./examples/desktop -client test-native -issuer http://127.0.0.1:18601 -user alice
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"

	moonsso "sso.moonl.cloud/sdk/go"
	"sso.moonl.cloud/sdk/go/desktop"
)

func main() {
	issuer := flag.String("issuer", "https://sso.moonl.cloud", "SSO issuer")
	clientID := flag.String("client", "", "client_id of a native application")
	user := flag.String("user", "", "sign in with username/password instead of the browser (first-party apps)")
	logout := flag.Bool("logout", false, "sign out and exit")
	flag.Parse()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	app, err := desktop.Open(ctx, desktop.Config{
		Issuer: *issuer, ClientID: *clientID, AppName: "MoonSSODemo",
		Scopes:           []string{"openid", "profile", "offline_access", "profile:write"},
		OnSessionExpired: func() { fmt.Println("会话已失效，请重新登录") },
		OnProfile:        func(p *moonsso.Profile) { fmt.Printf("资料已同步：%s（%s）\n", p.Name, p.PreferredUsername) },
	})
	if err != nil {
		fail(err)
	}
	if *logout {
		fail(app.Logout(ctx))
		return
	}
	if !app.Session.SignedIn(ctx) {
		if *user != "" {
			fmt.Print("密码：")
			pw := readLine()
			err = app.LoginWithPassword(ctx, *user, pw)
			var otp *moonsso.OTPRequiredError
			if errors.As(err, &otp) {
				fmt.Print("两步验证码：")
				err = app.CompleteOTP(ctx, otp.Challenge, readLine())
			}
		} else {
			fmt.Println("正在打开浏览器登录…")
			err = app.Login(ctx)
		}
		if err != nil {
			fail(err)
		}
	}
	me, err := app.Session.GetMe(ctx)
	if err != nil {
		fail(err)
	}
	fmt.Printf("已登录：%s（%s），sub=%s\n", me.Name, me.PreferredUsername, me.Sub)
	go app.Session.KeepFresh(ctx)
	fmt.Println("正在监听资料变更（在任意应用中修改昵称试试），Ctrl+C 退出")
	err = app.Session.Listen(ctx, func(e moonsso.Event) { fmt.Printf("事件 %s %v\n", e.Type, e.Data.Changed) })
	if err != nil && !errors.Is(err, context.Canceled) {
		fail(err)
	}
}

func readLine() string {
	s, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	return strings.TrimSpace(s)
}

func fail(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "错误：", err)
		os.Exit(1)
	}
}
