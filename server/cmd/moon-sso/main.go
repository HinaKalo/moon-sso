// Command moon-sso runs the Moon SSO authorization server.
//
//	moon-sso serve   -config /etc/moon-sso/config.toml
//	moon-sso migrate -config ...
//	moon-sso admin create -config ... -username alice [-password-file f]
//	moon-sso keys rotate -config ...
//	moon-sso gen-master-key
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"moon-sso/server/internal/account"
	"moon-sso/server/internal/admin"
	"moon-sso/server/internal/app"
	"moon-sso/server/internal/config"
	"moon-sso/server/internal/crypto"
	"moon-sso/server/internal/db"
	"moon-sso/server/internal/store"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "serve":
		err = cmdServe(os.Args[2:])
	case "migrate":
		err = cmdMigrate(os.Args[2:])
	case "admin":
		err = cmdAdmin(os.Args[2:])
	case "user":
		err = cmdUser(os.Args[2:])
	case "keys":
		err = cmdKeys(os.Args[2:])
	case "gen-master-key":
		fmt.Println(crypto.GenerateMasterKey())
	case "version":
		fmt.Println(app.Version)
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: moon-sso serve|migrate|admin create|reset|list|user delete|keys rotate|gen-master-key|version [-config path]")
	os.Exit(2)
}

func newLogger(c *config.Config) *slog.Logger {
	var lvl slog.Level
	_ = lvl.UnmarshalText([]byte(c.Log.Level))
	opts := &slog.HandlerOptions{Level: lvl}
	if c.Log.Format == "text" {
		return slog.New(slog.NewTextHandler(os.Stderr, opts))
	}
	return slog.New(slog.NewJSONHandler(os.Stderr, opts))
}

func loadConfig(fs *flag.FlagSet, args []string) (*config.Config, error) {
	path := fs.String("config", "/etc/moon-sso/config.toml", "config file")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	return config.Load(*path)
}

func cmdServe(args []string) error {
	cfg, err := loadConfig(flag.NewFlagSet("serve", flag.ExitOnError), args)
	if err != nil {
		return err
	}
	log := newLogger(cfg)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	a, err := app.New(ctx, cfg, log)
	if err != nil {
		return err
	}
	return a.Run(ctx)
}

func openDB(ctx context.Context, cfg *config.Config) (*db.DB, error) {
	return db.Open(ctx, db.Options{DSN: cfg.Database.DSN, MaxOpenConns: 4, MaxIdleConns: 2, ConnMaxLifetime: time.Minute})
}

func cmdMigrate(args []string) error {
	cfg, err := loadConfig(flag.NewFlagSet("migrate", flag.ExitOnError), args)
	if err != nil {
		return err
	}
	ctx := context.Background()
	d, err := openDB(ctx, cfg)
	if err != nil {
		return err
	}
	defer d.Close()
	if err := d.Migrate(ctx, newLogger(cfg)); err != nil {
		return err
	}
	fmt.Println("migrations applied")
	return nil
}

func cmdAdmin(args []string) error {
	if len(args) < 1 || (args[0] != "create" && args[0] != "reset" && args[0] != "list") {
		return fmt.Errorf("usage: moon-sso admin create|reset|list -username NAME [-password-file FILE]")
	}
	sub := args[0]
	fs := flag.NewFlagSet("admin "+sub, flag.ExitOnError)
	username := fs.String("username", "", "console administrator username")
	display := fs.String("display-name", "", "display name (create)")
	pwFile := fs.String("password-file", "", "initial password from file (create; default: generate a temporary one)")
	cfg, err := loadConfig(fs, args[1:])
	if err != nil {
		return err
	}
	ctx := context.Background()
	a, err := app.New(ctx, cfg, newLogger(cfg))
	if err != nil {
		return err
	}
	switch sub {
	case "list":
		list, err := store.ListAdmins(ctx, a.DB)
		if err != nil {
			return err
		}
		for _, ad := range list {
			fmt.Printf("%-24s status=%d totp=%v must_change=%v\n", ad.Username, ad.Status, ad.HasTOTP(), ad.MustChangePassword)
		}
		return nil
	case "create":
		if *username == "" {
			return fmt.Errorf("-username is required")
		}
		password := ""
		if *pwFile != "" {
			b, err := os.ReadFile(*pwFile)
			if err != nil {
				return err
			}
			password = strings.TrimSpace(string(b))
		}
		ad, temp, err := admin.CreateAdmin(ctx, a.DB, a.Hasher, *username, *display, password)
		if err != nil {
			return err
		}
		fmt.Printf("console administrator %q created\n", ad.Username)
		if temp != "" {
			fmt.Printf("temporary password (change at first login): %s\n", temp)
		}
		fmt.Println("an authenticator app (TOTP) must be bound at first login to the console")
		return nil
	default: // reset: break-glass recovery
		ad, err := store.GetAdminByUsername(ctx, a.DB, account.NormalizeUsername(*username))
		if err != nil {
			return fmt.Errorf("no console administrator %q", *username)
		}
		ad.Status = store.UserActive
		temp, err := admin.ResetAdmin(ctx, a.DB, a.Hasher, ad, true)
		if err != nil {
			return err
		}
		_ = store.InsertAudit(ctx, a.DB, &store.AuditEntry{At: time.Now().UTC(), ActorAdmin: "cli", Action: "admin.admin_reset",
			TargetType: "admin", TargetID: ad.Username, IP: "cli"})
		fmt.Printf("administrator %q reset; sessions ended, TOTP cleared\ntemporary password: %s\n", ad.Username, temp)
		return nil
	}
}

// cmdUser manages SSO users (not console administrators) from the host.
// Deletion goes through account.Service so applications receive user.deleted
// and a tombstone is kept, exactly as when deleted from the console.
func cmdUser(args []string) error {
	if len(args) < 1 || args[0] != "delete" {
		return fmt.Errorf("usage: moon-sso user delete -username NAME -confirm NAME")
	}
	fs := flag.NewFlagSet("user delete", flag.ExitOnError)
	username := fs.String("username", "", "SSO username to delete")
	confirm := fs.String("confirm", "", "repeat the username to confirm")
	cfg, err := loadConfig(fs, args[1:])
	if err != nil {
		return err
	}
	if *username == "" || *confirm != *username {
		return fmt.Errorf("-username is required and -confirm must repeat it")
	}
	ctx := context.Background()
	a, err := app.New(ctx, cfg, newLogger(cfg))
	if err != nil {
		return err
	}
	u, err := store.GetUserByUsername(ctx, a.DB, account.NormalizeUsername(*username))
	if err != nil {
		return fmt.Errorf("no SSO user %q", *username)
	}
	if err := a.Accounts.Delete(ctx, account.Actor{Admin: true, AdminName: "cli", IP: "cli"}, u.ID); err != nil {
		return err
	}
	fmt.Printf("SSO user %q deleted; applications are notified with user.deleted\n", u.Username)
	return nil
}

func cmdKeys(args []string) error {
	if len(args) < 1 || args[0] != "rotate" {
		return fmt.Errorf("usage: moon-sso keys rotate")
	}
	cfg, err := loadConfig(flag.NewFlagSet("keys rotate", flag.ExitOnError), args[1:])
	if err != nil {
		return err
	}
	ctx := context.Background()
	a, err := app.New(ctx, cfg, newLogger(cfg))
	if err != nil {
		return err
	}
	return a.RotateKeys(ctx)
}
