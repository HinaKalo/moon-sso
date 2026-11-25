// Package settings holds runtime-tunable options edited from the admin panel.
// Values live in the settings table and are cached in memory; a periodic
// reload keeps multiple instances consistent within a few seconds.
package settings

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	"moon-sso/server/internal/db"
	"moon-sso/server/internal/store"
)

const (
	ClientRegClosed   = "closed"
	ClientRegApproval = "approval"
	ClientRegOpen     = "open"
)

type Values struct {
	SiteName               string `json:"site_name"`
	RegistrationOpen       bool   `json:"registration_open"`
	ClientRegistration     string `json:"client_registration"`
	PasswordMinLength      int    `json:"password_min_length"`
	UsernameCooldownDays   int    `json:"username_cooldown_days"`
	UsernameReserveDays    int    `json:"username_reserve_days"`
	SessionIdleDays        int    `json:"session_idle_days"`
	AccessTokenMinutes     int    `json:"access_token_minutes"`
	RefreshIdleDays        int    `json:"refresh_idle_days"`
	RefreshAbsoluteDays    int    `json:"refresh_absolute_days"`
	MaxClientsPerDeveloper int    `json:"max_clients_per_developer"`
}

func Defaults() Values {
	return Values{
		SiteName:               "Moon SSO",
		RegistrationOpen:       true,
		ClientRegistration:     ClientRegApproval,
		PasswordMinLength:      8,
		UsernameCooldownDays:   30,
		UsernameReserveDays:    30,
		SessionIdleDays:        30,
		AccessTokenMinutes:     10,
		RefreshIdleDays:        30,
		RefreshAbsoluteDays:    180,
		MaxClientsPerDeveloper: 10,
	}
}

func (v Values) Validate() error {
	switch {
	case v.SiteName == "" || len(v.SiteName) > 60:
		return fmt.Errorf("站点名称长度需在 1–60 之间")
	case v.ClientRegistration != ClientRegClosed && v.ClientRegistration != ClientRegApproval && v.ClientRegistration != ClientRegOpen:
		return fmt.Errorf("应用注册模式无效")
	case v.PasswordMinLength < 8 || v.PasswordMinLength > 64:
		return fmt.Errorf("最短密码长度需在 8–64 之间")
	case v.UsernameCooldownDays < 0 || v.UsernameCooldownDays > 365:
		return fmt.Errorf("改名冷却天数需在 0–365 之间")
	case v.UsernameReserveDays < 0 || v.UsernameReserveDays > 365:
		return fmt.Errorf("旧用户名保留天数需在 0–365 之间")
	case v.SessionIdleDays < 1 || v.SessionIdleDays > 90:
		return fmt.Errorf("会话空闲天数需在 1–90 之间")
	case v.AccessTokenMinutes < 1 || v.AccessTokenMinutes > 60:
		return fmt.Errorf("访问令牌（Access Token）有效期需在 1–60 分钟之间")
	case v.RefreshIdleDays < 1 || v.RefreshIdleDays > v.RefreshAbsoluteDays:
		return fmt.Errorf("刷新令牌空闲天数需在 1 到绝对天数之间")
	case v.RefreshAbsoluteDays < 1 || v.RefreshAbsoluteDays > 365:
		return fmt.Errorf("刷新令牌绝对天数需在 1–365 之间")
	case v.MaxClientsPerDeveloper < 0 || v.MaxClientsPerDeveloper > 1000:
		return fmt.Errorf("每位开发者应用上限需在 0–1000 之间")
	}
	return nil
}

func (v Values) AccessTTL() time.Duration { return time.Duration(v.AccessTokenMinutes) * time.Minute }
func (v Values) RefreshIdleTTL() time.Duration {
	return time.Duration(v.RefreshIdleDays) * 24 * time.Hour
}
func (v Values) RefreshAbsTTL() time.Duration {
	return time.Duration(v.RefreshAbsoluteDays) * 24 * time.Hour
}
func (v Values) SessionIdleTTL() time.Duration {
	return time.Duration(v.SessionIdleDays) * 24 * time.Hour
}

type Service struct {
	db  *db.DB
	cur atomic.Pointer[Values]
	log *slog.Logger
}

func New(ctx context.Context, d *db.DB, log *slog.Logger) (*Service, error) {
	s := &Service{db: d, log: log}
	if err := s.Reload(ctx); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Service) Get() Values { return *s.cur.Load() }

// Reload reads the whole settings table; unknown keys are ignored and missing
// keys keep their defaults.
func (s *Service) Reload(ctx context.Context) error {
	raw, err := store.LoadSettingsRaw(ctx, s.db)
	if err != nil {
		return err
	}
	v := Defaults()
	if len(raw) > 0 {
		merged := map[string]json.RawMessage{}
		base, _ := json.Marshal(v)
		_ = json.Unmarshal(base, &merged)
		for k, val := range raw {
			merged[k] = val
		}
		b, _ := json.Marshal(merged)
		if err := json.Unmarshal(b, &v); err != nil {
			return fmt.Errorf("settings: %w", err)
		}
	}
	s.cur.Store(&v)
	return nil
}

// Save validates and persists all values.
func (s *Service) Save(ctx context.Context, v Values) error {
	if err := v.Validate(); err != nil {
		return err
	}
	b, _ := json.Marshal(v)
	var kv map[string]json.RawMessage
	_ = json.Unmarshal(b, &kv)
	now := time.Now().UTC()
	err := s.db.Tx(ctx, 0, func(tx *sql.Tx) error {
		for k, val := range kv {
			if err := store.PutSetting(ctx, tx, k, val, now); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	s.cur.Store(&v)
	return nil
}

// Run reloads periodically until ctx is done.
func (s *Service) Run(ctx context.Context) {
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := s.Reload(ctx); err != nil && ctx.Err() == nil {
				s.log.Warn("settings reload failed", "err", err)
			}
		}
	}
}
