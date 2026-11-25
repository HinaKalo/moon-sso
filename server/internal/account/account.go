// Package account is the single write path for user data. Every change to a
// user goes through Service so that profile_version, outbox events and the
// audit log stay consistent with the row itself.
package account

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"

	"moon-sso/server/internal/auth"
	"moon-sso/server/internal/crypto"
	"moon-sso/server/internal/db"
	"moon-sso/server/internal/settings"
	"moon-sso/server/internal/store"
)

var (
	ErrRegistrationClosed = errors.New("registration closed")
	ErrUsernameTaken      = &FieldError{Field: "username", Msg: "该用户名已被占用"}
	ErrBadCredentials     = errors.New("用户名或密码错误")
	ErrDisabled           = errors.New("该账号已被停用，请联系管理员")
	ErrBadTOTP            = &FieldError{Field: "code", Msg: "验证码不正确或已使用过"}
	ErrWrongPassword      = &FieldError{Field: "current_password", Msg: "当前密码不正确"}
	ErrUsernameCooldown   = &FieldError{Field: "username", Msg: "用户名修改过于频繁，请稍后再试"}
	ErrTooManyAttempts    = &FieldError{Field: "current_password", Msg: "密码错误次数过多，请稍后再试"}
)

// Event types published to integrated applications.
const (
	EventUserUpdated         = "user.updated"
	EventUserPasswordChanged = "user.password_changed"
	EventUserDisabled        = "user.disabled"
	EventUserEnabled         = "user.enabled"
	EventUserDeleted         = "user.deleted"
	EventConsentRevoked      = "consent.revoked"
	EventSessionRevoked      = "session.revoked"
)

// Actor identifies who performed an action, for auditing.
type Actor struct {
	UserID   *uuid.UUID
	ClientID string
	IP       string
	// Admin marks actions by a console administrator (AdminName) or the CLI.
	Admin     bool
	AdminName string
}

func UserActor(id uuid.UUID, ip string) Actor { return Actor{UserID: &id, IP: ip} }

// Hooks lets other subsystems react after a commit without import cycles.
type Hooks struct {
	// UserChanged is called after any committed change to a user (cache invalidation).
	UserChanged func(userID uuid.UUID)
	// RevokeUserTokens revokes sessions/refresh families of a user inside tx,
	// except the session keepSID. Implemented by the oidc package.
	RevokeUserTokens func(ctx context.Context, tx *sql.Tx, userID uuid.UUID, keepSID string, reason string) error
	// EventsWritten wakes the sequencer.
	EventsWritten func()
}

type Service struct {
	// Throttle slows repeated wrong current-password guesses per user.
	Throttle *auth.Throttle
	DB       *db.DB
	Hasher   *crypto.Hasher
	Settings *settings.Service
	AtRest   *crypto.Sealer
	Hooks    Hooks
	Log      *slog.Logger
	Now      func() time.Time
}

func (s *Service) now() time.Time { return s.Now().UTC() }

func (s *Service) audit(ctx context.Context, q db.Querier, a Actor, action, targetType, targetID string, meta map[string]any) error {
	return store.InsertAudit(ctx, q, &store.AuditEntry{
		At: s.now(), ActorUserID: a.UserID, ActorClientID: a.ClientID, ActorAdmin: a.AdminName, Action: action,
		TargetType: targetType, TargetID: targetID, IP: a.IP, Meta: meta,
	})
}

// Snapshot is the internal representation of a user carried in outbox events.
// It is rendered per recipient (pairwise sub, absolute picture URL) on delivery.
type Snapshot struct {
	UserID         uuid.UUID `json:"user_id"`
	PublicSub      string    `json:"public_sub"`
	Username       string    `json:"username"`
	DisplayName    string    `json:"display_name"`
	AvatarKey      string    `json:"avatar_key"`
	Status         int       `json:"status"`
	ProfileVersion uint64    `json:"profile_version"`
	UpdatedAt      time.Time `json:"updated_at"`
	Deleted        bool      `json:"deleted,omitempty"`
	Changed        []string  `json:"changed,omitempty"`
	SID            string    `json:"sid,omitempty"`
}

func SnapshotOf(u *store.User, changed []string) Snapshot {
	return Snapshot{UserID: u.ID, PublicSub: u.PublicSub, Username: u.Username, DisplayName: u.DisplayName,
		AvatarKey: u.AvatarKey, Status: u.Status, ProfileVersion: u.ProfileVersion, UpdatedAt: u.UpdatedAt, Changed: changed}
}

// emit writes an outbox event addressed to every client holding a grant.
func (s *Service) emit(ctx context.Context, tx *sql.Tx, typ string, u *store.User, changed []string) error {
	recipients, err := store.ActiveGrantClients(ctx, tx, u.ID)
	if err != nil {
		return err
	}
	return store.InsertEvent(ctx, tx, typ, &u.ID, SnapshotOf(u, changed), recipients, s.now())
}

func (s *Service) afterCommit(userID uuid.UUID, events bool) {
	if s.Hooks.UserChanged != nil {
		s.Hooks.UserChanged(userID)
	}
	if events && s.Hooks.EventsWritten != nil {
		s.Hooks.EventsWritten()
	}
}

// ---- registration ----

type RegisterInput struct {
	Username    string
	Password    string
	DisplayName string
	Via         string // "web", "api:<client>", "native:<client>", "admin"
	Actor       Actor
	// Force skips the registration_open check (admin-created accounts).
	Force              bool
	Roles              uint32
	MustChangePassword bool
}

func (s *Service) Register(ctx context.Context, in RegisterInput) (*store.User, error) {
	set := s.Settings.Get()
	if !in.Force && !set.RegistrationOpen {
		return nil, ErrRegistrationClosed
	}
	in.Username = strings.TrimSpace(in.Username)
	if err := ValidateUsername(in.Username); err != nil {
		return nil, err
	}
	if err := ValidatePassword(in.Password, in.Username, set.PasswordMinLength); err != nil {
		return nil, err
	}
	display, err := CleanDisplayName(in.DisplayName)
	if err != nil {
		return nil, err
	}
	// Hash before opening the transaction so no DB connection is held during argon2.
	hash, err := s.Hasher.Hash(ctx, in.Password)
	if err != nil {
		return nil, err
	}
	id, err := uuid.NewV7()
	if err != nil {
		return nil, err
	}
	now := s.now()
	u := &store.User{
		ID: id, PublicSub: crypto.RandomToken(16), Username: in.Username, UsernameNorm: NormalizeUsername(in.Username),
		DisplayName: display, PasswordHash: hash, PasswordChangedAt: now, MustChangePassword: in.MustChangePassword,
		Status: store.UserActive, Roles: in.Roles, ProfileVersion: 1, RegisteredVia: in.Via, CreatedAt: now, UpdatedAt: now,
	}
	err = s.DB.Tx(ctx, sql.LevelReadCommitted, func(tx *sql.Tx) error {
		reserved, err := store.UsernameReserved(ctx, tx, u.UsernameNorm, u.ID, now)
		if err != nil {
			return err
		}
		if reserved {
			return ErrUsernameTaken
		}
		if err := store.InsertUser(ctx, tx, u); err != nil {
			if db.IsDuplicate(err) {
				return ErrUsernameTaken
			}
			return err
		}
		return s.audit(ctx, tx, in.Actor, "user.register", "user", u.PublicSub, map[string]any{"via": in.Via, "username": u.Username})
	})
	if err != nil {
		return nil, err
	}
	s.log().Info("user registered", "sub", u.PublicSub, "via", in.Via)
	return u, nil
}

func (s *Service) log() *slog.Logger { return s.Log }

// ---- authentication ----

// Authenticate verifies username and password. It always performs one
// argon2 verification so response time does not reveal whether a user exists.
func (s *Service) Authenticate(ctx context.Context, username, password string) (*store.User, error) {
	norm := NormalizeUsername(username)
	u, err := store.GetUserByUsername(ctx, s.DB, norm)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	encoded := ""
	if u != nil {
		encoded = u.PasswordHash
	}
	if len(password) > 128 {
		password = password[:128]
	}
	ok, rehash, err := s.Hasher.Verify(ctx, password, encoded)
	if err != nil {
		return nil, err
	}
	if !ok || u == nil {
		return nil, ErrBadCredentials
	}
	if !u.IsActive() {
		return nil, ErrDisabled
	}
	if rehash {
		if h, err := s.Hasher.Hash(ctx, password); err == nil {
			_ = store.SetPasswordHash(ctx, s.DB, u.ID, h)
		}
	}
	return u, nil
}

func (s *Service) totpAAD(id uuid.UUID) []byte { return append([]byte("totp:"), id[:]...) }

// VerifyTOTP checks a code for a user with TOTP enabled and burns the step.
func (s *Service) VerifyTOTP(ctx context.Context, u *store.User, code string) error {
	if !u.HasTOTP() {
		return ErrBadTOTP
	}
	secret, err := s.AtRest.Open(u.TOTPSecretEnc, s.totpAAD(u.ID))
	if err != nil {
		return err
	}
	step, ok := crypto.VerifyTOTP(string(secret), code, s.now(), u.TOTPLastStep)
	if !ok {
		return ErrBadTOTP
	}
	advanced, err := store.SetTOTPLastStep(ctx, s.DB, u.ID, step)
	if err != nil {
		return err
	}
	if !advanced {
		return ErrBadTOTP // concurrent use of the same code
	}
	u.TOTPLastStep = step
	return nil
}

// EnableTOTP stores secret after the user proved possession with code.
func (s *Service) EnableTOTP(ctx context.Context, a Actor, userID uuid.UUID, secret, code string) error {
	step, ok := crypto.VerifyTOTP(secret, code, s.now(), 0)
	if !ok {
		return ErrBadTOTP
	}
	err := s.DB.Tx(ctx, sql.LevelReadCommitted, func(tx *sql.Tx) error {
		u, err := store.GetUserForUpdate(ctx, tx, userID)
		if err != nil {
			return err
		}
		u.TOTPSecretEnc = s.AtRest.Seal([]byte(secret), s.totpAAD(u.ID))
		u.TOTPLastStep = step
		u.UpdatedAt = s.now()
		if err := store.UpdateUser(ctx, tx, u); err != nil {
			return err
		}
		return s.audit(ctx, tx, a, "user.totp_enabled", "user", u.PublicSub, nil)
	})
	if err == nil {
		s.afterCommit(userID, false)
	}
	return err
}

// DisableTOTP removes the second factor after re-checking the password.
func (s *Service) DisableTOTP(ctx context.Context, a Actor, userID uuid.UUID, password string) error {
	u, err := store.GetUser(ctx, s.DB, userID)
	if err != nil {
		return err
	}
	if !a.Admin {
		if err := s.checkPassword(ctx, u, password); err != nil {
			return err
		}
	}
	err = s.DB.Tx(ctx, sql.LevelReadCommitted, func(tx *sql.Tx) error {
		u, err := store.GetUserForUpdate(ctx, tx, userID)
		if err != nil {
			return err
		}
		u.TOTPSecretEnc = nil
		u.TOTPLastStep = 0
		u.UpdatedAt = s.now()
		if err := store.UpdateUser(ctx, tx, u); err != nil {
			return err
		}
		return s.audit(ctx, tx, a, "user.totp_disabled", "user", u.PublicSub, nil)
	})
	if err == nil {
		s.afterCommit(userID, false)
	}
	return err
}

// ---- profile ----

type ProfileUpdate struct {
	DisplayName *string
	Username    *string
	AvatarKey   *string // "" removes the avatar
}

// UpdateProfile applies changes, bumps profile_version and notifies every
// application that holds a grant for the user.
func (s *Service) UpdateProfile(ctx context.Context, a Actor, userID uuid.UUID, p ProfileUpdate) (*store.User, error) {
	set := s.Settings.Get()
	var newDisplay string
	if p.DisplayName != nil {
		d, err := CleanDisplayName(*p.DisplayName)
		if err != nil {
			return nil, err
		}
		newDisplay = d
	}
	if p.Username != nil {
		*p.Username = strings.TrimSpace(*p.Username)
		if err := ValidateUsername(*p.Username); err != nil {
			return nil, err
		}
	}
	var result *store.User
	var changed []string
	err := s.DB.Tx(ctx, sql.LevelReadCommitted, func(tx *sql.Tx) error {
		changed = changed[:0]
		u, err := store.GetUserForUpdate(ctx, tx, userID)
		if err != nil {
			return err
		}
		now := s.now()
		if p.DisplayName != nil && newDisplay != u.DisplayName {
			u.DisplayName = newDisplay
			changed = append(changed, "display_name")
		}
		if p.AvatarKey != nil && *p.AvatarKey != u.AvatarKey {
			u.AvatarKey = *p.AvatarKey
			changed = append(changed, "picture")
		}
		if p.Username != nil && *p.Username != u.Username {
			norm := NormalizeUsername(*p.Username)
			if norm != u.UsernameNorm {
				if !a.Admin && u.UsernameChangedAt != nil && set.UsernameCooldownDays > 0 &&
					now.Before(u.UsernameChangedAt.Add(time.Duration(set.UsernameCooldownDays)*24*time.Hour)) {
					return ErrUsernameCooldown
				}
				reserved, err := store.UsernameReserved(ctx, tx, norm, u.ID, now)
				if err != nil {
					return err
				}
				if reserved {
					return ErrUsernameTaken
				}
				if set.UsernameReserveDays > 0 {
					if err := store.ReserveUsername(ctx, tx, u.UsernameNorm, u.ID, now.Add(time.Duration(set.UsernameReserveDays)*24*time.Hour)); err != nil {
						return err
					}
				}
				// Reclaiming one's own reserved name frees the reservation.
				if err := store.ReleaseUsernameReservation(ctx, tx, norm); err != nil {
					return err
				}
				t := now
				u.UsernameChangedAt = &t
			}
			u.Username = *p.Username
			u.UsernameNorm = norm
			changed = append(changed, "username")
		}
		if len(changed) == 0 {
			result = u
			return nil
		}
		u.ProfileVersion++
		u.UpdatedAt = now
		if err := store.UpdateUser(ctx, tx, u); err != nil {
			if db.IsDuplicate(err) {
				return ErrUsernameTaken
			}
			return err
		}
		if err := s.emit(ctx, tx, EventUserUpdated, u, changed); err != nil {
			return err
		}
		if err := s.audit(ctx, tx, a, "user.profile_updated", "user", u.PublicSub, map[string]any{"changed": changed}); err != nil {
			return err
		}
		result = u
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(changed) > 0 {
		s.afterCommit(userID, true)
	}
	return result, nil
}

// ChangePassword verifies the current password (unless an admin resets it),
// stores the new hash and revokes the user's other sessions and tokens.
func (s *Service) ChangePassword(ctx context.Context, a Actor, userID uuid.UUID, current, next, keepSID string) error {
	u, err := store.GetUser(ctx, s.DB, userID)
	if err != nil {
		return err
	}
	if err := s.checkPassword(ctx, u, current); err != nil {
		return err
	}
	if err := ValidatePassword(next, u.Username, s.Settings.Get().PasswordMinLength); err != nil {
		return err
	}
	if next == current {
		return fieldErr("password", "新密码不能与当前密码相同")
	}
	hash, err := s.Hasher.Hash(ctx, next)
	if err != nil {
		return err
	}
	return s.setPassword(ctx, a, userID, hash, false, keepSID, "user.password_changed")
}

// checkPassword verifies the current password with a per-user throttle so
// that apps holding password:write cannot brute-force it.
func (s *Service) checkPassword(ctx context.Context, u *store.User, pw string) error {
	key := "pw:" + u.ID.String()
	if s.Throttle != nil && s.Throttle.Delay(key) > 0 {
		return ErrTooManyAttempts
	}
	ok, _, err := s.Hasher.Verify(ctx, pw, u.PasswordHash)
	if err != nil {
		return err
	}
	if !ok {
		if s.Throttle != nil {
			s.Throttle.Fail(key)
		}
		return ErrWrongPassword
	}
	if s.Throttle != nil {
		s.Throttle.Success(key)
	}
	return nil
}

// AdminResetPassword sets a temporary password the user must change at next login.
func (s *Service) AdminResetPassword(ctx context.Context, a Actor, userID uuid.UUID) (string, error) {
	temp := crypto.RandomToken(12)
	hash, err := s.Hasher.Hash(ctx, temp)
	if err != nil {
		return "", err
	}
	if err := s.setPassword(ctx, a, userID, hash, true, "", "admin.password_reset"); err != nil {
		return "", err
	}
	return temp, nil
}

func (s *Service) setPassword(ctx context.Context, a Actor, userID uuid.UUID, hash string, mustChange bool, keepSID, action string) error {
	err := s.DB.Tx(ctx, sql.LevelReadCommitted, func(tx *sql.Tx) error {
		u, err := store.GetUserForUpdate(ctx, tx, userID)
		if err != nil {
			return err
		}
		now := s.now()
		u.PasswordHash = hash
		u.PasswordChangedAt = now
		u.MustChangePassword = mustChange
		u.ProfileVersion++
		u.UpdatedAt = now
		if err := store.UpdateUser(ctx, tx, u); err != nil {
			return err
		}
		if s.Hooks.RevokeUserTokens != nil {
			if err := s.Hooks.RevokeUserTokens(ctx, tx, userID, keepSID, "password_changed"); err != nil {
				return err
			}
		}
		if mustChange {
			// An administrator reset implies the account may be compromised:
			// developer API tokens stop working too.
			if _, err := store.RevokeOwnerAPITokens(ctx, tx, store.TokenDeveloper, userID, "password_reset", now); err != nil {
				return err
			}
		}
		if err := s.emit(ctx, tx, EventUserPasswordChanged, u, []string{"password"}); err != nil {
			return err
		}
		return s.audit(ctx, tx, a, action, "user", u.PublicSub, nil)
	})
	if err == nil {
		s.afterCommit(userID, true)
	}
	return err
}

// ---- administration ----

func (s *Service) SetStatus(ctx context.Context, a Actor, userID uuid.UUID, status int) error {
	err := s.DB.Tx(ctx, sql.LevelReadCommitted, func(tx *sql.Tx) error {
		u, err := store.GetUserForUpdate(ctx, tx, userID)
		if err != nil {
			return err
		}
		if u.Status == status {
			return nil
		}
		u.Status = status
		u.ProfileVersion++
		u.UpdatedAt = s.now()
		if err := store.UpdateUser(ctx, tx, u); err != nil {
			return err
		}
		typ, action := EventUserEnabled, "admin.user_enabled"
		if status == store.UserDisabled {
			typ, action = EventUserDisabled, "admin.user_disabled"
			if s.Hooks.RevokeUserTokens != nil {
				if err := s.Hooks.RevokeUserTokens(ctx, tx, userID, "", "user_disabled"); err != nil {
					return err
				}
			}
		}
		if err := s.emit(ctx, tx, typ, u, []string{"status"}); err != nil {
			return err
		}
		return s.audit(ctx, tx, a, action, "user", u.PublicSub, nil)
	})
	if err == nil {
		s.afterCommit(userID, true)
	}
	return err
}

func (s *Service) SetRoles(ctx context.Context, a Actor, userID uuid.UUID, roles uint32) error {
	err := s.DB.Tx(ctx, sql.LevelReadCommitted, func(tx *sql.Tx) error {
		u, err := store.GetUserForUpdate(ctx, tx, userID)
		if err != nil {
			return err
		}
		old := u.Roles
		u.Roles = roles
		u.UpdatedAt = s.now()
		if err := store.UpdateUser(ctx, tx, u); err != nil {
			return err
		}
		return s.audit(ctx, tx, a, "admin.roles_changed", "user", u.PublicSub, map[string]any{"from": old, "to": roles})
	})
	if err == nil {
		s.afterCommit(userID, false)
	}
	return err
}

// Delete removes the user, leaves a tombstone and tells every application.
// Recipients are snapshotted before grants are deleted.
func (s *Service) Delete(ctx context.Context, a Actor, userID uuid.UUID) error {
	err := s.DB.Tx(ctx, sql.LevelReadCommitted, func(tx *sql.Tx) error {
		u, err := store.GetUserForUpdate(ctx, tx, userID)
		if err != nil {
			return err
		}
		if s.Hooks.RevokeUserTokens != nil {
			if err := s.Hooks.RevokeUserTokens(ctx, tx, userID, "", "user_deleted"); err != nil {
				return err
			}
		}
		now := s.now()
		u.ProfileVersion++
		u.UpdatedAt = now
		snap := SnapshotOf(u, nil)
		snap.Deleted = true
		snap.Username, snap.DisplayName, snap.AvatarKey = "", "", ""
		recipients, err := store.ActiveGrantClients(ctx, tx, u.ID)
		if err != nil {
			return err
		}
		if err := store.InsertEvent(ctx, tx, EventUserDeleted, &u.ID, snap, recipients, now); err != nil {
			return err
		}
		if err := store.InsertTombstone(ctx, tx, u.ID, u.PublicSub, now); err != nil {
			return err
		}
		for _, q := range []string{
			"DELETE FROM grants WHERE user_id=?",
			"DELETE FROM username_reservations WHERE user_id=?",
			"DELETE FROM api_tokens WHERE kind=1 AND owner_id=?",
		} {
			if _, err := tx.ExecContext(ctx, q, u.ID[:]); err != nil {
				return err
			}
		}
		if err := store.DeleteUser(ctx, tx, u.ID); err != nil {
			return err
		}
		return s.audit(ctx, tx, a, "admin.user_deleted", "user", u.PublicSub, map[string]any{"username": u.Username})
	})
	if err == nil {
		s.afterCommit(userID, true)
	}
	return err
}
