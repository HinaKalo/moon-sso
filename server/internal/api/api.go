// Package api serves the JSON REST API under /api/v1 used by integrated
// applications and the SDKs: the current user's profile (read and write,
// including username, password and avatar), server-side registration and
// the users sync endpoints (changes feed and bulk snapshot).
package api

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/labstack/echo/v5"

	"moon-sso/server/internal/account"
	"moon-sso/server/internal/auth"
	"moon-sso/server/internal/avatar"
	"moon-sso/server/internal/crypto"
	"moon-sso/server/internal/db"
	"moon-sso/server/internal/feed"
	"moon-sso/server/internal/httpx"
	"moon-sso/server/internal/oidc"
	"moon-sso/server/internal/settings"
	"moon-sso/server/internal/store"
)

type Handler struct {
	DB       *db.DB
	OIDC     *oidc.Provider
	Accounts *account.Service
	Avatars  *avatar.Store
	Feed     *feed.Feed
	Settings *settings.Service
	Sessions *auth.Sessions
	Log      *slog.Logger

	regLimiter *auth.Limiter
}

func New(h *Handler) *Handler {
	h.regLimiter = auth.NewLimiter(0.5, 5) // same budget as the web registration form
	return h
}

func (h *Handler) GC() { h.regLimiter.GC() }

// RelaxLimits removes rate limits (testbed only).
func (h *Handler) RelaxLimits() { h.regLimiter = auth.NewLimiter(1e6, 1_000_000) }

type apiError struct {
	Error       string `json:"error"`
	Description string `json:"error_description"`
	Field       string `json:"field,omitempty"`
}

func fail(c *echo.Context, status int, code, desc string) error {
	return c.JSON(status, apiError{Error: code, Description: desc})
}

// deny writes an error and returns httpx.ErrResponded so the caller stops.
func deny(c *echo.Context, status int, code, desc string) error {
	if err := fail(c, status, code, desc); err != nil {
		return err
	}
	return httpx.ErrResponded
}

// mapErr turns service errors into JSON responses.
func (h *Handler) mapErr(c *echo.Context, err error) error {
	var fe *account.FieldError
	switch {
	case errors.As(err, &fe):
		return c.JSON(http.StatusUnprocessableEntity, apiError{Error: "validation_failed", Description: fe.Msg, Field: fe.Field})
	case errors.Is(err, account.ErrRegistrationClosed):
		return fail(c, http.StatusForbidden, "registration_closed", "暂未开放注册")
	case errors.Is(err, crypto.ErrHasherBusy):
		c.Response().Header().Set("Retry-After", "3")
		return fail(c, http.StatusServiceUnavailable, "temporarily_unavailable", "服务器繁忙，请稍后再试")
	case errors.Is(err, avatar.ErrTooLarge):
		return fail(c, http.StatusRequestEntityTooLarge, "avatar_too_large", err.Error())
	case errors.Is(err, avatar.ErrUnsupported), errors.Is(err, avatar.ErrDimensions):
		return fail(c, http.StatusUnprocessableEntity, "avatar_invalid", err.Error())
	case errors.Is(err, store.ErrNotFound):
		return fail(c, http.StatusNotFound, "not_found", "资源不存在")
	}
	return err
}

// ---- authentication helpers ----

func (h *Handler) userToken(c *echo.Context, needScope string) (*oidc.Authenticated, error) {
	a, err := h.OIDC.Authenticate(c)
	if err != nil {
		return nil, err
	}
	h.OIDC.CORS(c, a.Client)
	if a.User == nil {
		return nil, deny(c, http.StatusForbidden, "insufficient_scope", "需要用户授权的令牌")
	}
	if needScope != "" {
		if !a.Claims.HasScope(needScope) || !slices.Contains(a.Claims.Aud, h.OIDC.APIAudience()) {
			c.Response().Header().Set("WWW-Authenticate", `Bearer error="insufficient_scope", scope="`+needScope+`"`)
			return nil, deny(c, http.StatusForbidden, "insufficient_scope", "令牌缺少 scope: "+needScope)
		}
	}
	return a, nil
}

func (h *Handler) clientToken(c *echo.Context, needScope string) (*oidc.Authenticated, error) {
	a, err := h.OIDC.Authenticate(c)
	if err != nil {
		return nil, err
	}
	if a.User != nil || !a.Claims.HasScope(needScope) {
		return nil, deny(c, http.StatusForbidden, "insufficient_scope", "需要 client_credentials 令牌且包含 scope: "+needScope)
	}
	return a, nil
}

func (h *Handler) actor(c *echo.Context, a *oidc.Authenticated) account.Actor {
	act := account.UserActor(a.User.ID, c.RealIP())
	act.ClientID = a.Client.ID
	return act
}

// profile renders the user as the client sees it (client-specific sub).
func (h *Handler) profile(a *oidc.Authenticated, u *store.User) map[string]any {
	m := h.OIDC.ProfileClaims(u)
	m["sub"] = a.Claims.Sub
	if _, ok := m["picture"]; !ok {
		m["picture"] = nil
	}
	m["totp_enabled"] = u.HasTOTP()
	return m
}

// ---- /me ----

func (h *Handler) GetMe(c *echo.Context) error {
	a, err := h.userToken(c, "")
	if err != nil {
		return err
	}
	if !a.Claims.HasScope(oidc.ScopeProfile) && !slices.Contains(a.Claims.Aud, h.OIDC.APIAudience()) {
		return fail(c, http.StatusForbidden, "insufficient_scope", "需要 profile scope")
	}
	c.Response().Header().Set("Cache-Control", "no-store")
	c.Response().Header().Set("ETag", `"pv-`+strconv.FormatUint(a.User.ProfileVersion, 10)+`"`)
	if c.Request().Header.Get("If-None-Match") == `"pv-`+strconv.FormatUint(a.User.ProfileVersion, 10)+`"` {
		return c.NoContent(http.StatusNotModified)
	}
	return c.JSON(http.StatusOK, h.profile(a, a.User))
}

type patchMe struct {
	Username    *string `json:"username"`
	DisplayName *string `json:"display_name"`
	Nickname    *string `json:"nickname"`
}

// PatchMe updates username and/or nickname. An If-Match header with the
// current profile version provides optimistic concurrency.
func (h *Handler) PatchMe(c *echo.Context) error {
	a, err := h.userToken(c, oidc.ScopeProfileWrite)
	if err != nil {
		return err
	}
	var in patchMe
	if err := json.NewDecoder(io.LimitReader(c.Request().Body, 16<<10)).Decode(&in); err != nil {
		return fail(c, http.StatusBadRequest, "invalid_request", "请求体必须是 JSON")
	}
	if in.DisplayName == nil {
		in.DisplayName = in.Nickname
	}
	if m := c.Request().Header.Get("If-Match"); m != "" {
		if m != `"pv-`+strconv.FormatUint(a.User.ProfileVersion, 10)+`"` {
			return fail(c, http.StatusPreconditionFailed, "version_conflict", "资料已被其他应用修改，请刷新后重试")
		}
	}
	u, err := h.Accounts.UpdateProfile(c.Request().Context(), h.actor(c, a), a.User.ID, account.ProfileUpdate{Username: in.Username, DisplayName: in.DisplayName})
	if err != nil {
		return h.mapErr(c, err)
	}
	c.Response().Header().Set("ETag", `"pv-`+strconv.FormatUint(u.ProfileVersion, 10)+`"`)
	return c.JSON(http.StatusOK, h.profile(a, u))
}

// PutAvatar accepts multipart (field "avatar") or a raw image body.
func (h *Handler) PutAvatar(c *echo.Context) error {
	a, err := h.userToken(c, oidc.ScopeProfileWrite)
	if err != nil {
		return err
	}
	var r io.Reader = c.Request().Body
	if strings.HasPrefix(c.Request().Header.Get("Content-Type"), "multipart/form-data") {
		fh, err := c.FormFile("avatar")
		if err != nil {
			return fail(c, http.StatusBadRequest, "invalid_request", "缺少 avatar 文件")
		}
		f, err := fh.Open()
		if err != nil {
			return err
		}
		defer f.Close()
		r = f
	}
	key, err := h.Avatars.Save(r)
	if err != nil {
		return h.mapErr(c, err)
	}
	u, err := h.Accounts.UpdateProfile(c.Request().Context(), h.actor(c, a), a.User.ID, account.ProfileUpdate{AvatarKey: &key})
	if err != nil {
		return h.mapErr(c, err)
	}
	return c.JSON(http.StatusOK, h.profile(a, u))
}

func (h *Handler) DeleteAvatar(c *echo.Context) error {
	a, err := h.userToken(c, oidc.ScopeProfileWrite)
	if err != nil {
		return err
	}
	empty := ""
	u, err := h.Accounts.UpdateProfile(c.Request().Context(), h.actor(c, a), a.User.ID, account.ProfileUpdate{AvatarKey: &empty})
	if err != nil {
		return h.mapErr(c, err)
	}
	return c.JSON(http.StatusOK, h.profile(a, u))
}

type passwordChange struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
	// KeepThisDevice keeps the session this token belongs to (default true).
	KeepThisDevice *bool `json:"keep_this_device"`
}

func (h *Handler) ChangePassword(c *echo.Context) error {
	a, err := h.userToken(c, oidc.ScopePasswordWrite)
	if err != nil {
		return err
	}
	var in passwordChange
	if err := json.NewDecoder(io.LimitReader(c.Request().Body, 8<<10)).Decode(&in); err != nil {
		return fail(c, http.StatusBadRequest, "invalid_request", "请求体必须是 JSON")
	}
	keep := a.Claims.SID
	if in.KeepThisDevice != nil && !*in.KeepThisDevice {
		keep = ""
	}
	if err := h.Accounts.ChangePassword(c.Request().Context(), h.actor(c, a), a.User.ID, in.CurrentPassword, in.NewPassword, keep); err != nil {
		return h.mapErr(c, err)
	}
	h.Sessions.ForgetUser(a.User.ID)
	return c.JSON(http.StatusOK, map[string]any{"changed": true, "other_sessions_revoked": true})
}

// ---- registration from an application's own server or app ----

type registerReq struct {
	Username    string `json:"username"`
	Password    string `json:"password"`
	DisplayName string `json:"display_name"`
}

// Register lets an authenticated client create an account on behalf of a
// visitor ("declare they want to use the SSO user system"). It is governed by
// the global registration switch and the client's own allow_registration.
// The new user then signs in through the normal authorization flow.
func (h *Handler) Register(c *echo.Context) error {
	cl, e := h.OIDC.AuthenticateClient(c)
	if e != nil {
		return c.JSON(e.Status, apiError{Error: e.Code, Description: e.Description})
	}
	h.OIDC.CORS(c, cl)
	if ok, _ := h.regLimiter.Allow(auth.IPKey(c.RealIP())); !ok {
		return fail(c, http.StatusTooManyRequests, "rate_limited", "注册过于频繁，请稍后再试")
	}
	if !cl.AllowRegistration {
		return fail(c, http.StatusForbidden, "registration_closed", "该应用不允许注册新用户")
	}
	var in registerReq
	if strings.HasPrefix(c.Request().Header.Get("Content-Type"), "application/json") {
		if err := json.NewDecoder(io.LimitReader(c.Request().Body, 8<<10)).Decode(&in); err != nil {
			return fail(c, http.StatusBadRequest, "invalid_request", "请求体格式错误")
		}
	} else {
		in = registerReq{Username: c.FormValue("username"), Password: c.FormValue("password"), DisplayName: c.FormValue("display_name")}
	}
	u, err := h.Accounts.Register(c.Request().Context(), account.RegisterInput{
		Username: in.Username, Password: in.Password, DisplayName: in.DisplayName, Via: "api:" + cl.ID,
		Actor: account.Actor{ClientID: cl.ID, IP: c.RealIP()},
	})
	if err != nil {
		return h.mapErr(c, err)
	}
	return c.JSON(http.StatusCreated, map[string]any{
		"created": true, "username": u.Username,
		"login_hint": u.Username, "authorization_endpoint": h.OIDC.Issuer() + "/oauth/authorize",
	})
}

// RegistrationInfo tells SDKs whether self-service registration is available.
func (h *Handler) RegistrationInfo(c *echo.Context) error {
	s := h.Settings.Get()
	return c.JSON(http.StatusOK, map[string]any{
		"registration_open": s.RegistrationOpen, "password_min_length": s.PasswordMinLength,
		"username_pattern":    "^[A-Za-z0-9][A-Za-z0-9_.-]{1,30}[A-Za-z0-9]$",
		"client_registration": s.ClientRegistration,
	})
}

// ---- users sync (client_credentials, scope users:sync) ----

// Changes returns events for users who granted this client, after cursor.
func (h *Handler) Changes(c *echo.Context) error {
	a, err := h.clientToken(c, oidc.ScopeUsersSync)
	if err != nil {
		return err
	}
	ctx := c.Request().Context()
	cursor, _ := strconv.ParseUint(c.QueryParam("cursor"), 10, 64)
	limit, _ := strconv.Atoi(c.QueryParam("limit"))
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	if cursor > 0 && cursor < h.Feed.PurgedSeq(ctx) {
		return c.JSON(http.StatusGone, apiError{Error: "cursor_expired", Description: "游标早于保留期，请调用 GET /api/v1/users 全量同步后从返回的 watermark 继续"})
	}
	evs, next, more, err := h.Feed.Page(ctx, a.Client, cursor, limit)
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, map[string]any{"events": evs, "next_cursor": strconv.FormatUint(next, 10), "has_more": more})
}

// Users pages through current snapshots of all users who granted this client.
func (h *Handler) Users(c *echo.Context) error {
	a, err := h.clientToken(c, oidc.ScopeUsersSync)
	if err != nil {
		return err
	}
	ctx := c.Request().Context()
	limit, _ := strconv.Atoi(c.QueryParam("limit"))
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	after := make([]byte, 16)
	if cur := c.QueryParam("cursor"); cur != "" {
		b, err := hex.DecodeString(cur)
		if err != nil || len(b) != 16 {
			return fail(c, http.StatusBadRequest, "invalid_request", "cursor 无效")
		}
		after = b
	}
	watermark := h.Feed.LatestSeq(ctx, a.Client.ID)
	rows, err := h.DB.QueryContext(ctx, `SELECT g.user_id, g.sub FROM grants g
		WHERE g.client_id=? AND g.revoked_at IS NULL AND g.user_id > ? ORDER BY g.user_id LIMIT ?`, a.Client.ID, after, limit+1)
	if err != nil {
		return err
	}
	type item struct {
		id  uuid.UUID
		sub string
	}
	var items []item
	for rows.Next() {
		var it item
		if err := rows.Scan(&it.id, &it.sub); err != nil {
			rows.Close()
			return err
		}
		items = append(items, it)
	}
	rows.Close()
	more := len(items) > limit
	if more {
		items = items[:limit]
	}
	users := make([]map[string]any, 0, len(items))
	for _, it := range items {
		u, err := store.GetUser(ctx, h.DB, it.id)
		if err != nil {
			continue
		}
		m := h.OIDC.ProfileClaims(u)
		m["sub"] = it.sub
		m["status"] = map[bool]string{true: "active", false: "disabled"}[u.IsActive()]
		users = append(users, m)
	}
	out := map[string]any{"users": users, "has_more": more, "watermark": strconv.FormatUint(watermark, 10)}
	if more {
		out["next_cursor"] = hex.EncodeToString(items[len(items)-1].id[:])
	}
	return c.JSON(http.StatusOK, out)
}

// User returns one granted user's snapshot by client-specific sub.
func (h *Handler) User(c *echo.Context) error {
	a, err := h.clientToken(c, oidc.ScopeUsersSync)
	if err != nil {
		return err
	}
	ctx := c.Request().Context()
	uid, err := h.OIDC.UserIDForSubject(ctx, a.Client.ID, c.Param("sub"))
	if err != nil {
		return fail(c, http.StatusNotFound, "not_found", "用户不存在或未授权该应用")
	}
	u, err := store.GetUser(ctx, h.DB, uid)
	if err != nil {
		return h.mapErr(c, err)
	}
	m := h.OIDC.ProfileClaims(u)
	m["sub"] = c.Param("sub")
	m["status"] = map[bool]string{true: "active", false: "disabled"}[u.IsActive()]
	return c.JSON(http.StatusOK, m)
}
