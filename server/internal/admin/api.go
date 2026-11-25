package admin

import (
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v5"

	"moon-sso/server/internal/account"
	"moon-sso/server/internal/apitoken"
	"moon-sso/server/internal/clients"
	"moon-sso/server/internal/crypto"
	"moon-sso/server/internal/feed"
	"moon-sso/server/internal/portal"
	"moon-sso/server/internal/settings"
	"moon-sso/server/internal/store"
)

// Console API: https://sso-admin…/api/v1/*, authenticated with console API
// tokens (msso_adm_…) issued on the console's "API 令牌" page. Actions are
// audited as the owning administrator, tagged with the token.

func (h *Handler) apiActor(c *echo.Context) account.Actor {
	p := apitoken.PrincipalOf(c)
	return account.Actor{IP: c.RealIP(), Admin: true, AdminName: p.Token.OwnerName, ClientID: p.Tag()}
}

func (h *Handler) apiTokenActor(c *echo.Context) apitoken.Actor {
	p := apitoken.PrincipalOf(c)
	return apitoken.Actor{Admin: p.Token.OwnerName, Via: p.Tag(), IP: c.RealIP()}
}

func (h *Handler) apiAudit(c *echo.Context, action, ttype, tid string, meta map[string]any) {
	p := apitoken.PrincipalOf(c)
	_ = store.InsertAudit(c.Request().Context(), h.DB, &store.AuditEntry{At: time.Now().UTC(), ActorAdmin: p.Token.OwnerName,
		ActorClientID: p.Tag(), Action: action, TargetType: ttype, TargetID: tid, IP: c.RealIP(), Meta: meta})
}

func apiFail(c *echo.Context, status int, code, desc string) error {
	return c.JSON(status, map[string]string{"error": code, "error_description": desc})
}

func decodeBody(c *echo.Context, dst any) error {
	dec := json.NewDecoder(io.LimitReader(c.Request().Body, 64<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil && !errors.Is(err, io.EOF) {
		if f, ok := strings.CutPrefix(err.Error(), "json: unknown field "); ok {
			f = strings.Trim(f, `"`)
			return &account.FieldError{Field: f, Msg: "不支持的字段：" + f}
		}
		return &account.FieldError{Msg: "请求体必须是合法的 JSON 对象"}
	}
	return nil
}

func queryInt(c *echo.Context, k string, def, lo, hi int) int {
	n, err := strconv.Atoi(c.QueryParam(k))
	if err != nil {
		return def
	}
	return min(max(n, lo), hi)
}

func statusName(s int) string {
	switch s {
	case store.UserActive:
		return "active"
	case store.UserDisabled:
		return "disabled"
	}
	return strconv.Itoa(s)
}

// ---- token ----

// APITokenInfo: GET /api/v1/token
func (h *Handler) APITokenInfo(c *echo.Context) error {
	p := apitoken.PrincipalOf(c)
	return c.JSON(http.StatusOK, map[string]any{
		"token": apitoken.ViewOf(p.Token, time.Now()),
		"admin": map[string]any{"username": p.Token.OwnerName},
		"api":   h.Cfg.Server.AdminURL + "/api/v1",
	})
}

// APITokenRotate: POST /api/v1/token/rotate
func (h *Handler) APITokenRotate(c *echo.Context) error {
	grace, err := portal.GraceFrom(c)
	if err != nil {
		return portal.APIError(c, err)
	}
	plain, t, err := h.Tokens.Rotate(c.Request().Context(), apitoken.PrincipalOf(c).Token.ID, grace, h.apiTokenActor(c))
	if err != nil {
		return portal.APIError(c, err)
	}
	return c.JSON(http.StatusCreated, apitoken.IssuedView{View: apitoken.ViewOf(t, time.Now()), Token: plain})
}

// APITokenRevoke: DELETE /api/v1/token
func (h *Handler) APITokenRevoke(c *echo.Context) error {
	if err := h.Tokens.Revoke(c.Request().Context(), apitoken.PrincipalOf(c).Token.ID, "self", h.apiTokenActor(c)); err != nil {
		return portal.APIError(c, err)
	}
	return c.NoContent(http.StatusNoContent)
}

// ---- stats ----

// APIStats: GET /api/v1/stats
func (h *Handler) APIStats(c *echo.Context) error {
	ctx := c.Request().Context()
	now := time.Now().UTC()
	total, disabled, err := store.CountUsers(ctx, h.DB)
	if err != nil {
		return err
	}
	sessions, _ := store.CountActiveSessions(ctx, h.DB, now)
	families, _ := store.CountActiveFamilies(ctx, h.DB, now)
	var clientsTotal, pending, webhookFailing, deadLetters, newUsers, logins24 int
	_ = h.DB.QueryRowContext(ctx, "SELECT COUNT(*), COALESCE(SUM(status=2),0), COALESCE(SUM(webhook_last_error<>'' OR webhook_disabled_at IS NOT NULL),0) FROM clients").Scan(&clientsTotal, &pending, &webhookFailing)
	_ = h.DB.QueryRowContext(ctx, "SELECT COUNT(*) FROM webhook_dead_letters WHERE resolved_at IS NULL").Scan(&deadLetters)
	_ = h.DB.QueryRowContext(ctx, "SELECT COUNT(*) FROM users WHERE created_at > ?", now.Add(-24*time.Hour)).Scan(&newUsers)
	_ = h.DB.QueryRowContext(ctx, "SELECT COUNT(*) FROM audit_log WHERE action='user.login' AND at > ?", now.Add(-24*time.Hour)).Scan(&logins24)
	set := h.Settings.Get()
	return c.JSON(http.StatusOK, map[string]any{
		"users_total": total, "users_disabled": disabled, "users_new_24h": newUsers, "logins_24h": logins24,
		"active_sessions": sessions, "active_refresh_families": families, "clients_total": clientsTotal,
		"clients_pending": pending, "webhooks_failing": webhookFailing, "dead_letters": deadLetters,
		"sse_connections": h.Feed.Connections(), "registration_open": set.RegistrationOpen, "client_registration": set.ClientRegistration,
	})
}

// ---- users ----

func userJSON(u *store.User) map[string]any {
	return map[string]any{
		"sub": u.PublicSub, "username": u.Username, "display_name": u.DisplayName, "status": statusName(u.Status),
		"totp_enabled": u.HasTOTP(), "must_change_password": u.MustChangePassword, "registered_via": u.RegisteredVia,
		"profile_version": u.ProfileVersion, "has_avatar": u.AvatarKey != "", "created_at": u.CreatedAt, "updated_at": u.UpdatedAt,
		"password_changed_at": u.PasswordChangedAt,
	}
}

// APIUsers: GET /api/v1/users?q=&status=active|disabled&page=&per_page=
func (h *Handler) APIUsers(c *echo.Context) error {
	page := queryInt(c, "page", 1, 1, 1_000_000)
	per := queryInt(c, "per_page", 50, 1, 200)
	status := 0
	switch c.QueryParam("status") {
	case "active", "1":
		status = store.UserActive
	case "disabled", "2":
		status = store.UserDisabled
	}
	list, total, err := store.ListUsers(c.Request().Context(), h.DB, store.UserListFilter{
		Query: account.NormalizeUsername(strings.TrimSpace(c.QueryParam("q"))), Status: status, Limit: per, Offset: (page - 1) * per})
	if err != nil {
		return err
	}
	out := make([]map[string]any, 0, len(list))
	for _, u := range list {
		out = append(out, userJSON(u))
	}
	return c.JSON(http.StatusOK, map[string]any{"users": out, "total": total, "page": page, "per_page": per, "has_next": page*per < total})
}

// apiUser resolves :sub, also accepting a username.
func (h *Handler) apiUser(c *echo.Context) (*store.User, error) {
	ctx := c.Request().Context()
	key := c.Param("sub")
	u, err := store.GetUserByPublicSub(ctx, h.DB, key)
	if errors.Is(err, store.ErrNotFound) {
		u, err = store.GetUserByUsername(ctx, h.DB, account.NormalizeUsername(key))
	}
	return u, err
}

// APIUser: GET /api/v1/users/:sub (sub or username)
func (h *Handler) APIUser(c *echo.Context) error {
	ctx := c.Request().Context()
	u, err := h.apiUser(c)
	if err != nil {
		return portal.APIError(c, err)
	}
	out := userJSON(u)
	sessions, err := store.ListActiveSessions(ctx, h.DB, u.ID, time.Now().UTC())
	if err != nil {
		return err
	}
	ss := make([]map[string]any, 0, len(sessions))
	for _, s := range sessions {
		ss = append(ss, map[string]any{"sid": s.SID, "created_at": s.CreatedAt, "last_seen_at": s.LastSeenAt, "ip": s.IP, "user_agent": s.UserAgent, "amr": strings.Fields(s.AMR)})
	}
	grants, err := store.ListUserGrants(ctx, h.DB, u.ID)
	if err != nil {
		return err
	}
	gs := make([]map[string]any, 0, len(grants))
	for _, g := range grants {
		gs = append(gs, map[string]any{"client_id": g.ClientID, "client_name": g.ClientName, "scopes": g.ConsentedScopes, "last_used_at": g.LastUsedAt, "created_at": g.CreatedAt})
	}
	out["sessions"], out["grants"] = ss, gs
	return c.JSON(http.StatusOK, out)
}

type createUserBody struct {
	Username    string `json:"username"`
	DisplayName string `json:"display_name"`
	Password    string `json:"password"`
}

// APICreateUser: POST /api/v1/users
func (h *Handler) APICreateUser(c *echo.Context) error {
	var b createUserBody
	if err := decodeBody(c, &b); err != nil {
		return portal.APIError(c, err)
	}
	temp := b.Password
	generated := temp == ""
	if generated {
		temp = "Tmp-" + crypto.RandomToken(12)
	}
	u, err := h.Accounts.Register(c.Request().Context(), account.RegisterInput{Username: b.Username, Password: temp, DisplayName: b.DisplayName,
		Via: "admin", Force: true, MustChangePassword: true, Actor: h.apiActor(c)})
	if err != nil {
		return portal.APIError(c, err)
	}
	out := userJSON(u)
	if generated {
		out["temporary_password"] = temp
	}
	return c.JSON(http.StatusCreated, out)
}

// APIUserAction: POST /api/v1/users/:sub/:action
// actions: disable, enable, reset-password, disable-totp, revoke-sessions
func (h *Handler) APIUserAction(c *echo.Context) error {
	ctx := c.Request().Context()
	u, err := h.apiUser(c)
	if err != nil {
		return portal.APIError(c, err)
	}
	a := h.apiActor(c)
	extra := map[string]any{}
	switch c.Param("action") {
	case "disable":
		err = h.Accounts.SetStatus(ctx, a, u.ID, store.UserDisabled)
	case "enable":
		err = h.Accounts.SetStatus(ctx, a, u.ID, store.UserActive)
	case "reset-password":
		var temp string
		if temp, err = h.Accounts.AdminResetPassword(ctx, a, u.ID); err == nil {
			extra["temporary_password"] = temp
		}
	case "disable-totp":
		err = h.Accounts.DisableTOTP(ctx, a, u.ID, "")
	case "revoke-sessions":
		err = h.DB.Tx(ctx, sql.LevelReadCommitted, func(tx *sql.Tx) error {
			return h.OIDC.RevokeUserTokens(ctx, tx, u.ID, "", "admin_revoked")
		})
		if err == nil {
			h.Sessions.ForgetUser(u.ID)
			h.OIDC.WakeEvents()
			h.apiAudit(c, "admin.sessions_revoked", "user", u.PublicSub, nil)
		}
	default:
		return apiFail(c, http.StatusNotFound, "not_found", "未知操作："+c.Param("action"))
	}
	if err != nil {
		return portal.APIError(c, err)
	}
	fresh, err := store.GetUser(ctx, h.DB, u.ID)
	if err != nil {
		return portal.APIError(c, err)
	}
	out := userJSON(fresh)
	for k, v := range extra {
		out[k] = v
	}
	return c.JSON(http.StatusOK, out)
}

// APIDeleteUser: DELETE /api/v1/users/:sub?confirm=<username>
func (h *Handler) APIDeleteUser(c *echo.Context) error {
	u, err := h.apiUser(c)
	if err != nil {
		return portal.APIError(c, err)
	}
	if c.QueryParam("confirm") != u.Username {
		return apiFail(c, http.StatusBadRequest, "confirmation_required", "删除用户需要 ?confirm=<用户名> 确认")
	}
	if err := h.Accounts.Delete(c.Request().Context(), h.apiActor(c), u.ID); err != nil {
		return portal.APIError(c, err)
	}
	return c.NoContent(http.StatusNoContent)
}

// ---- clients ----

func (h *Handler) clientOwner(c *echo.Context, cl *store.Client) string {
	if cl.OwnerUserID == nil {
		return ""
	}
	if u, err := store.GetUser(c.Request().Context(), h.DB, *cl.OwnerUserID); err == nil {
		return u.Username
	}
	return ""
}

func clientStatus(s string) int {
	switch s {
	case "active", "1":
		return store.ClientActive
	case "pending", "pending_approval", "2":
		return store.ClientPending
	case "disabled", "3":
		return store.ClientDisabled
	}
	return 0
}

// APIClients: GET /api/v1/clients?q=&status=active|pending|disabled
func (h *Handler) APIClients(c *echo.Context) error {
	list, total, err := store.ListClients(c.Request().Context(), h.DB, store.ClientFilter{Query: c.QueryParam("q"),
		Status: clientStatus(c.QueryParam("status")), Limit: queryInt(c, "limit", 200, 1, 500)})
	if err != nil {
		return err
	}
	out := make([]map[string]any, 0, len(list))
	for _, cl := range list {
		out = append(out, h.Clients.DescribeAdmin(cl, nil, h.clientOwner(c, cl)))
	}
	return c.JSON(http.StatusOK, map[string]any{"clients": out, "total": total})
}

func (h *Handler) apiClient(c *echo.Context) (*store.Client, error) {
	return store.GetClient(c.Request().Context(), h.DB, c.Param("id"))
}

// APIClient: GET /api/v1/clients/:id
func (h *Handler) APIClient(c *echo.Context) error {
	cl, err := h.apiClient(c)
	if err != nil {
		return portal.APIError(c, err)
	}
	out := h.Clients.DescribeAdmin(cl, nil, h.clientOwner(c, cl))
	n, _ := store.CountClientGrants(c.Request().Context(), h.DB, cl.ID)
	out["grant_count"] = n
	return c.JSON(http.StatusOK, out)
}

// APICreateClient: POST /api/v1/clients (RFC 7591 metadata + admin flags)
func (h *Handler) APICreateClient(c *echo.Context) error {
	m, flags, err := clients.DecodeJSON(c.Request().Body, nil, true)
	if err != nil {
		return portal.APIError(c, err)
	}
	cl, creds, err := h.Clients.Create(c.Request().Context(), m, flags, nil, true, h.apiActor(c))
	if err != nil {
		return portal.APIError(c, err)
	}
	return c.JSON(http.StatusCreated, h.Clients.DescribeAdmin(cl, creds, ""))
}

// APIPatchClient: PATCH /api/v1/clients/:id
func (h *Handler) APIPatchClient(c *echo.Context) error {
	cl, err := h.apiClient(c)
	if err != nil {
		return portal.APIError(c, err)
	}
	m, flags, err := clients.DecodeJSON(c.Request().Body, cl, true)
	if err != nil {
		return portal.APIError(c, err)
	}
	updated, whSecret, err := h.Clients.Update(c.Request().Context(), cl.ID, m, flags, h.apiActor(c))
	if err != nil {
		return portal.APIError(c, err)
	}
	return c.JSON(http.StatusOK, h.Clients.DescribeAdmin(updated, &clients.Credentials{WebhookSecret: whSecret}, h.clientOwner(c, updated)))
}

// APIClientAction: POST /api/v1/clients/:id/:action
// actions: approve, enable, disable, rotate-secret, rotate-webhook-secret, webhook-test, webhook-enable
func (h *Handler) APIClientAction(c *echo.Context) error {
	ctx := c.Request().Context()
	cl, err := h.apiClient(c)
	if err != nil {
		return portal.APIError(c, err)
	}
	a := h.apiActor(c)
	extra := map[string]any{}
	switch c.Param("action") {
	case "approve", "enable":
		err = h.Clients.SetStatus(ctx, cl.ID, store.ClientActive, a)
	case "disable":
		err = h.Clients.SetStatus(ctx, cl.ID, store.ClientDisabled, a)
	case "rotate-secret":
		var s string
		if s, err = h.Clients.RotateSecret(ctx, cl.ID, a); err == nil {
			extra["client_secret"] = s
		}
	case "rotate-webhook-secret":
		if cl.WebhookURL == "" {
			return apiFail(c, http.StatusConflict, "webhook_not_configured", "尚未配置 Webhook 地址")
		}
		var s string
		if s, err = h.Clients.RotateWebhookSecret(ctx, cl.ID, a); err == nil {
			extra["webhook_secret"] = s
		}
	case "webhook-test":
		if cl.WebhookURL == "" {
			return apiFail(c, http.StatusConflict, "webhook_not_configured", "尚未配置 Webhook 地址")
		}
		if err := h.Feed.TestDelivery(ctx, cl); err != nil {
			return c.JSON(http.StatusOK, map[string]any{"delivered": false, "error": err.Error()})
		}
		return c.JSON(http.StatusOK, map[string]any{"delivered": true})
	case "webhook-enable":
		if err = feed.ReenableWebhook(ctx, h.DB, cl.ID); err == nil {
			h.apiAudit(c, "client.webhook_reenabled", "client", cl.ID, nil)
		}
	default:
		return apiFail(c, http.StatusNotFound, "not_found", "未知操作："+c.Param("action"))
	}
	if err != nil {
		return portal.APIError(c, err)
	}
	fresh, err := store.GetClient(ctx, h.DB, cl.ID)
	if err != nil {
		return portal.APIError(c, err)
	}
	out := h.Clients.DescribeAdmin(fresh, nil, h.clientOwner(c, fresh))
	for k, v := range extra {
		out[k] = v
	}
	return c.JSON(http.StatusOK, out)
}

// APIDeleteClient: DELETE /api/v1/clients/:id?confirm=<client_id>
func (h *Handler) APIDeleteClient(c *echo.Context) error {
	cl, err := h.apiClient(c)
	if err != nil {
		return portal.APIError(c, err)
	}
	if c.QueryParam("confirm") != cl.ID {
		return apiFail(c, http.StatusBadRequest, "confirmation_required", "删除应用需要 ?confirm=<client_id> 确认")
	}
	if err := h.Clients.Delete(c.Request().Context(), cl.ID, h.apiActor(c)); err != nil {
		return portal.APIError(c, err)
	}
	return c.NoContent(http.StatusNoContent)
}

// APIDeadLetters: GET /api/v1/webhooks/dead-letters?client_id=
func (h *Handler) APIDeadLetters(c *echo.Context) error {
	dead, err := h.deadLetters(c, c.QueryParam("client_id"))
	if err != nil {
		return err
	}
	out := make([]map[string]any, 0, len(dead))
	for _, d := range dead {
		out = append(out, map[string]any{"id": d.ID, "client_id": d.ClientID, "seq": d.Seq, "attempts": d.Attempts, "last_error": d.LastError, "created_at": d.CreatedAt})
	}
	return c.JSON(http.StatusOK, map[string]any{"dead_letters": out})
}

// APIRedrive: POST /api/v1/webhooks/dead-letters/:id/redrive
func (h *Handler) APIRedrive(c *echo.Context) error {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		return apiFail(c, http.StatusNotFound, "not_found", "死信不存在")
	}
	if err := h.Feed.Redrive(c.Request().Context(), id); err != nil {
		return apiFail(c, http.StatusConflict, "redrive_failed", err.Error())
	}
	h.apiAudit(c, "admin.webhook_redrive", "dead_letter", strconv.FormatUint(id, 10), nil)
	return c.JSON(http.StatusOK, map[string]any{"redriven": true})
}

// ---- settings ----

// APISettings: GET /api/v1/settings
func (h *Handler) APISettings(c *echo.Context) error {
	return c.JSON(http.StatusOK, h.Settings.Get())
}

// APIPatchSettings: PATCH /api/v1/settings (any subset of the fields)
func (h *Handler) APIPatchSettings(c *echo.Context) error {
	v := h.Settings.Get()
	before := v
	if err := decodeBody(c, &v); err != nil {
		return portal.APIError(c, err)
	}
	if err := h.Settings.Save(c.Request().Context(), v); err != nil {
		return c.JSON(http.StatusUnprocessableEntity, map[string]string{"error": "validation_failed", "error_description": err.Error()})
	}
	h.apiAudit(c, "admin.settings_changed", "settings", "api", settingsDiff(before, v))
	return c.JSON(http.StatusOK, h.Settings.Get())
}

func settingsDiff(a, b settings.Values) map[string]any {
	var ma, mb map[string]any
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	_ = json.Unmarshal(ja, &ma)
	_ = json.Unmarshal(jb, &mb)
	out := map[string]any{}
	for k, v := range mb {
		if ja, jb := mustJSON(ma[k]), mustJSON(v); ja != jb {
			out[k] = v
		}
	}
	return out
}

func mustJSON(v any) string { b, _ := json.Marshal(v); return string(b) }

// ---- audit ----

// APIAudit: GET /api/v1/audit?action=&target=&actor=&before=&limit=
// actor is an SSO username, or @name for a console administrator.
func (h *Handler) APIAudit(c *echo.Context) error {
	limit := queryInt(c, "limit", 50, 1, 500)
	before, _ := strconv.ParseUint(c.QueryParam("before"), 10, 64)
	f := store.AuditFilter{Action: c.QueryParam("action"), TargetID: c.QueryParam("target"), BeforeID: before, Limit: limit}
	if s := strings.TrimSpace(c.QueryParam("actor")); s != "" {
		if name, ok := strings.CutPrefix(s, "@"); ok {
			f.ActorAdmin = name
		} else if u, err := store.GetUserByUsername(c.Request().Context(), h.DB, account.NormalizeUsername(s)); err == nil {
			f.ActorID = &u.ID
		} else {
			nobody := uuid.Nil
			f.ActorID = &nobody
		}
	}
	list, err := store.ListAudit(c.Request().Context(), h.DB, f)
	if err != nil {
		return err
	}
	out := make([]map[string]any, 0, len(list))
	for _, e := range list {
		row := map[string]any{"id": e.ID, "at": e.At, "action": e.Action, "target_type": e.TargetType, "target_id": e.TargetID,
			"ip": e.IP, "meta": e.Meta, "actor_admin": e.ActorAdmin, "actor_client": e.ActorClientID}
		if e.ActorUserID != nil {
			row["actor_user_id"] = e.ActorUserID.String()
		}
		out = append(out, row)
	}
	resp := map[string]any{"entries": out}
	if len(list) == limit {
		resp["next_before"] = list[len(list)-1].ID
	}
	return c.JSON(http.StatusOK, resp)
}
