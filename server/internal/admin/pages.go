package admin

import (
	"database/sql"
	"errors"
	"html"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v5"

	"moon-sso/server/internal/account"
	"moon-sso/server/internal/clients"
	"moon-sso/server/internal/crypto"
	"moon-sso/server/internal/feed"
	"moon-sso/server/internal/httpx"
	"moon-sso/server/internal/oidc"
	"moon-sso/server/internal/portal"
	"moon-sso/server/internal/store"
	"moon-sso/server/internal/ui"
)

func (h *Handler) page(c *echo.Context, title, nav string) *ui.Page {
	return &ui.Page{Title: title, Nav: nav, Site: h.Settings.Get(), Env: h.Cfg.Server.Environment, Admin: adminOf(c),
		CSRF: h.CSRF.Token(c), Errors: map[string]string{}, Form: map[string]string{}, Data: map[string]any{}}
}

func render(c *echo.Context, status int, page, block string, p *ui.Page) error {
	return ui.Render(c, status, "admin/"+page, block, p)
}

func flashHTML(ok bool, msg string) string {
	cls := "alert-ok"
	if !ok {
		cls = "alert-err"
	}
	return `<div class="alert ` + cls + `" role="status">` + html.EscapeString(msg) + `</div>`
}

// ---- dashboard ----

func (h *Handler) Dashboard(c *echo.Context) error {
	ctx := c.Request().Context()
	p := h.page(c, "总览", "dashboard")
	now := time.Now().UTC()
	total, disabled, _ := store.CountUsers(ctx, h.DB)
	sessions, _ := store.CountActiveSessions(ctx, h.DB, now)
	families, _ := store.CountActiveFamilies(ctx, h.DB, now)
	var clientsTotal, pending, webhookFailing, deadLetters, newUsers, logins24 int
	_ = h.DB.QueryRowContext(ctx, "SELECT COUNT(*), COALESCE(SUM(status=2),0), COALESCE(SUM(webhook_last_error<>'' OR webhook_disabled_at IS NOT NULL),0) FROM clients").Scan(&clientsTotal, &pending, &webhookFailing)
	_ = h.DB.QueryRowContext(ctx, "SELECT COUNT(*) FROM webhook_dead_letters WHERE resolved_at IS NULL").Scan(&deadLetters)
	_ = h.DB.QueryRowContext(ctx, "SELECT COUNT(*) FROM users WHERE created_at > ?", now.Add(-24*time.Hour)).Scan(&newUsers)
	_ = h.DB.QueryRowContext(ctx, "SELECT COUNT(*) FROM audit_log WHERE action='user.login' AND at > ?", now.Add(-24*time.Hour)).Scan(&logins24)
	p.Data["Stats"] = []struct {
		Label string
		Value int
		Link  string
	}{
		{"用户总数", total, "/users"}, {"24 小时新用户", newUsers, "/users"}, {"24 小时登录", logins24, "/audit?action=user.login"},
		{"活跃会话", sessions, ""}, {"有效刷新令牌族", families, ""}, {"应用", clientsTotal, "/clients"},
		{"待审核应用", pending, "/clients?status=2"}, {"Webhook 异常", webhookFailing, "/clients"}, {"未处理死信", deadLetters, "/webhooks"},
		{"已停用用户", disabled, "/users?status=2"},
	}
	p.Data["Runtime"] = map[string]any{
		"tokens":   httpx.Metrics.Counter(`tokens_issued_total{grant="refresh_token"}`) + httpx.Metrics.Counter(`tokens_issued_total{grant="authorization_code"}`),
		"refresh":  httpx.Metrics.Counter(`tokens_issued_total{grant="refresh_token"}`),
		"grace":    httpx.Metrics.Counter("refresh_grace_hits_total"),
		"webhooks": httpx.Metrics.Counter("webhooks_delivered_total"),
		"sse":      h.Feed.Connections(),
	}
	recent, _ := store.ListAudit(ctx, h.DB, store.AuditFilter{Limit: 12})
	p.Data["Recent"] = recent
	p.Data["Set"] = h.Settings.Get()
	return render(c, http.StatusOK, "dashboard", "", p)
}

// QuickToggle flips the self-registration switch from the dashboard.
func (h *Handler) ToggleRegistration(c *echo.Context) error {
	v := h.Settings.Get()
	v.RegistrationOpen = c.FormValue("open") == "1"
	if err := h.Settings.Save(c.Request().Context(), v); err != nil {
		return err
	}
	h.audit(c, "admin.settings_changed", "settings", "registration_open", map[string]any{"registration_open": v.RegistrationOpen})
	p := h.page(c, "总览", "dashboard")
	p.Data["Set"] = v
	return render(c, http.StatusOK, "dashboard", "reg_toggle", p)
}

func (h *Handler) audit(c *echo.Context, action, ttype, tid string, meta map[string]any) {
	h.auditAs(c, adminOf(c).Username, action, ttype, tid, meta)
}

// ---- users ----

func (h *Handler) Users(c *echo.Context) error {
	p := h.page(c, "用户", "users")
	q := strings.TrimSpace(c.QueryParam("q"))
	status, _ := strconv.Atoi(c.QueryParam("status"))
	pageNo, _ := strconv.Atoi(c.QueryParam("page"))
	if pageNo < 1 {
		pageNo = 1
	}
	const per = 30
	list, total, err := store.ListUsers(c.Request().Context(), h.DB, store.UserListFilter{Query: account.NormalizeUsername(q), Status: status,
		Limit: per, Offset: (pageNo - 1) * per})
	if err != nil {
		return err
	}
	p.Form = map[string]string{"q": q, "status": c.QueryParam("status")}
	p.Data["Users"] = list
	p.Data["Total"] = total
	p.Data["Page"] = pageNo
	p.Data["HasPrev"] = pageNo > 1
	p.Data["HasNext"] = pageNo*per < total
	return render(c, http.StatusOK, "users", "users_table", p)
}

func (h *Handler) userByParam(c *echo.Context) (*store.User, error) {
	u, err := store.GetUserByPublicSub(c.Request().Context(), h.DB, c.Param("sub"))
	if err != nil {
		return nil, echo.NewHTTPError(http.StatusNotFound, "用户不存在")
	}
	return u, nil
}

func (h *Handler) userPage(c *echo.Context, u *store.User) (*ui.Page, error) {
	ctx := c.Request().Context()
	p := h.page(c, u.Username, "users")
	p.Data["Target"] = u
	sessions, err := store.ListActiveSessions(ctx, h.DB, u.ID, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	grants, err := store.ListUserGrants(ctx, h.DB, u.ID)
	if err != nil {
		return nil, err
	}
	activity, _ := store.ListAudit(ctx, h.DB, store.AuditFilter{TargetID: u.PublicSub, Limit: 20})
	p.Data["Sessions"] = sessions
	p.Data["Grants"] = grants
	p.Data["Activity"] = activity
	return p, nil
}

func (h *Handler) User(c *echo.Context) error {
	u, err := h.userByParam(c)
	if err != nil {
		return err
	}
	p, err := h.userPage(c, u)
	if err != nil {
		return err
	}
	return render(c, http.StatusOK, "user", "", p)
}

// UserAction handles enable/disable/admin/reset/revoke/delete from the user page.
func (h *Handler) UserAction(c *echo.Context) error {
	ctx := c.Request().Context()
	u, err := h.userByParam(c)
	if err != nil {
		return err
	}
	a := h.actor(c)
	var msg string
	switch c.FormValue("action") {
	case "disable":
		err, msg = h.Accounts.SetStatus(ctx, a, u.ID, store.UserDisabled), "已停用，该用户的所有登录已失效"
	case "enable":
		err, msg = h.Accounts.SetStatus(ctx, a, u.ID, store.UserActive), "已启用"
	case "reset_password":
		var temp string
		temp, err = h.Accounts.AdminResetPassword(ctx, a, u.ID)
		if err == nil {
			p, perr := h.userPage(c, u)
			if perr != nil {
				return perr
			}
			p.Data["TempPassword"] = temp
			p.Flash = "密码已重置，该用户所有设备已退出。临时密码只显示一次："
			return render(c, http.StatusOK, "user", "", p)
		}
	case "disable_totp":
		err, msg = h.Accounts.DisableTOTP(ctx, a, u.ID, ""), "已关闭该用户的两步验证"
	case "revoke_sessions":
		err = h.DB.Tx(ctx, sql.LevelReadCommitted, func(tx *sql.Tx) error {
			return h.OIDC.RevokeUserTokens(ctx, tx, u.ID, "", "admin_revoked")
		})
		h.Sessions.ForgetUser(u.ID)
		h.OIDC.WakeEvents()
		msg = "已让该用户在所有设备上退出登录"
		h.audit(c, "admin.sessions_revoked", "user", u.PublicSub, nil)
	case "delete":
		if c.FormValue("confirm") != u.Username {
			return echo.NewHTTPError(http.StatusBadRequest, "请输入用户名以确认删除")
		}
		if err := h.Accounts.Delete(ctx, a, u.ID); err != nil {
			return err
		}
		return ui.Redirect(c, "/users")
	default:
		return echo.NewHTTPError(http.StatusBadRequest, "未知操作")
	}
	if err != nil {
		return err
	}
	fresh, err := store.GetUser(ctx, h.DB, u.ID)
	if err != nil {
		return err
	}
	p, err := h.userPage(c, fresh)
	if err != nil {
		return err
	}
	p.Flash = msg
	return render(c, http.StatusOK, "user", "", p)
}

func (h *Handler) NewUser(c *echo.Context) error {
	return render(c, http.StatusOK, "user_new", "", h.page(c, "创建用户", "users"))
}

func (h *Handler) CreateUser(c *echo.Context) error {
	p := h.page(c, "创建用户", "users")
	p.Form = map[string]string{"username": c.FormValue("username"), "display_name": c.FormValue("display_name")}
	temp := c.FormValue("password")
	generated := temp == ""
	if generated {
		temp = "Tmp-" + crypto.RandomToken(12)
	}
	u, err := h.Accounts.Register(c.Request().Context(), account.RegisterInput{Username: p.Form["username"], Password: temp,
		DisplayName: p.Form["display_name"], Via: "admin", Force: true, MustChangePassword: true, Actor: h.actor(c)})
	if err != nil {
		var fe *account.FieldError
		if errors.As(err, &fe) {
			p.Errors[fe.Field] = fe.Msg
			return render(c, http.StatusUnprocessableEntity, "user_new", "", p)
		}
		return err
	}
	up, err := h.userPage(c, u)
	if err != nil {
		return err
	}
	up.Flash = "用户已创建，首次登录需修改密码。初始密码只显示一次："
	up.Data["TempPassword"] = temp
	return render(c, http.StatusOK, "user", "", up)
}

// ---- clients ----

func (h *Handler) ClientList(c *echo.Context) error {
	p := h.page(c, "应用", "clients")
	status, _ := strconv.Atoi(c.QueryParam("status"))
	list, total, err := store.ListClients(c.Request().Context(), h.DB, store.ClientFilter{Query: c.QueryParam("q"), Status: status, Limit: 200})
	if err != nil {
		return err
	}
	p.Form = map[string]string{"q": c.QueryParam("q"), "status": c.QueryParam("status")}
	p.Data["Clients"] = list
	p.Data["Total"] = total
	return render(c, http.StatusOK, "clients", "clients_table", p)
}

func (h *Handler) formPage(c *echo.Context, cl *store.Client) *ui.Page {
	title := "创建应用"
	if cl != nil {
		title = cl.Name
	}
	p := h.page(c, title, "clients")
	p.Data["Kinds"] = portal.AppKinds()
	p.Data["Scopes"] = oidc.Scopes
	p.Data["EventTypes"] = clients.EventTypes
	if cl == nil {
		p.Form["kind"] = "web"
		p.Data["Selected"] = []string{oidc.ScopeOpenID, oidc.ScopeProfile, oidc.ScopeOffline}
		p.Data["Flags"] = clients.AdminFlags{AllowRegistration: true, SubjectType: "pairwise"}
		return p
	}
	p.Data["App"] = cl
	p.Data["Selected"] = cl.Scopes
	p.Data["SelectedEvents"] = cl.WebhookEvents
	p.Data["Flags"] = clients.FlagsOf(cl)
	p.Data["Issuer"] = h.OIDC.Issuer()
	p.Form = map[string]string{"name": cl.Name, "description": cl.Description, "logo_uri": cl.LogoURI, "client_uri": cl.ClientURI,
		"policy_uri": cl.PolicyURI, "tos_uri": cl.TOSURI, "redirect_uris": strings.Join(cl.RedirectURIs, "\n"),
		"post_logout_redirect_uris": strings.Join(cl.PostLogoutRedirectURIs, "\n"), "webhook_url": cl.WebhookURL,
		"backchannel_logout_uri": cl.BackchannelLogoutURI, "kind": portal.KindOf(cl), "id_token_alg": cl.IDTokenAlg}
	if cl.RequireDPoP {
		p.Form["require_dpop"] = "1"
	}
	if cl.AccessTokenTTLSeconds != nil {
		p.Form["access_ttl"] = strconv.Itoa(*cl.AccessTokenTTLSeconds / 60)
	}
	if cl.OwnerUserID != nil {
		if o, err := store.GetUser(c.Request().Context(), h.DB, *cl.OwnerUserID); err == nil {
			p.Data["Owner"] = o
		}
	}
	grants, _ := store.CountClientGrants(c.Request().Context(), h.DB, cl.ID)
	p.Data["GrantCount"] = grants
	dead, _ := h.deadLetters(c, cl.ID)
	p.Data["Dead"] = dead
	return p
}

func flagsFromForm(c *echo.Context) *clients.AdminFlags {
	f := &clients.AdminFlags{
		FirstParty: c.FormValue("first_party") == "1", NativeLogin: c.FormValue("native_login") == "1",
		SkipConsent: c.FormValue("skip_consent") == "1", AllowRegistration: c.FormValue("allow_registration") == "1",
		Verified: c.FormValue("verified") == "1", WebhookAllowInsecure: c.FormValue("webhook_allow_insecure") == "1",
		SubjectType: c.FormValue("subject_type"),
	}
	if c.FormValue("require_otp") == "1" {
		f.RequireAMR = "otp"
	}
	if m, err := strconv.Atoi(c.FormValue("access_ttl")); err == nil && m >= 1 && m <= 60 {
		v := m * 60
		f.AccessTokenTTL = &v
	}
	return f
}

func (h *Handler) NewClient(c *echo.Context) error {
	return render(c, http.StatusOK, "client", "", h.formPage(c, nil))
}

func (h *Handler) CreateClient(c *echo.Context) error {
	m := portal.MetadataFromForm(c)
	flags := flagsFromForm(c)
	cl, creds, err := h.Clients.Create(c.Request().Context(), m, flags, nil, true, h.actor(c))
	if err != nil {
		var fe *account.FieldError
		if errors.As(err, &fe) {
			p := h.formPage(c, nil)
			p.Error = fe.Msg
			p.Errors[fe.Field] = fe.Msg
			for _, k := range []string{"name", "description", "redirect_uris", "post_logout_redirect_uris", "webhook_url", "backchannel_logout_uri", "kind", "logo_uri"} {
				p.Form[k] = c.FormValue(k)
			}
			p.Data["Flags"] = *flags
			return render(c, http.StatusUnprocessableEntity, "client", "", p)
		}
		return err
	}
	p := h.formPage(c, cl)
	p.Data["Creds"] = creds
	p.Flash = "应用已创建。凭证只显示这一次，请立即保存。"
	return render(c, http.StatusOK, "client", "", p)
}

func (h *Handler) clientByParam(c *echo.Context) (*store.Client, error) {
	cl, err := store.GetClient(c.Request().Context(), h.DB, c.Param("id"))
	if err != nil {
		return nil, echo.NewHTTPError(http.StatusNotFound, "应用不存在")
	}
	return cl, nil
}

func (h *Handler) Client(c *echo.Context) error {
	cl, err := h.clientByParam(c)
	if err != nil {
		return err
	}
	return render(c, http.StatusOK, "client", "", h.formPage(c, cl))
}

func (h *Handler) UpdateClient(c *echo.Context) error {
	cl, err := h.clientByParam(c)
	if err != nil {
		return err
	}
	m := portal.MetadataFromForm(c)
	flags := flagsFromForm(c)
	updated, whSecret, err := h.Clients.Update(c.Request().Context(), cl.ID, m, flags, h.actor(c))
	if err != nil {
		var fe *account.FieldError
		if errors.As(err, &fe) {
			p := h.formPage(c, cl)
			p.Error = fe.Msg
			p.Errors[fe.Field] = fe.Msg
			return render(c, http.StatusUnprocessableEntity, "client", "", p)
		}
		return err
	}
	p := h.formPage(c, updated)
	p.Flash = "已保存"
	if whSecret != "" {
		p.Data["Creds"] = &clients.Credentials{WebhookSecret: whSecret}
		p.Flash = "已保存。新的 Webhook 签名密钥只显示这一次："
	}
	return render(c, http.StatusOK, "client", "", p)
}

func (h *Handler) ClientAction(c *echo.Context) error {
	ctx := c.Request().Context()
	cl, err := h.clientByParam(c)
	if err != nil {
		return err
	}
	a := h.actor(c)
	var creds *clients.Credentials
	var msg string
	switch c.FormValue("action") {
	case "approve", "enable":
		err, msg = h.Clients.SetStatus(ctx, cl.ID, store.ClientActive, a), "应用已启用"
	case "disable":
		err, msg = h.Clients.SetStatus(ctx, cl.ID, store.ClientDisabled, a), "应用已停用，其刷新令牌全部失效"
	case "rotate_secret":
		var s string
		s, err = h.Clients.RotateSecret(ctx, cl.ID, a)
		creds, msg = &clients.Credentials{ClientSecret: s}, "新的 Client Secret 只显示这一次："
	case "rotate_webhook_secret":
		var s string
		s, err = h.Clients.RotateWebhookSecret(ctx, cl.ID, a)
		creds, msg = &clients.Credentials{WebhookSecret: s}, "新的 Webhook 签名密钥只显示这一次："
	case "webhook_test":
		if err := h.Feed.TestDelivery(ctx, cl); err != nil {
			return c.HTML(http.StatusOK, flashHTML(false, "投递失败："+err.Error()))
		}
		return c.HTML(http.StatusOK, flashHTML(true, "测试事件已送达"))
	case "webhook_enable":
		err, msg = feed.ReenableWebhook(ctx, h.DB, cl.ID), "Webhook 已重新启用，将从中断处继续投递"
	case "delete":
		if c.FormValue("confirm") != cl.ID {
			return echo.NewHTTPError(http.StatusBadRequest, "请输入 Client ID 以确认删除")
		}
		if err := h.Clients.Delete(ctx, cl.ID, a); err != nil {
			return err
		}
		return ui.Redirect(c, "/clients")
	default:
		return echo.NewHTTPError(http.StatusBadRequest, "未知操作")
	}
	if err != nil {
		return err
	}
	fresh, err := store.GetClient(ctx, h.DB, cl.ID)
	if err != nil {
		return err
	}
	p := h.formPage(c, fresh)
	p.Flash = msg
	if creds != nil {
		p.Data["Creds"] = creds
	}
	return render(c, http.StatusOK, "client", "", p)
}

// ---- webhooks / dead letters ----

type deadLetter struct {
	ID        uint64
	ClientID  string
	Seq       uint64
	Attempts  int
	LastError string
	CreatedAt time.Time
}

func (h *Handler) deadLetters(c *echo.Context, clientID string) ([]deadLetter, error) {
	q := "SELECT id, client_id, seq, attempts, last_error, created_at FROM webhook_dead_letters WHERE resolved_at IS NULL"
	var args []any
	if clientID != "" {
		q += " AND client_id=?"
		args = append(args, clientID)
	}
	rows, err := h.DB.QueryContext(c.Request().Context(), q+" ORDER BY id DESC LIMIT 100", args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []deadLetter
	for rows.Next() {
		var d deadLetter
		if err := rows.Scan(&d.ID, &d.ClientID, &d.Seq, &d.Attempts, &d.LastError, &d.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func (h *Handler) Webhooks(c *echo.Context) error {
	p := h.page(c, "Webhook 投递", "webhooks")
	dead, err := h.deadLetters(c, "")
	if err != nil {
		return err
	}
	p.Data["Dead"] = dead
	list, _, err := store.ListClients(c.Request().Context(), h.DB, store.ClientFilter{Limit: 200})
	if err != nil {
		return err
	}
	var hooks []*store.Client
	for _, cl := range list {
		if cl.WebhookURL != "" {
			hooks = append(hooks, cl)
		}
	}
	p.Data["Endpoints"] = hooks
	return render(c, http.StatusOK, "webhooks", "", p)
}

func (h *Handler) Redrive(c *echo.Context) error {
	id, _ := strconv.ParseUint(c.FormValue("id"), 10, 64)
	if err := h.Feed.Redrive(c.Request().Context(), id); err != nil {
		return c.HTML(http.StatusOK, flashHTML(false, "重投失败："+err.Error()))
	}
	h.audit(c, "admin.webhook_redrive", "dead_letter", strconv.FormatUint(id, 10), nil)
	return c.HTML(http.StatusOK, flashHTML(true, "已重新投递"))
}

// ---- settings ----

func (h *Handler) SettingsPage(c *echo.Context) error {
	p := h.page(c, "系统设置", "settings")
	p.Data["Set"] = h.Settings.Get()
	return render(c, http.StatusOK, "settings", "", p)
}

func (h *Handler) SaveSettings(c *echo.Context) error {
	p := h.page(c, "系统设置", "settings")
	v := h.Settings.Get()
	num := func(k string, dst *int) {
		if n, err := strconv.Atoi(c.FormValue(k)); err == nil {
			*dst = n
		}
	}
	v.SiteName = strings.TrimSpace(c.FormValue("site_name"))
	v.RegistrationOpen = c.FormValue("registration_open") == "1"
	v.ClientRegistration = c.FormValue("client_registration")
	num("password_min_length", &v.PasswordMinLength)
	num("username_cooldown_days", &v.UsernameCooldownDays)
	num("username_reserve_days", &v.UsernameReserveDays)
	num("session_idle_days", &v.SessionIdleDays)
	num("access_token_minutes", &v.AccessTokenMinutes)
	num("refresh_idle_days", &v.RefreshIdleDays)
	num("refresh_absolute_days", &v.RefreshAbsoluteDays)
	num("max_clients_per_developer", &v.MaxClientsPerDeveloper)
	if err := h.Settings.Save(c.Request().Context(), v); err != nil {
		p.Error = err.Error()
		p.Data["Set"] = v
		return render(c, http.StatusUnprocessableEntity, "settings", "settings_form", p)
	}
	h.audit(c, "admin.settings_changed", "settings", "all", map[string]any{"registration_open": v.RegistrationOpen, "client_registration": v.ClientRegistration})
	p.Data["Set"] = v
	p.Flash = "设置已保存，立即生效"
	return render(c, http.StatusOK, "settings", "settings_form", p)
}

// ---- keys ----

func (h *Handler) KeysPage(c *echo.Context) error {
	p := h.page(c, "签名密钥", "keys")
	list, err := h.Keys.List(c.Request().Context())
	if err != nil {
		return err
	}
	p.Data["Keys"] = list
	return render(c, http.StatusOK, "keys", "", p)
}

func (h *Handler) RotateKeys(c *echo.Context) error {
	if err := h.Keys.Rotate(c.Request().Context()); err != nil {
		return err
	}
	h.audit(c, "admin.keys_rotated", "keys", "", nil)
	return ui.Redirect(c, "/keys")
}

// ---- audit ----

func (h *Handler) Audit(c *echo.Context) error {
	p := h.page(c, "审计日志", "audit")
	before, _ := strconv.ParseUint(c.QueryParam("before"), 10, 64)
	f := store.AuditFilter{Action: c.QueryParam("action"), TargetID: c.QueryParam("target"), BeforeID: before, Limit: 50}
	if s := strings.TrimSpace(c.QueryParam("actor")); s != "" {
		if strings.HasPrefix(s, "@") {
			f.ActorAdmin = strings.TrimPrefix(s, "@") // console administrator
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
	p.Form = map[string]string{"action": f.Action, "target": f.TargetID, "actor": c.QueryParam("actor")}
	p.Data["Entries"] = list
	if len(list) == f.Limit {
		p.Data["Next"] = list[len(list)-1].ID
	}
	return render(c, http.StatusOK, "audit", "audit_table", p)
}
