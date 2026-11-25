// Package portal serves the signed-in user's "authorized apps" page, avatar
// uploads and the developer center where users self-register applications.
package portal

import (
	"errors"
	"html"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/labstack/echo/v5"

	"moon-sso/server/internal/account"
	"moon-sso/server/internal/apitoken"
	"moon-sso/server/internal/auth"
	"moon-sso/server/internal/avatar"
	"moon-sso/server/internal/clients"
	"moon-sso/server/internal/db"
	"moon-sso/server/internal/feed"
	"moon-sso/server/internal/oidc"
	"moon-sso/server/internal/settings"
	"moon-sso/server/internal/store"
	"moon-sso/server/internal/ui"
)

type Handler struct {
	// TestLimiter bounds webhook test sends per developer.
	TestLimiter *auth.Limiter
	DB          *db.DB
	UI          *ui.Handler
	OIDC        *oidc.Provider
	Accounts    *account.Service
	Avatars     *avatar.Store
	Clients     *clients.Service
	Feed        *feed.Feed
	Settings    *settings.Service
	Tokens      *apitoken.Service
	Log         *slog.Logger
}

func actor(c *echo.Context) account.Actor { return account.UserActor(ui.UserOf(c).ID, c.RealIP()) }

// ---- authorized apps ----

func (h *Handler) appsPage(c *echo.Context) (*ui.Page, error) {
	p := h.UI.NewPage(c, "授权应用")
	p.Nav = "apps"
	grants, err := store.ListUserGrants(c.Request().Context(), h.DB, ui.UserOf(c).ID)
	if err != nil {
		return nil, err
	}
	type row struct {
		*store.GrantView
		Scopes []string
	}
	var rows []row
	for _, g := range grants {
		var descs []string
		for _, s := range g.ConsentedScopes {
			for _, info := range oidc.Scopes {
				if info.Name == s {
					descs = append(descs, info.Description)
				}
			}
		}
		rows = append(rows, row{g, descs})
	}
	p.Data["Grants"] = rows
	return p, nil
}

func (h *Handler) Apps(c *echo.Context) error {
	p, err := h.appsPage(c)
	if err != nil {
		return err
	}
	return ui.Render(c, http.StatusOK, "apps", "", p)
}

func (h *Handler) RevokeApp(c *echo.Context) error {
	clientID := c.FormValue("client_id")
	if err := h.OIDC.RevokeGrant(c.Request().Context(), ui.UserOf(c).ID, clientID, actor(c)); err != nil {
		return err
	}
	p, err := h.appsPage(c)
	if err != nil {
		return err
	}
	p.Flash = "已取消授权，该应用将无法再访问你的账号"
	return ui.Render(c, http.StatusOK, "apps", "apps_list", p)
}

// ---- avatar ----

func (h *Handler) Avatar(c *echo.Context) error {
	ctx := c.Request().Context()
	u := ui.UserOf(c)
	p := h.UI.NewPage(c, "个人资料")
	p.Nav = "profile"
	var key string
	if c.FormValue("remove") != "1" {
		fh, err := c.FormFile("avatar")
		if err != nil {
			p.Data["AvatarError"] = "请选择要上传的图片"
			return ui.Render(c, http.StatusUnprocessableEntity, "account", "avatar_section", p)
		}
		if fh.Size > avatar.MaxBytes {
			p.Data["AvatarError"] = avatar.ErrTooLarge.Error()
			return ui.Render(c, http.StatusUnprocessableEntity, "account", "avatar_section", p)
		}
		f, err := fh.Open()
		if err != nil {
			return err
		}
		defer f.Close()
		key, err = h.Avatars.Save(f)
		if err != nil {
			if errors.Is(err, avatar.ErrTooLarge) || errors.Is(err, avatar.ErrUnsupported) || errors.Is(err, avatar.ErrDimensions) {
				p.Data["AvatarError"] = err.Error()
				return ui.Render(c, http.StatusUnprocessableEntity, "account", "avatar_section", p)
			}
			return err
		}
	}
	updated, err := h.Accounts.UpdateProfile(ctx, actor(c), u.ID, account.ProfileUpdate{AvatarKey: &key})
	if err != nil {
		return err
	}
	p.User = updated
	if key == "" {
		p.Data["AvatarFlash"] = "头像已移除"
	} else {
		p.Data["AvatarFlash"] = "头像已更新，并会同步到你使用的所有应用"
	}
	return ui.Render(c, http.StatusOK, "account", "avatar_section", p)
}

// ---- developer center ----

type appKind struct {
	ID, Name, Help string
}

var appKinds = []appKind{
	{"web", "Web 服务端应用", "有后端的网站（Go/Node/Python/Java 等），可安全保存密钥"},
	{"spa", "浏览器单页应用", "纯前端应用，无法保存密钥，使用 PKCE + DPoP"},
	{"native", "桌面 / 移动应用", "Windows、macOS、Linux 桌面程序或 Android 应用，使用系统浏览器回调"},
	{"service", "后台服务", "只用 client_credentials 同步用户数据，不需要用户登录"},
}

// KindOf classifies a client for the forms.
func KindOf(c *store.Client) string { return kindOf(c) }

// AppKinds lists the application kinds offered by the forms.
func AppKinds() any { return appKinds }

func kindOf(c *store.Client) string {
	switch {
	case c.ApplicationType == "native":
		return "native"
	case c.IsPublic():
		return "spa"
	case !c.HasGrant(oidc.GrantAuthCode):
		return "service"
	}
	return "web"
}

func lines(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if l = strings.TrimSpace(l); l != "" && !slices.Contains(out, l) {
			out = append(out, l)
		}
	}
	return out
}

// MetadataFromForm builds client metadata from the developer/admin form.
func MetadataFromForm(c *echo.Context) clients.Metadata {
	form, _ := c.FormValues()
	m := clients.Metadata{
		Name: c.FormValue("name"), Description: strings.TrimSpace(c.FormValue("description")),
		LogoURI: strings.TrimSpace(c.FormValue("logo_uri")), ClientURI: strings.TrimSpace(c.FormValue("client_uri")),
		PolicyURI: strings.TrimSpace(c.FormValue("policy_uri")), TOSURI: strings.TrimSpace(c.FormValue("tos_uri")),
		RedirectURIs: lines(c.FormValue("redirect_uris")), PostLogoutRedirectURIs: lines(c.FormValue("post_logout_redirect_uris")),
		WebhookURL: strings.TrimSpace(c.FormValue("webhook_url")), BackchannelLogoutURI: strings.TrimSpace(c.FormValue("backchannel_logout_uri")),
		Scopes: form["scopes"], WebhookEvents: form["webhook_events"], IDTokenAlg: c.FormValue("id_token_alg"),
		RequireDPoP: c.FormValue("require_dpop") == "1",
	}
	switch c.FormValue("kind") {
	case "spa":
		m.ApplicationType, m.AuthMethod = "web", "none"
		m.GrantTypes = []string{oidc.GrantAuthCode, oidc.GrantRefresh}
	case "native":
		m.ApplicationType, m.AuthMethod = "native", "none"
		m.GrantTypes = []string{oidc.GrantAuthCode, oidc.GrantRefresh}
	case "service":
		m.ApplicationType, m.AuthMethod = "web", "client_secret_basic"
		m.GrantTypes = []string{oidc.GrantClientCredentials}
		m.Scopes = []string{oidc.ScopeUsersSync}
	default:
		m.ApplicationType, m.AuthMethod = "web", "client_secret_basic"
		m.GrantTypes = []string{oidc.GrantAuthCode, oidc.GrantRefresh}
		if slices.Contains(m.Scopes, oidc.ScopeUsersSync) {
			m.GrantTypes = append(m.GrantTypes, oidc.GrantClientCredentials)
		}
	}
	if len(m.WebhookEvents) == 0 && m.WebhookURL != "" {
		m.WebhookEvents = []string{"*"}
	}
	return m
}

func (h *Handler) devPage(c *echo.Context, title string) *ui.Page {
	p := h.UI.NewPage(c, title)
	p.Nav = "developer"
	p.Data["Kinds"] = appKinds
	p.Data["Scopes"] = oidc.Scopes
	p.Data["EventTypes"] = clients.EventTypes
	return p
}

func (h *Handler) Developer(c *echo.Context) error {
	p := h.devPage(c, "开发者中心")
	u := ui.UserOf(c)
	list, _, err := store.ListClients(c.Request().Context(), h.DB, store.ClientFilter{Owner: &u.ID, Limit: 200})
	if err != nil {
		return err
	}
	p.Data["Apps"] = list
	if err := h.tokenData(c, p); err != nil {
		return err
	}
	p.Form["days"] = "90"
	return ui.Render(c, http.StatusOK, "developer", "", p)
}

func (h *Handler) NewApp(c *echo.Context) error {
	p := h.devPage(c, "创建应用")
	p.Form["kind"] = "web"
	p.Data["Selected"] = []string{oidc.ScopeOpenID, oidc.ScopeProfile, oidc.ScopeOffline}
	return ui.Render(c, http.StatusOK, "developer_app", "", p)
}

func fieldErr(p *ui.Page, err error) bool {
	var fe *account.FieldError
	if errors.As(err, &fe) {
		if fe.Field == "" {
			p.Error = fe.Msg
		} else {
			p.Errors[fe.Field] = fe.Msg
			p.Error = fe.Msg
		}
		return true
	}
	if errors.Is(err, clients.ErrQuota) {
		p.Error = err.Error()
		return true
	}
	return false
}

func refill(p *ui.Page, c *echo.Context, m clients.Metadata) {
	for _, k := range []string{"name", "description", "logo_uri", "client_uri", "policy_uri", "tos_uri", "redirect_uris",
		"post_logout_redirect_uris", "webhook_url", "backchannel_logout_uri", "kind", "id_token_alg", "require_dpop"} {
		p.Form[k] = c.FormValue(k)
	}
	p.Data["Selected"] = m.Scopes
	p.Data["SelectedEvents"] = m.WebhookEvents
}

func (h *Handler) CreateApp(c *echo.Context) error {
	p := h.devPage(c, "创建应用")
	m := MetadataFromForm(c)
	u := ui.UserOf(c)
	cl, creds, err := h.Clients.Create(c.Request().Context(), m, nil, &u.ID, false, actor(c))
	if err != nil {
		if fieldErr(p, err) {
			refill(p, c, m)
			return ui.Render(c, http.StatusUnprocessableEntity, "developer_app", "", p)
		}
		return err
	}
	return h.showCredentials(c, cl, creds)
}

func (h *Handler) showCredentials(c *echo.Context, cl *store.Client, creds *clients.Credentials) error {
	p := h.devPage(c, "应用凭证")
	p.Data["App"] = cl
	p.Data["Creds"] = creds
	p.Data["Issuer"] = h.OIDC.Issuer()
	return ui.Render(c, http.StatusOK, "developer_secret", "", p)
}

// ownApp loads an app owned by the current user.
func (h *Handler) ownApp(c *echo.Context) (*store.Client, error) {
	cl, err := store.GetClient(c.Request().Context(), h.DB, c.Param("id"))
	u := ui.UserOf(c)
	if err != nil || cl.OwnerUserID == nil || *cl.OwnerUserID != u.ID {
		return nil, echo.NewHTTPError(http.StatusNotFound, "应用不存在")
	}
	return cl, nil
}

func (h *Handler) editPage(c *echo.Context, cl *store.Client) *ui.Page {
	p := h.devPage(c, cl.Name)
	p.Data["App"] = cl
	p.Data["Kind"] = kindOf(cl)
	p.Data["Selected"] = cl.Scopes
	p.Data["SelectedEvents"] = cl.WebhookEvents
	p.Data["Issuer"] = h.OIDC.Issuer()
	p.Form = map[string]string{"name": cl.Name, "description": cl.Description, "logo_uri": cl.LogoURI, "client_uri": cl.ClientURI,
		"policy_uri": cl.PolicyURI, "tos_uri": cl.TOSURI, "redirect_uris": strings.Join(cl.RedirectURIs, "\n"),
		"post_logout_redirect_uris": strings.Join(cl.PostLogoutRedirectURIs, "\n"), "webhook_url": cl.WebhookURL,
		"backchannel_logout_uri": cl.BackchannelLogoutURI, "kind": kindOf(cl), "id_token_alg": cl.IDTokenAlg}
	if cl.RequireDPoP {
		p.Form["require_dpop"] = "1"
	}
	return p
}

func (h *Handler) App(c *echo.Context) error {
	cl, err := h.ownApp(c)
	if err != nil {
		return err
	}
	return ui.Render(c, http.StatusOK, "developer_app", "", h.editPage(c, cl))
}

func (h *Handler) UpdateApp(c *echo.Context) error {
	cl, err := h.ownApp(c)
	if err != nil {
		return err
	}
	m := MetadataFromForm(c)
	updated, whSecret, err := h.Clients.Update(c.Request().Context(), cl.ID, m, nil, actor(c))
	if err != nil {
		p := h.editPage(c, cl)
		if fieldErr(p, err) {
			refill(p, c, m)
			return ui.Render(c, http.StatusUnprocessableEntity, "developer_app", "", p)
		}
		return err
	}
	if whSecret != "" {
		return h.showCredentials(c, updated, &clients.Credentials{WebhookSecret: whSecret})
	}
	p := h.editPage(c, updated)
	p.Flash = "已保存"
	return ui.Render(c, http.StatusOK, "developer_app", "", p)
}

func (h *Handler) RotateSecret(c *echo.Context) error {
	cl, err := h.ownApp(c)
	if err != nil {
		return err
	}
	secret, err := h.Clients.RotateSecret(c.Request().Context(), cl.ID, actor(c))
	if err != nil {
		return err
	}
	return h.showCredentials(c, cl, &clients.Credentials{ClientSecret: secret})
}

func (h *Handler) RotateWebhookSecret(c *echo.Context) error {
	cl, err := h.ownApp(c)
	if err != nil {
		return err
	}
	secret, err := h.Clients.RotateWebhookSecret(c.Request().Context(), cl.ID, actor(c))
	if err != nil {
		return err
	}
	return h.showCredentials(c, cl, &clients.Credentials{WebhookSecret: secret})
}

func (h *Handler) TestWebhook(c *echo.Context) error {
	cl, err := h.ownApp(c)
	if err != nil {
		return err
	}
	msg := "测试事件已成功送达"
	ok := true
	if allowed, _ := h.TestLimiter.Allow("whtest:" + ui.UserOf(c).ID.String()); !allowed {
		msg, ok = "测试过于频繁，请稍后再试", false
	} else if cl.WebhookURL == "" {
		msg, ok = "尚未配置 Webhook 地址", false
	} else if err := h.Feed.TestDelivery(c.Request().Context(), cl); err != nil {
		msg, ok = "投递失败："+err.Error(), false
	}
	cls := "alert-ok"
	if !ok {
		cls = "alert-err"
	}
	return c.HTML(http.StatusOK, `<div class="alert `+cls+`" role="status">`+template_escape(msg)+`</div>`)
}

func (h *Handler) DeleteApp(c *echo.Context) error {
	cl, err := h.ownApp(c)
	if err != nil {
		return err
	}
	if err := h.Clients.Delete(c.Request().Context(), cl.ID, actor(c)); err != nil {
		return err
	}
	return ui.Redirect(c, "/developer")
}

func (h *Handler) NewToken(c *echo.Context) error {
	p := h.devPage(c, "开发者中心")
	if h.Settings.Get().ClientRegistration == settings.ClientRegClosed {
		return echo.NewHTTPError(http.StatusForbidden, "管理员已关闭应用自助注册")
	}
	tok, err := h.Clients.NewInitialAccessToken(c.Request().Context(), ui.UserOf(c).ID, 1, 24*time.Hour, "developer portal")
	if err != nil {
		return err
	}
	p.Data["Token"] = tok
	p.Data["Issuer"] = h.OIDC.Issuer()
	return ui.Render(c, http.StatusOK, "developer", "token_box", p)
}

func template_escape(s string) string { return html.EscapeString(s) }
