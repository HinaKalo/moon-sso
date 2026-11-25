package admin

import (
	"database/sql"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v5"

	"moon-sso/server/internal/account"
	"moon-sso/server/internal/store"
	"moon-sso/server/internal/ui"
)

// Admins lists console administrators.
func (h *Handler) Admins(c *echo.Context) error {
	p, err := h.adminsPage(c)
	if err != nil {
		return err
	}
	return render(c, http.StatusOK, "admins", "", p)
}

func (h *Handler) adminsPage(c *echo.Context) (*ui.Page, error) {
	p := h.page(c, "管理员", "admins")
	list, err := store.ListAdmins(c.Request().Context(), h.DB)
	if err != nil {
		return nil, err
	}
	p.Data["Admins"] = list
	return p, nil
}

// CreateAdminSubmit adds an administrator with a one-time temporary password.
func (h *Handler) CreateAdminSubmit(c *echo.Context) error {
	ctx := c.Request().Context()
	a, temp, err := CreateAdmin(ctx, h.DB, h.Hasher, c.FormValue("username"), c.FormValue("display_name"), "")
	p, perr := h.adminsPage(c)
	if perr != nil {
		return perr
	}
	if err != nil {
		var fe *account.FieldError
		if errors.As(err, &fe) {
			p.Error = fe.Msg
			p.Form["username"], p.Form["display_name"] = c.FormValue("username"), c.FormValue("display_name")
			return render(c, http.StatusUnprocessableEntity, "admins", "", p)
		}
		return err
	}
	h.audit(c, "admin.admin_created", "admin", a.Username, nil)
	p.Flash = "管理员 " + a.Username + " 已创建。临时密码只显示一次，首次登录需修改密码并绑定身份验证器："
	p.Data["TempPassword"] = temp
	return render(c, http.StatusOK, "admins", "", p)
}

// AdminAction resets, disables or enables an administrator, or ends their sessions.
func (h *Handler) AdminAction(c *echo.Context) error {
	ctx := c.Request().Context()
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return echo.ErrNotFound
	}
	target, err := store.GetAdmin(ctx, h.DB, id)
	if err != nil {
		return echo.ErrNotFound
	}
	me := adminOf(c)
	self := me.ID == target.ID
	now := time.Now().UTC()
	var msg, temp string
	switch c.FormValue("action") {
	case "disable":
		if self {
			return echo.NewHTTPError(http.StatusBadRequest, "不能停用自己")
		}
		if n, err := store.CountActiveAdmins(ctx, h.DB); err != nil || n <= 1 {
			return echo.NewHTTPError(http.StatusBadRequest, "至少需要保留一位启用的管理员")
		}
		target.Status, target.UpdatedAt = store.UserDisabled, now
		err = h.DB.Tx(ctx, sql.LevelReadCommitted, func(tx *sql.Tx) error {
			if err := store.UpdateAdmin(ctx, tx, target); err != nil {
				return err
			}
			return store.RevokeAdminSessions(ctx, tx, target.ID, nil, now)
		})
		msg = "已停用，并结束了其所有会话"
	case "enable":
		target.Status, target.UpdatedAt = store.UserActive, now
		err, msg = store.UpdateAdmin(ctx, h.DB, target), "已启用"
	case "reset":
		if self {
			return echo.NewHTTPError(http.StatusBadRequest, "请在“我的账号”中修改自己的密码")
		}
		temp, err = ResetAdmin(ctx, h.DB, h.Hasher, target, true)
		msg = "已重置：密码和身份验证器均需重新设置。临时密码只显示一次："
	case "revoke_sessions":
		var keep []byte
		if self {
			keep, _ = c.Get("admin_session").([]byte)
		}
		err, msg = store.RevokeAdminSessions(ctx, h.DB, target.ID, keep, now), "已结束该管理员的其他会话"
	default:
		return echo.NewHTTPError(http.StatusBadRequest, "未知操作")
	}
	if err != nil {
		return err
	}
	h.admins.Delete(target.ID)
	h.sessions.DeleteFunc(func(_ string, s *store.AdminSession) bool { return s.AdminID == target.ID })
	h.audit(c, "admin.admin_"+c.FormValue("action"), "admin", target.Username, nil)
	p, err := h.adminsPage(c)
	if err != nil {
		return err
	}
	p.Flash = target.Username + "：" + msg
	if temp != "" {
		p.Data["TempPassword"] = temp
	}
	return render(c, http.StatusOK, "admins", "", p)
}

// Profile shows the signed-in administrator's own account.
func (h *Handler) Profile(c *echo.Context) error {
	p, err := h.profilePage(c)
	if err != nil {
		return err
	}
	return render(c, http.StatusOK, "profile", "", p)
}

func (h *Handler) profilePage(c *echo.Context) (*ui.Page, error) {
	p := h.page(c, "我的账号", "profile")
	sessions, err := store.ListAdminSessions(c.Request().Context(), h.DB, adminOf(c).ID, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	p.Data["Sessions"] = sessions
	cur, _ := c.Get("admin_session").([]byte)
	p.Data["Current"] = string(cur)
	return p, nil
}

// ChangeOwnPassword requires the current password and ends other sessions.
func (h *Handler) ChangeOwnPassword(c *echo.Context) error {
	ctx := c.Request().Context()
	me := adminOf(c)
	p, err := h.profilePage(c)
	if err != nil {
		return err
	}
	fresh, err := store.GetAdmin(ctx, h.DB, me.ID)
	if err != nil {
		return err
	}
	if ok, _, err := h.Hasher.Verify(ctx, c.FormValue("current_password"), fresh.PasswordHash); err != nil || !ok {
		p.Errors["current_password"] = "当前密码不正确"
		return render(c, http.StatusUnprocessableEntity, "profile", "", p)
	}
	if c.FormValue("password") != c.FormValue("password_confirm") {
		p.Errors["password_confirm"] = "两次输入的密码不一致"
		return render(c, http.StatusUnprocessableEntity, "profile", "", p)
	}
	if err := h.setPassword(ctx, fresh, c.FormValue("password")); err != nil {
		var fe *account.FieldError
		if errors.As(err, &fe) {
			p.Errors["password"] = fe.Msg
			return render(c, http.StatusUnprocessableEntity, "profile", "", p)
		}
		return err
	}
	keep, _ := c.Get("admin_session").([]byte)
	_ = store.RevokeAdminSessions(ctx, h.DB, me.ID, keep, time.Now().UTC())
	h.sessions.DeleteFunc(func(_ string, s *store.AdminSession) bool { return s.AdminID == me.ID })
	h.audit(c, "admin.password_changed", "admin", me.Username, nil)
	p.Flash = "密码已修改，其他会话已结束"
	return render(c, http.StatusOK, "profile", "", p)
}
