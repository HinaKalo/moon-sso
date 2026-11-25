package account

import (
	_ "embed"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// FieldError is a user-facing validation error.
type FieldError struct {
	Field string
	Msg   string
}

func (e *FieldError) Error() string { return e.Msg }

func fieldErr(field, msg string) error { return &FieldError{Field: field, Msg: msg} }

var usernameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{1,30}[A-Za-z0-9]$`)

var reservedUsernames = map[string]bool{
	"admin": true, "administrator": true, "root": true, "system": true, "sso": true, "moon": true,
	"moonl": true, "support": true, "help": true, "security": true, "api": true, "oauth": true,
	"login": true, "logout": true, "register": true, "account": true, "null": true, "undefined": true,
	"anonymous": true, "owner": true, "staff": true, "official": true, "webmaster": true, "postmaster": true,
	"noreply": true, "no-reply": true, "service": true, "test": true,
}

// NormalizeUsername returns the case-folded form used for uniqueness.
func NormalizeUsername(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

func ValidateUsername(s string) error {
	s = strings.TrimSpace(s)
	if !usernameRe.MatchString(s) {
		return fieldErr("username", "用户名需为 3–32 位，只能包含字母、数字和 _ . -，且首尾必须是字母或数字")
	}
	for _, bad := range []string{"..", "__", "--", "._", "_.", ".-", "-.", "_-", "-_"} {
		if strings.Contains(s, bad) {
			return fieldErr("username", "用户名中的符号不能连续出现")
		}
	}
	if reservedUsernames[NormalizeUsername(s)] {
		return fieldErr("username", "该用户名为系统保留，请换一个")
	}
	return nil
}

func CleanDisplayName(s string) (string, error) {
	s = strings.TrimSpace(s)
	var b strings.Builder
	for _, r := range s {
		if unicode.IsControl(r) || r == '​' || r == '‮' || r == '‭' {
			continue
		}
		b.WriteRune(r)
	}
	s = b.String()
	if utf8.RuneCountInString(s) > 32 {
		return "", fieldErr("display_name", "昵称最多 32 个字符")
	}
	return s, nil
}

//go:embed common_passwords.txt
var commonPasswordsRaw string

var commonPasswords = func() map[string]bool {
	m := map[string]bool{}
	for _, l := range strings.Split(commonPasswordsRaw, "\n") {
		if l = strings.TrimSpace(strings.ToLower(l)); l != "" {
			m[l] = true
		}
	}
	return m
}()

func ValidatePassword(pw, username string, minLen int) error {
	n := utf8.RuneCountInString(pw)
	if n < minLen {
		return fieldErr("password", "密码至少需要 "+itoa(minLen)+" 个字符")
	}
	if len(pw) > 128 {
		return fieldErr("password", "密码不能超过 128 个字节")
	}
	lower := strings.ToLower(pw)
	if commonPasswords[lower] {
		return fieldErr("password", "这个密码太常见了，很容易被猜中，请换一个")
	}
	if username != "" && strings.Contains(lower, NormalizeUsername(username)) && len(username) >= 3 {
		return fieldErr("password", "密码不能包含用户名")
	}
	first, _ := utf8.DecodeRuneInString(pw)
	if strings.Count(pw, string(first)) == n {
		return fieldErr("password", "密码不能由同一个字符重复组成")
	}
	if isSequence(lower) {
		return fieldErr("password", "密码不能是连续的数字或字母")
	}
	return nil
}

func isSequence(s string) bool {
	if len(s) < 4 {
		return false
	}
	asc, desc := true, true
	for i := 1; i < len(s); i++ {
		if s[i] != s[i-1]+1 {
			asc = false
		}
		if s[i] != s[i-1]-1 {
			desc = false
		}
	}
	return asc || desc
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
