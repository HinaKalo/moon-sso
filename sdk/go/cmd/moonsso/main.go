// Command moonsso is a terminal client for the Moon SSO developer and console
// (super-admin) APIs that are authenticated with API tokens.
//
//	go install sso.moonl.cloud/sdk/go/cmd/moonsso@latest
package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime/debug"
	"strconv"
	"strings"
	"time"
)

// version is set at build time with -ldflags "-X main.version=v1.2.3".
var version = "dev"

const (
	devTokenPrefix  = "msso_dev_"
	admTokenPrefix  = "msso_adm_"
	kindDeveloper   = "developer"
	kindConsole     = "console"
	defaultDevURL   = "https://sso.moonl.cloud"
	defaultAdminURL = "https://sso-admin.moonl.cloud"
	devAPIPrefix    = "/api/v1/developer"
	adminAPIPrefix  = "/api/v1"
)

// sleep is replaced in tests so retries do not slow them down.
var sleep = time.Sleep

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr, os.Getenv))
}

type app struct {
	stdin  io.Reader
	in     *bufio.Reader
	stdout io.Writer
	stderr io.Writer
	env    func(string) string

	profile    string
	profileSet bool
	baseURL    string
	jsonOut    bool
	help       bool

	http   *http.Client
	warned map[string]bool
}

// usageError is a problem with the command line; it exits with status 2.
type usageError struct{ msg, topic string }

func (e *usageError) Error() string { return e.msg }

func usagef(topic, format string, args ...any) error {
	return &usageError{msg: fmt.Sprintf(format, args...), topic: topic}
}

// exitError ends the command with a status after output was already written.
type exitError struct{ code int }

func (e *exitError) Error() string { return "exit status " + strconv.Itoa(e.code) }

func run(args []string, stdin io.Reader, stdout, stderr io.Writer, env func(string) string) int {
	if env == nil {
		env = func(string) string { return "" }
	}
	if stdin == nil {
		stdin = strings.NewReader("")
	}
	a := &app{
		stdin:  stdin,
		in:     bufio.NewReader(stdin),
		stdout: stdout,
		stderr: stderr,
		env:    env,
		http:   &http.Client{Timeout: 30 * time.Second},
		warned: map[string]bool{},
	}
	rest, err := a.parseGlobal(args)
	if err != nil {
		return a.exit(err)
	}
	if a.help {
		a.printHelp(a.stdout, rest)
		return 0
	}
	if len(rest) == 0 {
		a.printHelp(a.stderr, nil)
		return 2
	}
	return a.exit(a.dispatch(rest))
}

func (a *app) exit(err error) int {
	if err == nil {
		return 0
	}
	var ee *exitError
	var ue *usageError
	var ae *apiError
	switch {
	case errors.As(err, &ee):
		return ee.code
	case errors.As(err, &ue):
		fmt.Fprintf(a.stderr, "错误：%s\n", ue.msg)
		hint := "moonsso help"
		if ue.topic != "" {
			hint += " " + ue.topic
		}
		fmt.Fprintf(a.stderr, "用法见 %s\n", hint)
		return 2
	case errors.As(err, &ae):
		fmt.Fprintln(a.stderr, ae.render())
		if ae.RetryAfter > 0 {
			fmt.Fprintf(a.stderr, "请在 %d 秒后重试\n", ae.RetryAfter)
		}
		return 1
	default:
		fmt.Fprintf(a.stderr, "错误：%v\n", err)
		return 1
	}
}

// parseGlobal pulls --profile, --url, --json and -h/--help out of the argument
// list wherever they appear (up to a literal "--") and returns the rest.
func (a *app) parseGlobal(args []string) ([]string, error) {
	var rest []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			rest = append(rest, args[i:]...)
			break
		}
		name, val, hasVal := splitFlag(arg)
		switch name {
		case "profile", "url":
			if !hasVal {
				if i+1 >= len(args) {
					return nil, usagef("", "--%s 需要一个值", name)
				}
				i++
				val = args[i]
			}
			if name == "profile" {
				if strings.TrimSpace(val) == "" {
					return nil, usagef("", "--profile 不能为空")
				}
				a.profile, a.profileSet = val, true
			} else {
				a.baseURL = val
			}
		case "json":
			if hasVal {
				b, err := strconv.ParseBool(val)
				if err != nil {
					return nil, usagef("", "--json 的值无效：%s", val)
				}
				a.jsonOut = b
			} else {
				a.jsonOut = true
			}
		case "h", "help":
			a.help = true
		default:
			rest = append(rest, arg)
		}
	}
	return rest, nil
}

func splitFlag(arg string) (name, val string, hasVal bool) {
	if len(arg) < 2 || arg[0] != '-' {
		return "", "", false
	}
	s := arg[1:]
	if s[0] == '-' {
		s = s[1:]
	}
	if s == "" || s[0] == '-' {
		return "", "", false
	}
	if i := strings.IndexByte(s, '='); i >= 0 {
		return s[:i], s[i+1:], true
	}
	return s, "", false
}

func (a *app) dispatch(args []string) error {
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "help":
		a.printHelp(a.stdout, rest)
		return nil
	case "version", "--version":
		if len(rest) > 0 {
			return usagef("version", "version 不接受参数")
		}
		fmt.Fprintf(a.stdout, "moonsso %s\n", versionString())
		return nil
	case "login":
		return a.cmdLogin(rest)
	case "logout":
		return a.cmdLogout(rest)
	case "whoami":
		return a.cmdWhoami(rest, "", "whoami")
	case "token":
		return a.cmdToken(rest)
	case "apps", "app":
		return a.cmdApps(rest)
	case "admin":
		return a.cmdAdmin(rest)
	case "api":
		return a.cmdAPI(rest)
	default:
		return usagef("", "未知命令 %q", cmd)
	}
}

func versionString() string {
	if version != "dev" {
		return version
	}
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		return bi.Main.Version
	}
	return version
}

// stringList is a repeatable string flag.
type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }

func (s *stringList) Set(v string) error {
	*s = append(*s, v)
	return nil
}

func newFlags(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}
	return fs
}

// parseArgs parses flags that may be mixed with positional arguments and
// returns the positional ones in order.
func parseArgs(fs *flag.FlagSet, topic string, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, usagef(topic, "%s", flagError(err))
		}
		rest := fs.Args()
		if len(rest) == 0 {
			return pos, nil
		}
		consumed := len(args) - len(rest)
		if consumed > 0 && args[consumed-1] == "--" {
			return append(pos, rest...), nil
		}
		pos = append(pos, rest[0])
		args = rest[1:]
	}
}

func flagError(err error) string {
	msg := err.Error()
	switch {
	case strings.HasPrefix(msg, "flag provided but not defined: "):
		return "未知参数 " + strings.TrimPrefix(msg, "flag provided but not defined: ")
	case strings.HasPrefix(msg, "flag needs an argument: "):
		return "参数 " + strings.TrimPrefix(msg, "flag needs an argument: ") + " 需要一个值"
	case strings.HasPrefix(msg, "invalid value "):
		return "参数值无效：" + strings.TrimPrefix(msg, "invalid value ")
	case strings.HasPrefix(msg, "invalid boolean value "):
		return "布尔参数值无效：" + strings.TrimPrefix(msg, "invalid boolean value ")
	}
	return msg
}

// exactArgs parses flags and requires exactly n positional arguments.
func exactArgs(fs *flag.FlagSet, topic string, args []string, n int, what string) ([]string, error) {
	pos, err := parseArgs(fs, topic, args)
	if err != nil {
		return nil, err
	}
	if len(pos) < n {
		return nil, usagef(topic, "缺少参数：%s", what)
	}
	if len(pos) > n {
		return nil, usagef(topic, "多余的参数：%s", strings.Join(pos[n:], " "))
	}
	return pos, nil
}
