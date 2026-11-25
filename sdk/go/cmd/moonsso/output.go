package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"
	"time"
	"unicode"
)

func decodeObject(b []byte) (map[string]any, error) {
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	var m map[string]any
	if err := d.Decode(&m); err != nil {
		return nil, err
	}
	if m == nil {
		m = map[string]any{}
	}
	return m, nil
}

// printJSON pretty-prints a JSON body; anything else is written unchanged.
func (a *app) printJSON(b []byte) {
	if len(bytes.TrimSpace(b)) == 0 {
		return
	}
	var buf bytes.Buffer
	if err := json.Indent(&buf, b, "", "  "); err == nil {
		buf.WriteByte('\n')
		a.stdout.Write(buf.Bytes())
		return
	}
	a.stdout.Write(b)
	if b[len(b)-1] != '\n' {
		io.WriteString(a.stdout, "\n")
	}
}

// sanitize strips control characters so server-provided text cannot inject
// terminal escape sequences or break table layout.
func sanitize(s string) string {
	if !strings.ContainsFunc(s, isControl) {
		return s
	}
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' || r == '\r' {
			return ' '
		}
		if isControl(r) {
			return -1
		}
		return r
	}, s)
}

func isControl(r rune) bool { return r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) }

// sval returns a value as plain text, or "" when absent.
func sval(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	return scalar(m[key])
}

func scalar(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return sanitize(x)
	case json.Number:
		return x.String()
	case bool:
		if x {
			return "true"
		}
		return "false"
	case float64:
		return fmt.Sprint(x)
	default:
		b, err := json.Marshal(x)
		if err != nil {
			return sanitize(fmt.Sprint(x))
		}
		return sanitize(string(b))
	}
}

// fmtVal formats a value for human output; empty values become "-".
func fmtVal(key string, v any) string {
	switch x := v.(type) {
	case nil:
		return "-"
	case string:
		if x == "" {
			return "-"
		}
		if isTimeKey(key) {
			if t, err := time.Parse(time.RFC3339Nano, x); err == nil {
				return localTime(t)
			}
		}
		return sanitize(x)
	case bool:
		if x {
			return "是"
		}
		return "否"
	case []any:
		if len(x) == 0 {
			return "-"
		}
		parts := make([]string, len(x))
		for i, e := range x {
			parts[i] = scalar(e)
		}
		return strings.Join(parts, ", ")
	case map[string]any:
		if len(x) == 0 {
			return "-"
		}
		if u := sval(x, "username"); u != "" {
			return u
		}
		return scalar(x)
	}
	return scalar(v)
}

func isTimeKey(key string) bool {
	if i := strings.LastIndexByte(key, '.'); i >= 0 {
		key = key[i+1:]
	}
	return key == "at" || strings.HasSuffix(key, "_at")
}

func localTime(t time.Time) string { return t.Local().Format("2006-01-02 15:04:05") }

// fmtDuration renders a duration in Chinese, largest units first.
func fmtDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%d 秒", int(d/time.Second))
	}
	days := int(d / (24 * time.Hour))
	hours := int(d % (24 * time.Hour) / time.Hour)
	mins := int(d % time.Hour / time.Minute)
	var parts []string
	if days > 0 {
		parts = append(parts, fmt.Sprintf("%d 天", days))
	}
	if hours > 0 {
		parts = append(parts, fmt.Sprintf("%d 小时", hours))
	}
	if mins > 0 && days == 0 {
		parts = append(parts, fmt.Sprintf("%d 分钟", mins))
	}
	return strings.Join(parts, " ")
}

type kv struct{ k, v string }

// writeKV prints an aligned key/value block; alignment accounts for
// double-width CJK characters in keys.
func writeKV(w io.Writer, rows []kv) {
	width := 0
	for _, r := range rows {
		if n := displayWidth(r.k); n > width {
			width = n
		}
	}
	for _, r := range rows {
		fmt.Fprintf(w, "%s:%s %s\n", r.k, strings.Repeat(" ", width-displayWidth(r.k)), r.v)
	}
}

func displayWidth(s string) int {
	n := 0
	for _, r := range s {
		switch {
		case unicode.Is(unicode.Mn, r):
		case isWide(r):
			n += 2
		default:
			n++
		}
	}
	return n
}

func isWide(r rune) bool {
	return (r >= 0x1100 && r <= 0x115f) || (r >= 0x2e80 && r <= 0xa4cf) || (r >= 0xac00 && r <= 0xd7a3) ||
		(r >= 0xf900 && r <= 0xfaff) || (r >= 0xfe30 && r <= 0xfe4f) || (r >= 0xff00 && r <= 0xff60) ||
		(r >= 0xffe0 && r <= 0xffe6) || (r >= 0x1f300 && r <= 0x1faff) || (r >= 0x20000 && r <= 0x3fffd)
}

// objectKV lists the keys in order first, then the rest alphabetically.
// Nested objects are flattened as parent.child; skipped keys are omitted.
func objectKV(m map[string]any, order []string, skip ...string) []kv {
	skipSet := map[string]bool{}
	for _, k := range skip {
		skipSet[k] = true
	}
	var rows []kv
	seen := map[string]bool{}
	add := func(k string) {
		if seen[k] || skipSet[k] {
			return
		}
		seen[k] = true
		v, ok := m[k]
		if !ok {
			return
		}
		if sub, isMap := v.(map[string]any); isMap && len(sub) > 0 && sval(sub, "username") == "" {
			for _, r := range objectKV(sub, nil) {
				rows = append(rows, kv{k + "." + r.k, r.v})
			}
			return
		}
		rows = append(rows, kv{k, fmtVal(k, v)})
	}
	for _, k := range order {
		add(k)
	}
	rest := make([]string, 0, len(m))
	for k := range m {
		if !seen[k] {
			rest = append(rest, k)
		}
	}
	sort.Strings(rest)
	for _, k := range rest {
		add(k)
	}
	return rows
}

func writeTable(w io.Writer, headers []string, rows [][]string) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, strings.Join(headers, "\t"))
	for _, r := range rows {
		cells := make([]string, len(r))
		for i, c := range r {
			cells[i] = strings.ReplaceAll(c, "\t", " ")
		}
		fmt.Fprintln(tw, strings.Join(cells, "\t"))
	}
	tw.Flush()
}

func objects(v any) []map[string]any {
	arr, _ := v.([]any)
	out := make([]map[string]any, 0, len(arr))
	for _, e := range arr {
		if m, ok := e.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

// genericTable prints objects whose shape is not fixed: columns are the
// scalar keys found in any item, "id" first, then alphabetical.
func genericTable(w io.Writer, items []map[string]any) {
	cols := map[string]bool{}
	for _, it := range items {
		for k, v := range it {
			switch v.(type) {
			case map[string]any:
			default:
				cols[k] = true
			}
		}
	}
	keys := make([]string, 0, len(cols))
	for k := range cols {
		if k != "id" {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	if cols["id"] {
		keys = append([]string{"id"}, keys...)
	}
	headers := make([]string, len(keys))
	for i, k := range keys {
		headers[i] = strings.ToUpper(k)
	}
	rows := make([][]string, len(items))
	for i, it := range items {
		row := make([]string, len(keys))
		for j, k := range keys {
			row[j] = fmtVal(k, it[k])
		}
		rows[i] = row
	}
	writeTable(w, headers, rows)
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

// secrets that the server shows once.
var secretKeys = []string{"client_secret", "registration_access_token", "webhook_secret", "temporary_password"}

func (a *app) printSecrets(m map[string]any, keys ...string) {
	var rows []kv
	for _, k := range keys {
		if v := sval(m, k); v != "" {
			rows = append(rows, kv{k, v})
		}
	}
	if len(rows) == 0 {
		return
	}
	fmt.Fprintln(a.stderr, "注意：以下密钥只显示这一次，请立即妥善保存。")
	fmt.Fprintln(a.stdout)
	writeKV(a.stdout, rows)
}
