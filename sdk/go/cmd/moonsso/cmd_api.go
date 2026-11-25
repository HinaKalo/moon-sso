package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

func (a *app) cmdAPI(args []string) error {
	fs := newFlags("api")
	data := fs.String("d", "", "")
	fs.StringVar(data, "data", "", "")
	pos, err := exactArgs(fs, "api", args, 2, "METHOD PATH")
	if err != nil {
		return err
	}
	method := strings.ToUpper(pos[0])
	switch method {
	case "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS":
	default:
		return usagef("api", "不支持的方法 %q", pos[0])
	}
	path := pos[1]
	if strings.Contains(path, "://") || strings.HasPrefix(path, "//") || strings.ContainsAny(path, " \t\r\n") {
		return usagef("api", "PATH 必须是 API 前缀下的相对路径（如 apps）或以 /api/ 开头的绝对路径")
	}
	var body []byte
	if *data != "" {
		if strings.HasPrefix(*data, "@") {
			if body, err = a.readSource((*data)[1:]); err != nil {
				return err
			}
		} else {
			body = []byte(*data)
		}
		body = bytes.TrimSpace(body)
		if !json.Valid(body) {
			return usagef("api", "-d 的内容不是有效的 JSON")
		}
	}
	s, err := a.session("")
	if err != nil {
		return err
	}
	res, err := s.send(method, path, nil, body)
	if err != nil {
		return err
	}
	a.printJSON(res.body)
	if res.status >= 400 {
		fmt.Fprintln(a.stderr, newAPIError(res).render())
		return &exitError{code: 1}
	}
	return nil
}
