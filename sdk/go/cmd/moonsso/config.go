package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
)

type profile struct {
	URL   string `json:"url,omitempty"`
	Token string `json:"token"`
}

type config struct {
	Default  string              `json:"default,omitempty"`
	Profiles map[string]*profile `json:"profiles"`
}

func (c *config) token(name string) string {
	if p := c.Profiles[name]; p != nil {
		return p.Token
	}
	return ""
}

// pickDefault chooses a new default after the current one was removed:
// "developer" first, then any remaining developer token, then anything.
func (c *config) pickDefault() {
	if c.Profiles[c.Default] != nil {
		return
	}
	c.Default = ""
	if c.Profiles["developer"] != nil {
		c.Default = "developer"
		return
	}
	names := make([]string, 0, len(c.Profiles))
	for n := range c.Profiles {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if k, _ := tokenKind(c.Profiles[n].Token); k == kindDeveloper {
			c.Default = n
			return
		}
	}
	if len(names) > 0 {
		c.Default = names[0]
	}
}

func (a *app) configPath() (string, error) {
	if p := a.env("MOONSSO_CONFIG"); p != "" {
		return p, nil
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("无法确定配置目录：%v（可设置 MOONSSO_CONFIG）", err)
	}
	return filepath.Join(dir, "moonsso", "config.json"), nil
}

func (a *app) loadConfig() (*config, string, error) {
	path, err := a.configPath()
	if err != nil {
		return nil, "", err
	}
	cfg := &config{Profiles: map[string]*profile{}}
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return cfg, path, nil
	}
	if err != nil {
		return nil, "", fmt.Errorf("读取配置文件失败：%v", err)
	}
	if err := json.Unmarshal(b, cfg); err != nil {
		return nil, "", fmt.Errorf("配置文件 %s 格式错误：%v", path, err)
	}
	if cfg.Profiles == nil {
		cfg.Profiles = map[string]*profile{}
	}
	for n, p := range cfg.Profiles {
		if p == nil {
			delete(cfg.Profiles, n)
		}
	}
	return cfg, path, nil
}

// saveConfig writes the file atomically with owner-only permissions.
func saveConfig(path string, cfg *config) (err error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("创建配置目录失败：%v", err)
	}
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	f, err := os.CreateTemp(dir, ".config-*.tmp")
	if err != nil {
		return fmt.Errorf("写入配置失败：%v", err)
	}
	tmp := f.Name()
	defer func() {
		if err != nil {
			os.Remove(tmp)
		}
	}()
	if err = f.Chmod(0o600); err != nil {
		f.Close()
		return fmt.Errorf("设置配置文件权限失败：%v", err)
	}
	if _, err = f.Write(b); err != nil {
		f.Close()
		return fmt.Errorf("写入配置失败：%v", err)
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return fmt.Errorf("写入配置失败：%v", err)
	}
	if err = f.Close(); err != nil {
		return fmt.Errorf("写入配置失败：%v", err)
	}
	if err = os.Rename(tmp, path); err != nil {
		return fmt.Errorf("保存配置失败：%v", err)
	}
	return nil
}
