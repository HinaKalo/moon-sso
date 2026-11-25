package safehttp

import (
	"net/netip"
	"testing"
)

func TestAddrAllowed(t *testing.T) {
	blocked := []string{"127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.169.254", "100.64.0.1",
		"0.0.0.0", "::1", "fe80::1", "fc00::1", "::ffff:127.0.0.1", "224.0.0.1"}
	for _, s := range blocked {
		if AddrAllowed(netip.MustParseAddr(s)) {
			t.Errorf("%s should be blocked", s)
		}
	}
	for _, s := range []string{"1.1.1.1", "8.8.8.8", "2606:4700:4700::1111"} {
		if !AddrAllowed(netip.MustParseAddr(s)) {
			t.Errorf("%s should be allowed", s)
		}
	}
}

func TestValidateURL(t *testing.T) {
	for _, u := range []string{"http://example.com/x", "https://127.0.0.1:2019/stop", "https://localhost/x", "https://user:pw@example.com/",
		"https://intranet/x", "ftp://example.com", "https://10.0.0.1/x"} {
		if ValidateURL(u, false) == nil {
			t.Errorf("%s should be rejected", u)
		}
	}
	if ValidateURL("https://1.1.1.1/hook", false) != nil {
		t.Error("public https IP rejected")
	}
}
