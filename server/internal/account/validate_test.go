package account

import "testing"

func TestValidateUsername(t *testing.T) {
	for _, ok := range []string{"alice", "Bob_1", "a.b-c", "abc"} {
		if err := ValidateUsername(ok); err != nil {
			t.Errorf("%q rejected: %v", ok, err)
		}
	}
	for _, bad := range []string{"ab", "_abc", "abc_", "a..b", "admin", "ROOT", "中文名", "a b", "x" + string(make([]byte, 40))} {
		if ValidateUsername(bad) == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestValidatePassword(t *testing.T) {
	if err := ValidatePassword("Moon-Test-7781!", "alice", 8); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"short", "password123", "aaaaaaaaaa", "12345678", "my-alice-pass", string(make([]byte, 200))} {
		if ValidatePassword(bad, "alice", 8) == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestCleanDisplayName(t *testing.T) {
	if s, err := CleanDisplayName("  爱丽丝\u202e  "); err != nil || s != "爱丽丝" {
		t.Fatalf("got %q %v", s, err)
	}
	long := ""
	for i := 0; i < 40; i++ {
		long += "字"
	}
	if _, err := CleanDisplayName(long); err == nil {
		t.Fatal("over-long name accepted")
	}
}
