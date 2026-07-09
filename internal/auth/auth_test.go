package auth

import (
	"path/filepath"
	"testing"
)

func TestDefaultLogin(t *testing.T) {
	s, err := New("")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got := s.Username(); got != DefaultUsername {
		t.Errorf("username: got %q, want %q", got, DefaultUsername)
	}
	tok, err := s.Login(DefaultUsername, DefaultPassword)
	if err != nil {
		t.Fatalf("login with defaults: %v", err)
	}
	if tok == "" {
		t.Fatal("empty token")
	}
	if !s.Valid(tok) {
		t.Error("token should be valid")
	}
}

func TestLoginRejectsBadCredentials(t *testing.T) {
	s, _ := New("")
	for _, tc := range []struct{ user, pass string }{
		{"admin", "wrong"},
		{"root", "admin"},
		{"", ""},
	} {
		if _, err := s.Login(tc.user, tc.pass); err != ErrBadCredentials {
			t.Errorf("Login(%q,%q): got %v, want ErrBadCredentials", tc.user, tc.pass, err)
		}
	}
}

func TestLogout(t *testing.T) {
	s, _ := New("")
	tok, _ := s.Login(DefaultUsername, DefaultPassword)
	s.Logout(tok)
	if s.Valid(tok) {
		t.Error("token should be invalid after logout")
	}
}

func TestChangePassword(t *testing.T) {
	s, _ := New("")
	if err := s.ChangePassword("wrong", "newsecret"); err != ErrBadCredentials {
		t.Errorf("wrong current: got %v, want ErrBadCredentials", err)
	}
	if err := s.ChangePassword(DefaultPassword, "no"); err != ErrWeakPassword {
		t.Errorf("weak new: got %v, want ErrWeakPassword", err)
	}
	if err := s.ChangePassword(DefaultPassword, "newsecret"); err != nil {
		t.Fatalf("change: %v", err)
	}
	if _, err := s.Login(DefaultUsername, DefaultPassword); err != ErrBadCredentials {
		t.Error("old password should no longer work")
	}
	if _, err := s.Login(DefaultUsername, "newsecret"); err != nil {
		t.Errorf("new password should work: %v", err)
	}
}

func TestPersistenceRoundTrip(t *testing.T) {
	file := filepath.Join(t.TempDir(), "creds.json")
	s1, err := New(file)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := s1.ChangePassword(DefaultPassword, "persisted"); err != nil {
		t.Fatalf("change: %v", err)
	}
	// Reload from disk — the changed password must survive.
	s2, err := New(file)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if _, err := s2.Login(DefaultUsername, "persisted"); err != nil {
		t.Errorf("persisted password should work after reload: %v", err)
	}
}
