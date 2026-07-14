package auth

import (
	"os"
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

func TestNewFailsWhenFileUnwritable(t *testing.T) {
	// Seeding into a directory that doesn't exist must fail loudly at startup,
	// not leave a store whose password changes silently vanish on restart.
	if _, err := New(filepath.Join(t.TempDir(), "missing-dir", "creds.json")); err == nil {
		t.Error("New should error when the credentials file can't be written")
	}
}

func TestChangePasswordRollsBackWhenPersistFails(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "creds-dir")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	s, err := New(filepath.Join(dir, "creds.json"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// Remove the directory out from under the store so persist's temp-file
	// creation fails (works on both Unix and Windows, unlike chmod tricks).
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}

	if err := s.ChangePassword(DefaultPassword, "newsecret"); err == nil {
		t.Fatal("ChangePassword should error when the file can't be written")
	}
	// The failed change must roll back: the old password still works.
	if _, err := s.Login(DefaultUsername, DefaultPassword); err != nil {
		t.Errorf("old password should still work after failed change: %v", err)
	}
	if _, err := s.Login(DefaultUsername, "newsecret"); err != ErrBadCredentials {
		t.Error("new password should not work after failed change")
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
