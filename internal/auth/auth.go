// Package auth provides the admin portal's credential store and session
// management. Credentials are a single username + salted PBKDF2-HMAC-SHA256
// password hash, persisted to disk atomically (temp file + fsync + rename, the
// same pattern the blacklist uses). Sessions are opaque random tokens held in
// memory with a sliding TTL — they do not survive a restart, which is fine for
// a cluster-internal admin page.
//
// Standard library only: PBKDF2 is implemented here (crypto/pbkdf2 landed in
// Go 1.24; this module targets 1.22) on top of crypto/hmac + crypto/sha256.
package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"hash"
	"log"
	"os"
	"sync"
	"time"
)

// Tunables for the password KDF and sessions.
const (
	pbkdf2Iter     = 100_000
	saltLen        = 16
	keyLen         = 32
	sessionTTL     = 12 * time.Hour
	MinPasswordLen = 4

	// DefaultUsername / DefaultPassword seed a fresh install so the operator can
	// log in immediately, then change the password from the Settings tab.
	DefaultUsername = "admin"
	DefaultPassword = "admin"
)

// Errors returned by the store. Handlers map these to HTTP status codes.
var (
	ErrBadCredentials = errors.New("invalid username or password")
	ErrWeakPassword   = errors.New("new password too short")
	ErrInvalidToken   = errors.New("invalid or expired session")
)

// creds is the on-disk representation. Salt and Hash are base64.
type creds struct {
	Username   string `json:"username"`
	Salt       string `json:"salt"`
	Hash       string `json:"hash"`
	Iterations int    `json:"iterations"`
}

// Store holds the current credentials and live sessions. All methods are safe
// for concurrent use.
type Store struct {
	mu       sync.Mutex
	file     string
	username string
	salt     []byte
	hash     []byte
	iter     int
	sessions map[string]time.Time // token -> expiry
}

// New loads credentials from file, seeding admin/admin (and persisting them if
// file is non-empty) when the file does not yet exist. An empty file path keeps
// everything in memory — usable, but password changes won't survive a restart.
func New(file string) (*Store, error) {
	s := &Store{file: file, sessions: make(map[string]time.Time)}
	if file != "" {
		if data, err := os.ReadFile(file); err == nil {
			var c creds
			if err := json.Unmarshal(data, &c); err != nil {
				return nil, err
			}
			salt, err := base64.StdEncoding.DecodeString(c.Salt)
			if err != nil {
				return nil, err
			}
			h, err := base64.StdEncoding.DecodeString(c.Hash)
			if err != nil {
				return nil, err
			}
			s.username, s.salt, s.hash, s.iter = c.Username, salt, h, c.Iterations
			if s.iter <= 0 {
				s.iter = pbkdf2Iter
			}
			return s, nil
		} else if !os.IsNotExist(err) {
			return nil, err
		}
	}
	// Seed defaults.
	if err := s.setPassword(DefaultUsername, DefaultPassword); err != nil {
		return nil, err
	}
	if file != "" {
		s.persist()
	}
	return s, nil
}

// setPassword derives and stores a fresh salt+hash for the given credentials.
// The caller holds no lock on first use (New); ChangePassword holds s.mu.
func (s *Store) setPassword(username, password string) error {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	s.username = username
	s.salt = salt
	s.iter = pbkdf2Iter
	s.hash = pbkdf2Key([]byte(password), salt, s.iter, keyLen, sha256.New)
	return nil
}

// Username returns the current admin username.
func (s *Store) Username() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.username
}

// Login verifies credentials and, on success, returns a new session token.
// Both the username and password are always compared (constant time) so timing
// does not reveal which half was wrong.
func (s *Store) Login(username, password string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	derived := pbkdf2Key([]byte(password), s.salt, s.iter, keyLen, sha256.New)
	userOK := subtle.ConstantTimeCompare([]byte(username), []byte(s.username)) == 1
	passOK := subtle.ConstantTimeCompare(derived, s.hash) == 1
	if !userOK || !passOK {
		return "", ErrBadCredentials
	}

	s.sweepLocked()
	token, err := newToken()
	if err != nil {
		return "", err
	}
	s.sessions[token] = time.Now().Add(sessionTTL)
	return token, nil
}

// Valid reports whether token names a live session, refreshing its TTL.
func (s *Store) Valid(token string) bool {
	if token == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	exp, ok := s.sessions[token]
	if !ok {
		return false
	}
	if time.Now().After(exp) {
		delete(s.sessions, token)
		return false
	}
	s.sessions[token] = time.Now().Add(sessionTTL) // sliding expiry
	return true
}

// Logout invalidates a session token.
func (s *Store) Logout(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, token)
}

// ChangePassword verifies the current password, then replaces it. All existing
// sessions except the caller's stay valid; callers may keep using their token.
func (s *Store) ChangePassword(current, next string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	derived := pbkdf2Key([]byte(current), s.salt, s.iter, keyLen, sha256.New)
	if subtle.ConstantTimeCompare(derived, s.hash) != 1 {
		return ErrBadCredentials
	}
	if len(next) < MinPasswordLen {
		return ErrWeakPassword
	}
	if err := s.setPassword(s.username, next); err != nil {
		return err
	}
	s.persist()
	return nil
}

// sweepLocked drops expired sessions. Caller holds s.mu.
func (s *Store) sweepLocked() {
	now := time.Now()
	for tok, exp := range s.sessions {
		if now.After(exp) {
			delete(s.sessions, tok)
		}
	}
}

// persist atomically writes the credentials file. Caller holds s.mu. Follows the
// blacklist's temp-file + fsync + rename pattern.
func (s *Store) persist() {
	if s.file == "" {
		return
	}
	c := creds{
		Username:   s.username,
		Salt:       base64.StdEncoding.EncodeToString(s.salt),
		Hash:       base64.StdEncoding.EncodeToString(s.hash),
		Iterations: s.iter,
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		log.Printf("auth: marshal failed: %v", err)
		return
	}
	tmp := s.file + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		log.Printf("auth: open %s failed: %v", tmp, err)
		return
	}
	if _, err := f.Write(data); err != nil {
		log.Printf("auth: write %s failed: %v", tmp, err)
		_ = f.Close()
		return
	}
	if err := f.Sync(); err != nil {
		log.Printf("auth: fsync %s failed: %v", tmp, err)
		_ = f.Close()
		return
	}
	if err := f.Close(); err != nil {
		log.Printf("auth: close %s failed: %v", tmp, err)
		return
	}
	if err := os.Rename(tmp, s.file); err != nil {
		log.Printf("auth: rename %s -> %s failed: %v", tmp, s.file, err)
	}
}

// newToken returns a 256-bit random session token, hex-encoded.
func newToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// pbkdf2Key implements PBKDF2 (RFC 8018) with the given PRF hash. This mirrors
// golang.org/x/crypto/pbkdf2 so we stay standard-library only.
func pbkdf2Key(password, salt []byte, iter, keyLength int, h func() hash.Hash) []byte {
	prf := hmac.New(h, password)
	hashLen := prf.Size()
	numBlocks := (keyLength + hashLen - 1) / hashLen

	var buf [4]byte
	dk := make([]byte, 0, numBlocks*hashLen)
	U := make([]byte, hashLen)
	for block := 1; block <= numBlocks; block++ {
		prf.Reset()
		prf.Write(salt)
		buf[0] = byte(block >> 24)
		buf[1] = byte(block >> 16)
		buf[2] = byte(block >> 8)
		buf[3] = byte(block)
		prf.Write(buf[:4])
		dk = prf.Sum(dk)
		T := dk[len(dk)-hashLen:]
		copy(U, T)

		for n := 2; n <= iter; n++ {
			prf.Reset()
			prf.Write(U)
			U = prf.Sum(U[:0])
			for x := range U {
				T[x] ^= U[x]
			}
		}
	}
	return dk[:keyLength]
}
