// Package auth holds the device-key proof of possession used for
// registration and login. It uses only standard primitives from the Go
// standard library: ECDSA over P-256 with SHA-256, signatures in ASN.1 DER
// (what Android Keystore produces for "SHA256withECDSA").
package auth

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"sync"
	"time"
)

const (
	PurposeRegister = "register"
	PurposeLogin    = "login"

	registerPrefix = "PHANTOM-CALL/v1/register\n"
	loginPrefix    = "PHANTOM-CALL/v1/login\n"
)

var (
	ErrBadKey         = errors.New("auth: public key must be a canonical P-256 SubjectPublicKeyInfo")
	ErrChallenge      = errors.New("auth: unknown, expired or mismatched challenge")
	ErrTooManyPending = errors.New("auth: too many pending challenges")
	ErrUnknownPurpose = errors.New("auth: unknown purpose")
)

// RegisterMessage is the exact byte string a device signs to register.
// The purpose prefix keeps a signature made for one operation from being
// accepted for another.
func RegisterMessage(nonceB64 string, spki []byte) []byte {
	h := sha256.Sum256(spki)
	return []byte(registerPrefix + nonceB64 + "\n" + hex.EncodeToString(h[:]))
}

// LoginMessage is the exact byte string a device signs to open a session.
func LoginMessage(nonceB64, deviceID string) []byte {
	return []byte(loginPrefix + nonceB64 + "\n" + deviceID)
}

// ParsePublicKey accepts only a P-256 key in canonical SPKI DER encoding.
func ParsePublicKey(spki []byte) (*ecdsa.PublicKey, error) {
	if len(spki) == 0 || len(spki) > 200 {
		return nil, ErrBadKey
	}
	k, err := x509.ParsePKIXPublicKey(spki)
	if err != nil {
		return nil, ErrBadKey
	}
	pub, ok := k.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return nil, ErrBadKey
	}
	canon, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil || !bytes.Equal(canon, spki) {
		return nil, ErrBadKey
	}
	return pub, nil
}

// Verify checks an ASN.1 DER ECDSA signature over SHA-256(msg).
func Verify(pub *ecdsa.PublicKey, msg, sigDER []byte) bool {
	if len(sigDER) == 0 || len(sigDER) > 80 {
		return false
	}
	d := sha256.Sum256(msg)
	return ecdsa.VerifyASN1(pub, d[:], sigDER)
}

type challenge struct {
	nonce    string
	purpose  string
	deviceID string
	expires  time.Time
}

// Challenges issues single-use nonces. A challenge is removed the first time
// anyone tries to use it, whether or not the attempt succeeds.
type Challenges struct {
	mu  sync.Mutex
	m   map[string]challenge
	ttl time.Duration
	max int
	now func() time.Time
}

func NewChallenges(ttl time.Duration, max int, now func() time.Time) *Challenges {
	return &Challenges{m: map[string]challenge{}, ttl: ttl, max: max, now: now}
}

func randB64(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("auth: system randomness unavailable: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// Issue creates a challenge bound to a purpose and, for login, to a device.
func (c *Challenges) Issue(purpose, deviceID string) (id, nonce string, expires time.Time, err error) {
	switch purpose {
	case PurposeRegister:
		deviceID = ""
	case PurposeLogin:
		if deviceID == "" {
			return "", "", time.Time{}, ErrUnknownPurpose
		}
	default:
		return "", "", time.Time{}, ErrUnknownPurpose
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if len(c.m) >= c.max {
		c.sweepLocked(now)
		if len(c.m) >= c.max {
			return "", "", time.Time{}, ErrTooManyPending
		}
	}
	id, nonce = randB64(16), randB64(32)
	expires = now.Add(c.ttl)
	c.m[id] = challenge{nonce: nonce, purpose: purpose, deviceID: deviceID, expires: expires}
	return id, nonce, expires, nil
}

// Consume returns the nonce of a live challenge that matches purpose and
// device, and removes the challenge in every case.
func (c *Challenges) Consume(id, purpose, deviceID string) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	ch, ok := c.m[id]
	if !ok {
		return "", ErrChallenge
	}
	delete(c.m, id)
	if purpose == PurposeRegister {
		deviceID = ""
	}
	if !c.now().Before(ch.expires) || ch.purpose != purpose || ch.deviceID != deviceID {
		return "", ErrChallenge
	}
	return ch.nonce, nil
}

// Sweep drops expired challenges and reports how many remain.
func (c *Challenges) Sweep() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sweepLocked(c.now())
	return len(c.m)
}

func (c *Challenges) sweepLocked(now time.Time) {
	for id, ch := range c.m {
		if !now.Before(ch.expires) {
			delete(c.m, id)
		}
	}
}
