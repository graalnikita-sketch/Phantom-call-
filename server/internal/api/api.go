// Package api is the HTTP interface of the Phase 1 server: account and
// device registration, key-based login, public-key lookup, session and
// account management. Signalling for calls is added in Phase 2.
package api

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"phantomcall/server/internal/auth"
	"phantomcall/server/internal/ratelimit"
	"phantomcall/server/internal/store"
)

type Config struct {
	SessionTTL           time.Duration
	ChallengeTTL         time.Duration
	MaxPendingChallenges int
	MaxSessionsPerDevice int
	MaxBodyBytes         int64
	// TrustForwardedFor makes the limiter use the right-most X-Forwarded-For
	// entry. Enable only behind a reverse proxy that you control.
	TrustForwardedFor bool

	ChallengesPerMinute  int
	RegistrationsPerHour int
	LoginsPerMinute      int
	KeyLookupsPerMinute  int
}

func DefaultConfig() Config {
	return Config{
		SessionTTL:           30 * 24 * time.Hour,
		ChallengeTTL:         60 * time.Second,
		MaxPendingChallenges: 100_000,
		MaxSessionsPerDevice: 5,
		MaxBodyBytes:         8 << 10,
		ChallengesPerMinute:  30,
		RegistrationsPerHour: 5,
		LoginsPerMinute:      20,
		KeyLookupsPerMinute:  60,
	}
}

type Server struct {
	cfg       Config
	st        store.Store
	ch        *auth.Challenges
	now       func() time.Time
	log       *slog.Logger
	limChal   *ratelimit.Limiter
	limReg    *ratelimit.Limiter
	limLogin  *ratelimit.Limiter
	limLookup *ratelimit.Limiter
}

func New(cfg Config, st store.Store, log *slog.Logger, now func() time.Time) *Server {
	if now == nil {
		now = time.Now
	}
	const maxKeys = 200_000
	return &Server{
		cfg: cfg, st: st, now: now, log: log,
		ch:        auth.NewChallenges(cfg.ChallengeTTL, cfg.MaxPendingChallenges, now),
		limChal:   ratelimit.New(cfg.ChallengesPerMinute, time.Minute, maxKeys, now),
		limReg:    ratelimit.New(cfg.RegistrationsPerHour, time.Hour, maxKeys, now),
		limLogin:  ratelimit.New(cfg.LoginsPerMinute, time.Minute, maxKeys, now),
		limLookup: ratelimit.New(cfg.KeyLookupsPerMinute, time.Minute, maxKeys, now),
	}
}

// Maintain removes expired sessions, challenges and limiter entries.
func (s *Server) Maintain(ctx context.Context) {
	_, _ = s.st.DeleteExpiredSessions(ctx, s.now())
	s.ch.Sweep()
	s.limChal.Sweep()
	s.limReg.Sweep()
	s.limLogin.Sweep()
	s.limLookup.Sweep()
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, 200, map[string]string{"status": "ok"}) })
	mux.HandleFunc("POST /v1/challenges", s.handleChallenge)
	mux.HandleFunc("POST /v1/accounts", s.handleRegister)
	mux.HandleFunc("POST /v1/sessions", s.handleLogin)
	mux.HandleFunc("GET /v1/me", s.authed(s.handleMe))
	mux.HandleFunc("DELETE /v1/me", s.authed(s.handleDeleteAccount))
	mux.HandleFunc("PUT /v1/me/push-token", s.authed(s.handlePushToken))
	mux.HandleFunc("DELETE /v1/sessions/{id}", s.authed(s.handleDeleteSession))
	mux.HandleFunc("GET /v1/accounts/{phantom_id}/keys", s.authed(s.handleKeys))
	return s.wrap(mux)
}

// ---- plumbing ----

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(c int) { w.status = c; w.ResponseWriter.WriteHeader(c) }

// wrap adds body limits, no-store headers and request logging. The log line
// carries the route pattern, never the concrete path, address or any id.
func (s *Server) wrap(next *http.ServeMux) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := s.now()
		r.Body = http.MaxBytesReader(w, r.Body, s.cfg.MaxBodyBytes)
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		sw := &statusWriter{ResponseWriter: w, status: 200}
		_, pattern := next.Handler(r)
		if pattern == "" {
			pattern = "unmatched"
		}
		next.ServeHTTP(sw, r)
		if s.log != nil {
			s.log.Info("request", "route", pattern, "status", sw.status, "ms", s.now().Sub(start).Milliseconds())
		}
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, map[string]string{"error": code})
}

func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			writeErr(w, http.StatusRequestEntityTooLarge, "body_too_large")
		} else {
			writeErr(w, http.StatusBadRequest, "bad_json")
		}
		return false
	}
	if dec.More() {
		writeErr(w, http.StatusBadRequest, "bad_json")
		return false
	}
	return true
}

func (s *Server) clientKey(r *http.Request) string {
	if s.cfg.TrustForwardedFor {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			if ip := strings.TrimSpace(parts[len(parts)-1]); ip != "" {
				return ip
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("api: system randomness unavailable: " + err.Error())
	}
	return hex.EncodeToString(b)
}

const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// newPhantomID returns a random public identifier with 60 bits of entropy,
// e.g. PH-7K2M-Q9XA-0RTD. It is not derived from a phone number or a key.
func newPhantomID() string {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		panic("api: system randomness unavailable: " + err.Error())
	}
	out := []byte("PH-")
	for i, x := range b {
		if i > 0 && i%4 == 0 {
			out = append(out, '-')
		}
		out = append(out, crockford[x&31])
	}
	return string(out)
}

func validPhantomID(id string) bool {
	if len(id) != 17 || !strings.HasPrefix(id, "PH-") {
		return false
	}
	for i := 3; i < len(id); i++ {
		c := id[i]
		if (i-3)%5 == 4 {
			if c != '-' {
				return false
			}
			continue
		}
		if !strings.ContainsRune(crockford, rune(c)) {
			return false
		}
	}
	return true
}

func (s *Server) authed(h func(http.ResponseWriter, *http.Request, store.Session)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		const p = "Bearer "
		a := r.Header.Get("Authorization")
		if !strings.HasPrefix(a, p) || len(a) > 200 {
			writeErr(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		sess, err := s.st.SessionByTokenHash(r.Context(), sha256.Sum256([]byte(a[len(p):])))
		if err != nil || !s.now().Before(sess.ExpiresAt) {
			writeErr(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		h(w, r, sess)
	}
}

// ---- handlers ----

func (s *Server) handleChallenge(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Purpose  string `json:"purpose"`
		DeviceID string `json:"device_id,omitempty"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	if !s.limChal.Allow(s.clientKey(r)) {
		writeErr(w, http.StatusTooManyRequests, "rate_limited")
		return
	}
	if len(req.DeviceID) > 64 {
		writeErr(w, http.StatusBadRequest, "bad_request")
		return
	}
	id, nonce, exp, err := s.ch.Issue(req.Purpose, req.DeviceID)
	switch {
	case errors.Is(err, auth.ErrUnknownPurpose):
		writeErr(w, http.StatusBadRequest, "bad_request")
		return
	case errors.Is(err, auth.ErrTooManyPending):
		writeErr(w, http.StatusServiceUnavailable, "busy")
		return
	case err != nil:
		writeErr(w, http.StatusInternalServerError, "internal")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"challenge_id": id, "nonce": nonce, "expires_at": exp.UTC().Format(time.RFC3339)})
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ChallengeID string `json:"challenge_id"`
		PublicKey   string `json:"public_key"` // base64 (standard) of SPKI DER
		Signature   string `json:"signature"`  // base64 (standard) of ASN.1 DER ECDSA
	}
	if !readJSON(w, r, &req) {
		return
	}
	if !s.limReg.Allow(s.clientKey(r)) {
		writeErr(w, http.StatusTooManyRequests, "rate_limited")
		return
	}
	nonce, err := s.ch.Consume(req.ChallengeID, auth.PurposeRegister, "")
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "invalid_challenge")
		return
	}
	spki, err1 := base64.StdEncoding.DecodeString(req.PublicKey)
	sig, err2 := base64.StdEncoding.DecodeString(req.Signature)
	if err1 != nil || err2 != nil {
		writeErr(w, http.StatusBadRequest, "bad_request")
		return
	}
	pub, err := auth.ParsePublicKey(spki)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_public_key")
		return
	}
	if !auth.Verify(pub, auth.RegisterMessage(nonce, spki), sig) {
		writeErr(w, http.StatusUnauthorized, "bad_signature")
		return
	}
	now := s.now()
	for attempt := 0; attempt < 3; attempt++ {
		acc := store.Account{PhantomID: newPhantomID(), CreatedAt: now}
		dev := store.Device{ID: randHex(16), PhantomID: acc.PhantomID, PublicKey: spki, KeyHash: sha256.Sum256(spki), CreatedAt: now}
		err = s.st.CreateAccountWithDevice(r.Context(), acc, dev)
		if err == nil {
			writeJSON(w, http.StatusCreated, map[string]string{"phantom_id": acc.PhantomID, "device_id": dev.ID})
			return
		}
		if !errors.Is(err, store.ErrConflict) {
			writeErr(w, http.StatusInternalServerError, "internal")
			return
		}
	}
	// Three conflicts in a row with fresh random ids means the key is taken.
	writeErr(w, http.StatusConflict, "key_already_registered")
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ChallengeID string `json:"challenge_id"`
		DeviceID    string `json:"device_id"`
		Signature   string `json:"signature"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	if !s.limLogin.Allow(s.clientKey(r)) {
		writeErr(w, http.StatusTooManyRequests, "rate_limited")
		return
	}
	// Every failure below returns the same answer, so the endpoint does not
	// reveal whether a device id exists.
	deny := func() { writeErr(w, http.StatusUnauthorized, "invalid_credentials") }
	nonce, err := s.ch.Consume(req.ChallengeID, auth.PurposeLogin, req.DeviceID)
	if err != nil {
		deny()
		return
	}
	sig, err := base64.StdEncoding.DecodeString(req.Signature)
	if err != nil {
		deny()
		return
	}
	dev, err := s.st.DeviceByID(r.Context(), req.DeviceID)
	if err != nil {
		deny()
		return
	}
	pub, err := auth.ParsePublicKey(dev.PublicKey)
	if err != nil || !auth.Verify(pub, auth.LoginMessage(nonce, dev.ID), sig) {
		deny()
		return
	}
	tb := make([]byte, 32)
	if _, err := rand.Read(tb); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal")
		return
	}
	token := base64.RawURLEncoding.EncodeToString(tb)
	now := s.now()
	sess := store.Session{ID: randHex(8), TokenHash: sha256.Sum256([]byte(token)), DeviceID: dev.ID, PhantomID: dev.PhantomID, CreatedAt: now, ExpiresAt: now.Add(s.cfg.SessionTTL)}
	if err := s.st.CreateSession(r.Context(), sess, s.cfg.MaxSessionsPerDevice); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"token": token, "session_id": sess.ID, "expires_at": sess.ExpiresAt.UTC().Format(time.RFC3339)})
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request, sess store.Session) {
	sessions, err := s.st.SessionsByDevice(r.Context(), sess.DeviceID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal")
		return
	}
	type sv struct {
		ID        string `json:"session_id"`
		CreatedAt string `json:"created_at"`
		ExpiresAt string `json:"expires_at"`
		Current   bool   `json:"current"`
	}
	out := []sv{}
	for _, x := range sessions {
		if s.now().Before(x.ExpiresAt) {
			out = append(out, sv{x.ID, x.CreatedAt.UTC().Format(time.RFC3339), x.ExpiresAt.UTC().Format(time.RFC3339), x.ID == sess.ID})
		}
	}
	writeJSON(w, 200, map[string]any{"phantom_id": sess.PhantomID, "device_id": sess.DeviceID, "sessions": out})
}

func (s *Server) handleDeleteAccount(w http.ResponseWriter, r *http.Request, sess store.Session) {
	if err := s.st.DeleteAccount(r.Context(), sess.PhantomID); err != nil && !errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusInternalServerError, "internal")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handlePushToken(w http.ResponseWriter, r *http.Request, sess store.Session) {
	var req struct {
		Token string `json:"token"` // empty string clears it
	}
	if !readJSON(w, r, &req) {
		return
	}
	if len(req.Token) > 4096 {
		writeErr(w, http.StatusBadRequest, "bad_request")
		return
	}
	if err := s.st.SetPushToken(r.Context(), sess.DeviceID, req.Token); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleDeleteSession(w http.ResponseWriter, r *http.Request, sess store.Session) {
	id := r.PathValue("id")
	if id == "current" {
		id = sess.ID
	}
	err := s.st.DeleteSession(r.Context(), sess.DeviceID, id)
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "not_found")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleKeys(w http.ResponseWriter, r *http.Request, sess store.Session) {
	if !s.limLookup.Allow(sess.DeviceID) {
		writeErr(w, http.StatusTooManyRequests, "rate_limited")
		return
	}
	id := r.PathValue("phantom_id")
	if !validPhantomID(id) {
		writeErr(w, http.StatusBadRequest, "bad_request")
		return
	}
	devs, err := s.st.DevicesByAccount(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "not_found")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal")
		return
	}
	type dv struct {
		DeviceID  string `json:"device_id"`
		PublicKey string `json:"public_key"`
	}
	out := []dv{}
	for _, d := range devs {
		out = append(out, dv{d.ID, base64.StdEncoding.EncodeToString(d.PublicKey)})
	}
	writeJSON(w, 200, map[string]any{"phantom_id": id, "devices": out})
}
