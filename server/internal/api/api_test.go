package api

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"phantomcall/server/internal/auth"
	"phantomcall/server/internal/store"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time      { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) Add(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }

type env struct {
	t    *testing.T
	h    http.Handler
	clk  *clock
	logs *bytes.Buffer
	st   *store.Memory
}

func newEnv(t *testing.T, mut func(*Config)) *env {
	t.Helper()
	cfg := DefaultConfig()
	cfg.ChallengesPerMinute, cfg.RegistrationsPerHour, cfg.LoginsPerMinute = 1000, 1000, 1000
	if mut != nil {
		mut(&cfg)
	}
	clk := &clock{t: time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)}
	logs := &bytes.Buffer{}
	st := store.NewMemory()
	s := New(cfg, st, slog.New(slog.NewJSONHandler(logs, nil)), clk.Now)
	return &env{t: t, h: s.Handler(), clk: clk, logs: logs, st: st}
}

func (e *env) do(method, path, token string, body any) (int, map[string]any) {
	e.t.Helper()
	var rd *bytes.Reader
	switch b := body.(type) {
	case nil:
		rd = bytes.NewReader(nil)
	case string:
		rd = bytes.NewReader([]byte(b))
	default:
		j, _ := json.Marshal(b)
		rd = bytes.NewReader(j)
	}
	r := httptest.NewRequest(method, path, rd)
	r.RemoteAddr = "203.0.113.77:5555"
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, r)
	out := map[string]any{}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

type device struct {
	key       *ecdsa.PrivateKey
	spki      []byte
	phantomID string
	deviceID  string
}

func newKey(t *testing.T) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spki, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	return k, spki
}

func sign(t *testing.T, k *ecdsa.PrivateKey, msg []byte) string {
	t.Helper()
	d := sha256.Sum256(msg)
	sig, err := ecdsa.SignASN1(rand.Reader, k, d[:])
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(sig)
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func (e *env) challenge(purpose, deviceID string) (string, string) {
	e.t.Helper()
	body := map[string]string{"purpose": purpose}
	if deviceID != "" {
		body["device_id"] = deviceID
	}
	code, out := e.do("POST", "/v1/challenges", "", body)
	if code != 201 {
		e.t.Fatalf("challenge: %d %v", code, out)
	}
	return out["challenge_id"].(string), out["nonce"].(string)
}

func (e *env) register() *device {
	e.t.Helper()
	k, spki := newKey(e.t)
	id, nonce := e.challenge("register", "")
	code, out := e.do("POST", "/v1/accounts", "", map[string]string{"challenge_id": id, "public_key": b64(spki), "signature": sign(e.t, k, auth.RegisterMessage(nonce, spki))})
	if code != 201 {
		e.t.Fatalf("register: %d %v", code, out)
	}
	return &device{key: k, spki: spki, phantomID: out["phantom_id"].(string), deviceID: out["device_id"].(string)}
}

func (e *env) login(d *device) string {
	e.t.Helper()
	id, nonce := e.challenge("login", d.deviceID)
	code, out := e.do("POST", "/v1/sessions", "", map[string]string{"challenge_id": id, "device_id": d.deviceID, "signature": sign(e.t, d.key, auth.LoginMessage(nonce, d.deviceID))})
	if code != 201 {
		e.t.Fatalf("login: %d %v", code, out)
	}
	return out["token"].(string)
}

func TestHappyPath(t *testing.T) {
	e := newEnv(t, nil)
	a, b := e.register(), e.register()
	if !validPhantomID(a.phantomID) || a.phantomID == b.phantomID {
		t.Fatalf("bad ids %q %q", a.phantomID, b.phantomID)
	}
	ta := e.login(a)
	code, me := e.do("GET", "/v1/me", ta, nil)
	if code != 200 || me["phantom_id"] != a.phantomID || len(me["sessions"].([]any)) != 1 {
		t.Fatalf("me: %d %v", code, me)
	}
	code, keys := e.do("GET", "/v1/accounts/"+b.phantomID+"/keys", ta, nil)
	if code != 200 {
		t.Fatalf("keys: %d %v", code, keys)
	}
	got := keys["devices"].([]any)[0].(map[string]any)
	if got["public_key"] != b64(b.spki) || got["device_id"] != b.deviceID {
		t.Fatalf("server returned a different key for B: %v", got)
	}
}

func TestRegisterRejectsBadProofs(t *testing.T) {
	e := newEnv(t, nil)
	k, spki := newKey(t)
	other, otherSPKI := newKey(t)

	// signature made by a different key
	id, nonce := e.challenge("register", "")
	if code, _ := e.do("POST", "/v1/accounts", "", map[string]string{"challenge_id": id, "public_key": b64(spki), "signature": sign(t, other, auth.RegisterMessage(nonce, spki))}); code != 401 {
		t.Fatalf("foreign signature accepted: %d", code)
	}
	// signature over a different key's hash (key substitution in transit)
	id, nonce = e.challenge("register", "")
	if code, _ := e.do("POST", "/v1/accounts", "", map[string]string{"challenge_id": id, "public_key": b64(otherSPKI), "signature": sign(t, k, auth.RegisterMessage(nonce, spki))}); code != 401 {
		t.Fatalf("substituted key accepted: %d", code)
	}
	// login-purpose signature replayed for registration
	id, nonce = e.challenge("register", "")
	if code, _ := e.do("POST", "/v1/accounts", "", map[string]string{"challenge_id": id, "public_key": b64(spki), "signature": sign(t, k, auth.LoginMessage(nonce, "x"))}); code != 401 {
		t.Fatalf("cross-purpose signature accepted: %d", code)
	}
	// unknown challenge
	if code, _ := e.do("POST", "/v1/accounts", "", map[string]string{"challenge_id": "nope", "public_key": b64(spki), "signature": sign(t, k, auth.RegisterMessage("x", spki))}); code != 401 {
		t.Fatalf("unknown challenge accepted: %d", code)
	}
}

func TestRegisterRejectsWrongKeyTypes(t *testing.T) {
	e := newEnv(t, nil)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	spki384, _ := x509.MarshalPKIXPublicKey(&p384.PublicKey)
	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	spkiRSA, _ := x509.MarshalPKIXPublicKey(&rk.PublicKey)
	_, good := newKey(t)
	trailing := append(append([]byte{}, good...), 0x00)
	for name, spki := range map[string][]byte{"p384": spki384, "rsa": spkiRSA, "garbage": []byte("hello"), "trailing-bytes": trailing, "empty": {}} {
		id, _ := e.challenge("register", "")
		code, out := e.do("POST", "/v1/accounts", "", map[string]string{"challenge_id": id, "public_key": b64(spki), "signature": b64([]byte{1})})
		if code != 400 || out["error"] != "bad_public_key" {
			t.Errorf("%s: got %d %v", name, code, out)
		}
	}
}

func TestChallengeIsSingleUseAndExpires(t *testing.T) {
	e := newEnv(t, nil)
	k, spki := newKey(t)
	id, nonce := e.challenge("register", "")
	req := map[string]string{"challenge_id": id, "public_key": b64(spki), "signature": sign(t, k, auth.RegisterMessage(nonce, spki))}
	if code, _ := e.do("POST", "/v1/accounts", "", req); code != 201 {
		t.Fatalf("first use: %d", code)
	}
	if code, _ := e.do("POST", "/v1/accounts", "", req); code != 401 {
		t.Fatalf("replayed registration accepted: %d", code)
	}

	// a failed attempt also burns the challenge
	d := e.register()
	id, nonce = e.challenge("login", d.deviceID)
	if code, _ := e.do("POST", "/v1/sessions", "", map[string]string{"challenge_id": id, "device_id": d.deviceID, "signature": b64([]byte{0x30, 0x00})}); code != 401 {
		t.Fatalf("bad signature accepted: %d", code)
	}
	if code, _ := e.do("POST", "/v1/sessions", "", map[string]string{"challenge_id": id, "device_id": d.deviceID, "signature": sign(t, d.key, auth.LoginMessage(nonce, d.deviceID))}); code != 401 {
		t.Fatalf("challenge reusable after a failed attempt: %d", code)
	}

	// expiry
	id, nonce = e.challenge("login", d.deviceID)
	e.clk.Add(61 * time.Second)
	if code, _ := e.do("POST", "/v1/sessions", "", map[string]string{"challenge_id": id, "device_id": d.deviceID, "signature": sign(t, d.key, auth.LoginMessage(nonce, d.deviceID))}); code != 401 {
		t.Fatalf("expired challenge accepted: %d", code)
	}
}

func TestLoginRejectsImpostorsUniformly(t *testing.T) {
	e := newEnv(t, nil)
	a, b := e.register(), e.register()

	// B signs a challenge issued for A's device
	id, nonce := e.challenge("login", a.deviceID)
	c1, o1 := e.do("POST", "/v1/sessions", "", map[string]string{"challenge_id": id, "device_id": a.deviceID, "signature": sign(t, b.key, auth.LoginMessage(nonce, a.deviceID))})
	// challenge issued for B, presented for A
	id, nonce = e.challenge("login", b.deviceID)
	c2, o2 := e.do("POST", "/v1/sessions", "", map[string]string{"challenge_id": id, "device_id": a.deviceID, "signature": sign(t, b.key, auth.LoginMessage(nonce, a.deviceID))})
	// device that does not exist
	ghost := strings.Repeat("ab", 16)
	id, nonce = e.challenge("login", ghost)
	c3, o3 := e.do("POST", "/v1/sessions", "", map[string]string{"challenge_id": id, "device_id": ghost, "signature": sign(t, b.key, auth.LoginMessage(nonce, ghost))})
	// register-purpose challenge used for login
	id, nonce = e.challenge("register", "")
	c4, o4 := e.do("POST", "/v1/sessions", "", map[string]string{"challenge_id": id, "device_id": a.deviceID, "signature": sign(t, a.key, auth.LoginMessage(nonce, a.deviceID))})

	for i, c := range []int{c1, c2, c3, c4} {
		if c != 401 {
			t.Errorf("case %d: status %d", i+1, c)
		}
	}
	for i, o := range []map[string]any{o1, o2, o3, o4} {
		if o["error"] != "invalid_credentials" {
			t.Errorf("case %d leaks the failure reason: %v", i+1, o)
		}
	}
}

func TestDuplicateKeyRejected(t *testing.T) {
	e := newEnv(t, nil)
	k, spki := newKey(t)
	for i, want := range []int{201, 409} {
		id, nonce := e.challenge("register", "")
		code, _ := e.do("POST", "/v1/accounts", "", map[string]string{"challenge_id": id, "public_key": b64(spki), "signature": sign(t, k, auth.RegisterMessage(nonce, spki))})
		if code != want {
			t.Fatalf("attempt %d: got %d want %d", i, code, want)
		}
	}
}

func TestAuthRequiredAndSessionLifecycle(t *testing.T) {
	e := newEnv(t, nil)
	d := e.register()
	for _, p := range [][2]string{{"GET", "/v1/me"}, {"DELETE", "/v1/me"}, {"PUT", "/v1/me/push-token"}, {"DELETE", "/v1/sessions/current"}, {"GET", "/v1/accounts/" + d.phantomID + "/keys"}} {
		if code, _ := e.do(p[0], p[1], "", nil); code != 401 {
			t.Errorf("%s %s without token: %d", p[0], p[1], code)
		}
		if code, _ := e.do(p[0], p[1], "made-up-token", nil); code != 401 {
			t.Errorf("%s %s with fake token: %d", p[0], p[1], code)
		}
	}
	t1, t2 := e.login(d), e.login(d)
	if code, _ := e.do("DELETE", "/v1/sessions/current", t1, nil); code != 204 {
		t.Fatalf("logout: %d", code)
	}
	if code, _ := e.do("GET", "/v1/me", t1, nil); code != 401 {
		t.Fatalf("token alive after logout: %d", code)
	}
	if code, _ := e.do("GET", "/v1/me", t2, nil); code != 200 {
		t.Fatalf("other session died: %d", code)
	}
	e.clk.Add(31 * 24 * time.Hour)
	if code, _ := e.do("GET", "/v1/me", t2, nil); code != 401 {
		t.Fatalf("expired token accepted: %d", code)
	}
}

func TestCannotDeleteAnotherDevicesSession(t *testing.T) {
	e := newEnv(t, nil)
	a, b := e.register(), e.register()
	ta, tb := e.login(a), e.login(b)
	_, me := e.do("GET", "/v1/me", tb, nil)
	bSession := me["sessions"].([]any)[0].(map[string]any)["session_id"].(string)
	if code, _ := e.do("DELETE", "/v1/sessions/"+bSession, ta, nil); code != 404 {
		t.Fatalf("A deleted B's session: %d", code)
	}
	if code, _ := e.do("GET", "/v1/me", tb, nil); code != 200 {
		t.Fatalf("B's session gone: %d", code)
	}
}

func TestSessionCapEvictsOldest(t *testing.T) {
	e := newEnv(t, func(c *Config) { c.MaxSessionsPerDevice = 2 })
	d := e.register()
	t1 := e.login(d)
	e.clk.Add(time.Second)
	t2 := e.login(d)
	e.clk.Add(time.Second)
	t3 := e.login(d)
	if code, _ := e.do("GET", "/v1/me", t1, nil); code != 401 {
		t.Fatalf("oldest session survived: %d", code)
	}
	for _, tok := range []string{t2, t3} {
		if code, _ := e.do("GET", "/v1/me", tok, nil); code != 200 {
			t.Fatalf("recent session evicted: %d", code)
		}
	}
}

func TestDeleteAccountRemovesEverything(t *testing.T) {
	e := newEnv(t, nil)
	a, b := e.register(), e.register()
	ta, tb := e.login(a), e.login(b)
	if code, _ := e.do("PUT", "/v1/me/push-token", ta, map[string]string{"token": "fcm-token"}); code != 204 {
		t.Fatalf("push token: %d", code)
	}
	if code, _ := e.do("DELETE", "/v1/me", ta, nil); code != 204 {
		t.Fatalf("delete: %d", code)
	}
	if code, _ := e.do("GET", "/v1/me", ta, nil); code != 401 {
		t.Fatalf("token alive after account deletion: %d", code)
	}
	if code, _ := e.do("GET", "/v1/accounts/"+a.phantomID+"/keys", tb, nil); code != 404 {
		t.Fatalf("key still served after deletion: %d", code)
	}
	id, nonce := e.challenge("login", a.deviceID)
	if code, _ := e.do("POST", "/v1/sessions", "", map[string]string{"challenge_id": id, "device_id": a.deviceID, "signature": sign(t, a.key, auth.LoginMessage(nonce, a.deviceID))}); code != 401 {
		t.Fatalf("deleted device can log in: %d", code)
	}
	// the key is free again: the same phone can start over with a new id
	id, nonce = e.challenge("register", "")
	if code, _ := e.do("POST", "/v1/accounts", "", map[string]string{"challenge_id": id, "public_key": b64(a.spki), "signature": sign(t, a.key, auth.RegisterMessage(nonce, a.spki))}); code != 201 {
		t.Fatalf("re-registration after deletion: %d", code)
	}
}

func TestRateLimits(t *testing.T) {
	e := newEnv(t, func(c *Config) { c.ChallengesPerMinute = 3; c.KeyLookupsPerMinute = 2 })
	for i := 0; i < 3; i++ {
		e.challenge("register", "")
	}
	if code, _ := e.do("POST", "/v1/challenges", "", map[string]string{"purpose": "register"}); code != 429 {
		t.Fatalf("challenge limit not enforced: %d", code)
	}
	e.clk.Add(61 * time.Second)
	d := e.register()
	tok := e.login(d)
	for i, want := range []int{200, 200, 429} {
		if code, _ := e.do("GET", "/v1/accounts/"+d.phantomID+"/keys", tok, nil); code != want {
			t.Fatalf("lookup %d: got %d want %d", i, code, want)
		}
	}
}

func TestInputHardening(t *testing.T) {
	e := newEnv(t, nil)
	if code, out := e.do("POST", "/v1/challenges", "", `{"purpose":"register","admin":true}`); code != 400 {
		t.Errorf("unknown field accepted: %d %v", code, out)
	}
	if code, _ := e.do("POST", "/v1/challenges", "", `{"purpose":"register"}{"purpose":"login"}`); code != 400 {
		t.Errorf("trailing JSON accepted: %d", code)
	}
	if code, _ := e.do("POST", "/v1/challenges", "", `{"purpose":"root"}`); code != 400 {
		t.Errorf("unknown purpose accepted: %d", code)
	}
	if code, _ := e.do("POST", "/v1/challenges", "", `{"purpose":"login"}`); code != 400 {
		t.Errorf("login challenge without device accepted: %d", code)
	}
	big := `{"purpose":"` + strings.Repeat("a", 20_000) + `"}`
	if code, _ := e.do("POST", "/v1/challenges", "", big); code != 413 {
		t.Errorf("oversized body: %d", code)
	}
	d := e.register()
	tok := e.login(d)
	for _, bad := range []string{"PH-0000-0000-000", "ph-0000-0000-0000", "PH-0000-0000-000U", "XX-0000-0000-0000"} {
		if code, _ := e.do("GET", "/v1/accounts/"+bad+"/keys", tok, nil); code != 400 {
			t.Errorf("malformed id %q: %d", bad, code)
		}
	}
}

func TestLogsCarryNoIdentifiers(t *testing.T) {
	e := newEnv(t, nil)
	a, b := e.register(), e.register()
	tok := e.login(a)
	e.do("GET", "/v1/accounts/"+b.phantomID+"/keys", tok, nil)
	e.do("PUT", "/v1/me/push-token", tok, map[string]string{"token": "fcm-secret-token"})
	logs := e.logs.String()
	if !strings.Contains(logs, "/v1/accounts/{phantom_id}/keys") {
		t.Fatalf("expected route patterns in logs, got:\n%s", logs)
	}
	for name, secret := range map[string]string{"client address": "203.0.113.77", "phantom id A": a.phantomID, "phantom id B": b.phantomID, "device id": a.deviceID, "session token": tok, "push token": "fcm-secret-token", "public key": b64(a.spki)} {
		if strings.Contains(logs, secret) {
			t.Errorf("%s appears in the server log", name)
		}
	}
}

func TestStoreNeverHoldsTheToken(t *testing.T) {
	e := newEnv(t, nil)
	d := e.register()
	tok := e.login(d)
	sess, err := e.st.SessionsByDevice(t.Context(), d.deviceID)
	if err != nil || len(sess) != 1 {
		t.Fatal(err)
	}
	if sess[0].TokenHash != sha256.Sum256([]byte(tok)) {
		t.Fatal("stored value is not the hash of the token")
	}
}

func TestConcurrentRegistrations(t *testing.T) {
	e := newEnv(t, nil)
	var wg sync.WaitGroup
	ids := make(chan string, 40)
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d := e.register()
			e.login(d)
			ids <- d.phantomID
		}()
	}
	wg.Wait()
	close(ids)
	seen := map[string]bool{}
	for id := range ids {
		if seen[id] {
			t.Fatalf("duplicate phantom id %s", id)
		}
		seen[id] = true
	}
}
