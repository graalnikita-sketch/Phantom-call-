package auth

import (
	"encoding/base64"
	"testing"
)

// These vectors are duplicated in the Android unit tests
// (android/app/src/test/.../ProtocolMessagesTest.kt). Both sides must build
// byte-identical strings, otherwise no signature will ever verify.
const vectorSPKI = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEa9d7Fg2qU0XKO0bqV8t0v1cF0rA0Yx2m1sQy2t7lW8b4v6dA3Q1s0qkq2b7j3bq0g6q2z9m1v4yQ1b0v3c5n9g=="

func TestMessageVectors(t *testing.T) {
	spki, err := base64.StdEncoding.DecodeString(vectorSPKI)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(RegisterMessage("bm9uY2U", spki)), "PHANTOM-CALL/v1/register\nbm9uY2U\n95065dc48bb6ee14034b8add4956460f7750e0db3f9152ead9edbd0be4857133"; got != want {
		t.Fatalf("register message\n got %q\nwant %q", got, want)
	}
	if got, want := string(LoginMessage("bm9uY2U", "00112233445566778899aabbccddeeff")), "PHANTOM-CALL/v1/login\nbm9uY2U\n00112233445566778899aabbccddeeff"; got != want {
		t.Fatalf("login message\n got %q\nwant %q", got, want)
	}
}
