package ratelimit

import (
	"fmt"
	"testing"
	"time"
)

func TestWindowAndFullTable(t *testing.T) {
	now := time.Unix(0, 0)
	l := New(2, time.Minute, 3, func() time.Time { return now })
	if !l.Allow("a") || !l.Allow("a") || l.Allow("a") {
		t.Fatal("limit of 2 not enforced")
	}
	l.Allow("b")
	l.Allow("c")
	if l.Allow("d") {
		t.Fatal("full table must refuse new keys")
	}
	now = now.Add(time.Minute)
	if !l.Allow("d") || !l.Allow("a") {
		t.Fatal("window did not reset")
	}
	for i := 0; i < 100; i++ {
		l.Allow(fmt.Sprint(i))
	}
	if len(l.m) > 3 {
		t.Fatalf("table grew to %d", len(l.m))
	}
}
