// Package ratelimit is a small in-memory fixed-window limiter. Keys (client
// addresses, session ids) live only in memory and are never logged.
package ratelimit

import (
	"sync"
	"time"
)

type entry struct {
	windowStart time.Time
	count       int
}

type Limiter struct {
	mu      sync.Mutex
	m       map[string]entry
	limit   int
	window  time.Duration
	maxKeys int
	now     func() time.Time
}

func New(limit int, window time.Duration, maxKeys int, now func() time.Time) *Limiter {
	return &Limiter{m: map[string]entry{}, limit: limit, window: window, maxKeys: maxKeys, now: now}
}

// Allow reports whether one more event for key fits in the current window.
// When the table is full of live keys it fails closed for new keys.
func (l *Limiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	e, ok := l.m[key]
	if ok && now.Sub(e.windowStart) >= l.window {
		ok = false
	}
	if !ok {
		if len(l.m) >= l.maxKeys {
			l.sweepLocked(now)
			if _, exists := l.m[key]; !exists && len(l.m) >= l.maxKeys {
				return false
			}
		}
		l.m[key] = entry{windowStart: now, count: 1}
		return l.limit >= 1
	}
	if e.count >= l.limit {
		return false
	}
	e.count++
	l.m[key] = e
	return true
}

func (l *Limiter) Sweep() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.sweepLocked(l.now())
}

func (l *Limiter) sweepLocked(now time.Time) {
	for k, e := range l.m {
		if now.Sub(e.windowStart) >= l.window {
			delete(l.m, k)
		}
	}
}
