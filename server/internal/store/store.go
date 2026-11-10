// Package store defines what the server persists. It deliberately has no
// place for call history, contacts, phone numbers, audio or private keys.
package store

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"
)

var (
	ErrNotFound = errors.New("store: not found")
	ErrConflict = errors.New("store: conflict")
)

type Account struct {
	PhantomID string
	CreatedAt time.Time
}

type Device struct {
	ID        string
	PhantomID string
	PublicKey []byte   // X.509 SubjectPublicKeyInfo, DER, P-256
	KeyHash   [32]byte // SHA-256 of PublicKey, unique across the service
	PushToken string
	CreatedAt time.Time
}

type Session struct {
	ID        string
	TokenHash [32]byte // SHA-256 of the bearer token; the token itself is never stored
	DeviceID  string
	PhantomID string
	CreatedAt time.Time
	ExpiresAt time.Time
}

type Store interface {
	CreateAccountWithDevice(ctx context.Context, a Account, d Device) error
	DeviceByID(ctx context.Context, id string) (Device, error)
	DevicesByAccount(ctx context.Context, phantomID string) ([]Device, error)
	SetPushToken(ctx context.Context, deviceID, token string) error
	// CreateSession stores s; if the device then has more than maxPerDevice
	// sessions the oldest ones are removed.
	CreateSession(ctx context.Context, s Session, maxPerDevice int) error
	SessionByTokenHash(ctx context.Context, h [32]byte) (Session, error)
	SessionsByDevice(ctx context.Context, deviceID string) ([]Session, error)
	DeleteSession(ctx context.Context, deviceID, sessionID string) error
	DeleteAccount(ctx context.Context, phantomID string) error
	DeleteExpiredSessions(ctx context.Context, now time.Time) (int, error)
}

// Memory is an in-process Store used for development and tests.
// Data is lost on restart.
type Memory struct {
	mu       sync.Mutex
	accounts map[string]Account
	devices  map[string]Device
	keys     map[[32]byte]string // key hash -> device id
	sessions map[[32]byte]Session
}

func NewMemory() *Memory {
	return &Memory{
		accounts: map[string]Account{},
		devices:  map[string]Device{},
		keys:     map[[32]byte]string{},
		sessions: map[[32]byte]Session{},
	}
}

func (m *Memory) CreateAccountWithDevice(_ context.Context, a Account, d Device) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.accounts[a.PhantomID]; ok {
		return ErrConflict
	}
	if _, ok := m.devices[d.ID]; ok {
		return ErrConflict
	}
	if _, ok := m.keys[d.KeyHash]; ok {
		return ErrConflict
	}
	d.PublicKey = append([]byte(nil), d.PublicKey...)
	m.accounts[a.PhantomID] = a
	m.devices[d.ID] = d
	m.keys[d.KeyHash] = d.ID
	return nil
}

func (m *Memory) DeviceByID(_ context.Context, id string) (Device, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	d, ok := m.devices[id]
	if !ok {
		return Device{}, ErrNotFound
	}
	return d, nil
}

func (m *Memory) DevicesByAccount(_ context.Context, phantomID string) ([]Device, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.accounts[phantomID]; !ok {
		return nil, ErrNotFound
	}
	var out []Device
	for _, d := range m.devices {
		if d.PhantomID == phantomID {
			out = append(out, d)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (m *Memory) SetPushToken(_ context.Context, deviceID, token string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	d, ok := m.devices[deviceID]
	if !ok {
		return ErrNotFound
	}
	d.PushToken = token
	m.devices[deviceID] = d
	return nil
}

func (m *Memory) CreateSession(_ context.Context, s Session, maxPerDevice int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.devices[s.DeviceID]; !ok {
		return ErrNotFound
	}
	if _, ok := m.sessions[s.TokenHash]; ok {
		return ErrConflict
	}
	m.sessions[s.TokenHash] = s
	var mine []Session
	for _, x := range m.sessions {
		if x.DeviceID == s.DeviceID {
			mine = append(mine, x)
		}
	}
	if maxPerDevice > 0 && len(mine) > maxPerDevice {
		sort.Slice(mine, func(i, j int) bool { return mine[i].CreatedAt.Before(mine[j].CreatedAt) })
		for _, old := range mine[:len(mine)-maxPerDevice] {
			delete(m.sessions, old.TokenHash)
		}
	}
	return nil
}

func (m *Memory) SessionByTokenHash(_ context.Context, h [32]byte) (Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[h]
	if !ok {
		return Session{}, ErrNotFound
	}
	return s, nil
}

func (m *Memory) SessionsByDevice(_ context.Context, deviceID string) ([]Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Session
	for _, s := range m.sessions {
		if s.DeviceID == deviceID {
			out = append(out, s)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}

func (m *Memory) DeleteSession(_ context.Context, deviceID, sessionID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for h, s := range m.sessions {
		if s.DeviceID == deviceID && s.ID == sessionID {
			delete(m.sessions, h)
			return nil
		}
	}
	return ErrNotFound
}

func (m *Memory) DeleteAccount(_ context.Context, phantomID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.accounts[phantomID]; !ok {
		return ErrNotFound
	}
	for h, s := range m.sessions {
		if s.PhantomID == phantomID {
			delete(m.sessions, h)
		}
	}
	for id, d := range m.devices {
		if d.PhantomID == phantomID {
			delete(m.keys, d.KeyHash)
			delete(m.devices, id)
		}
	}
	delete(m.accounts, phantomID)
	return nil
}

func (m *Memory) DeleteExpiredSessions(_ context.Context, now time.Time) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for h, s := range m.sessions {
		if !now.Before(s.ExpiresAt) {
			delete(m.sessions, h)
			n++
		}
	}
	return n, nil
}
