package store

import (
	"regexp"
	"strings"
	"sync"
	"time"
)

type Memory struct {
	mu    sync.RWMutex
	items map[string][]byte
	exps  map[string]time.Time
}

func NewMemory() *Memory {
	return &Memory{
		items: make(map[string][]byte),
		exps:  make(map[string]time.Time),
	}
}

func (s *Memory) ClearExp() error {
	s.mu.Lock()
	for k, e := range s.exps {
		if !e.IsZero() && !e.After(time.Now()) {
			delete(s.items, k)
			delete(s.exps, k)
		}
	}
	s.mu.Unlock()
	return nil
}

func (s *Memory) Set(key string, value []byte, exp time.Duration) error {
	s.mu.Lock()
	s.items[key] = value
	if exp > 0 {
		s.exps[key] = time.Now().Add(exp)
	} else {
		delete(s.exps, key)
	}
	s.mu.Unlock()
	return nil
}

func (s *Memory) Get(key string) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	exp := s.exps[key]
	if !exp.IsZero() && !exp.After(time.Now()) {
		return nil, nil
	}

	return s.items[key], nil
}

func (s *Memory) Del(key string) (bool, error) {
	s.mu.Lock()
	_, ok := s.items[key]
	delete(s.items, key)
	delete(s.exps, key)
	s.mu.Unlock()
	return ok, nil
}

func (s *Memory) SetExp(key string, exp time.Duration) (bool, error) {
	s.mu.Lock()
	_, ok := s.items[key]
	s.exps[key] = time.Now().Add(exp)
	s.mu.Unlock()
	return ok, nil
}

func (s *Memory) Exp(key string) (time.Duration, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.items[key]
	if !ok {
		return 0, false, nil
	}

	exp, ok := s.exps[key]
	if !ok {
		return 0, true, nil
	}

	expIn := time.Until(exp)
	if expIn < 0 {
		return 0, false, nil
	}

	return expIn, true, nil
}

func (s *Memory) Keys(pattern string) ([]string, error) {
	if !strings.Contains(pattern, "*") {
		pattern += "*"
	}

	pattern = "^" + strings.ReplaceAll(pattern, "*", ".*") + "$"
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	var r []string
	for k := range s.items {
		if re.MatchString(k) {
			r = append(r, k)
		}
	}
	return r, nil
}

func (s *Memory) Scan(cursor int, pattern string, count int) (int, []string, error) {
	return 0, nil, nil
}
