package oauth2

import (
	"context"
	"sync"
	"time"

	"github.com/vishalanandl177/m2mauth"
)

// tokenCache provides thread-safe caching with single-flight refresh.
type tokenCache struct {
	mu     sync.RWMutex
	token  *m2mauth.Token
	buffer time.Duration // refresh this much before actual expiry

	// refreshMu ensures only one goroutine refreshes at a time.
	refreshMu sync.Mutex
}

func newTokenCache(buffer time.Duration) *tokenCache {
	return &tokenCache{buffer: buffer}
}

// get returns the cached token if it's still valid (accounting for the buffer).
func (tc *tokenCache) get() *m2mauth.Token {
	tc.mu.RLock()
	defer tc.mu.RUnlock()

	if tc.token == nil {
		return nil
	}
	if time.Now().After(tc.token.ExpiresAt.Add(-tc.buffer)) {
		return nil
	}
	return tc.token
}

// refresh fetches a new token using the provided function, ensuring only
// one concurrent refresh happens (double-check locking pattern).
func (tc *tokenCache) refresh(ctx context.Context, fetch func(ctx context.Context) (*m2mauth.Token, error)) (*m2mauth.Token, error) {
	tc.refreshMu.Lock()
	defer tc.refreshMu.Unlock()

	// Double-check: another goroutine may have refreshed while we waited.
	if tok := tc.get(); tok != nil {
		return tok, nil
	}

	tok, err := fetch(ctx)
	if err != nil {
		return nil, err
	}

	tc.mu.Lock()
	tc.token = tok
	tc.mu.Unlock()

	return tok, nil
}

// clear removes the cached token.
func (tc *tokenCache) clear() {
	tc.mu.Lock()
	tc.token = nil
	tc.mu.Unlock()
}
