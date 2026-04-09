package apikey

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/vishalanandl177/m2mauth"
)

func BenchmarkAPIKeyValidate(b *testing.B) {
	store := NewMapStore(map[string]*m2mauth.Claims{
		"sk_live_key_001": {Subject: "svc-orders", Scopes: []string{"read:data"}},
		"sk_live_key_002": {Subject: "svc-analytics", Scopes: []string{"read:data"}},
		"sk_live_key_003": {Subject: "svc-admin", Scopes: []string{"admin"}},
	})
	v, _ := New(WithStore(store))
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
		req.Header.Set("X-API-Key", "sk_live_key_001")
		_, err := v.Validate(ctx, req)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkAPIKeyValidateParallel(b *testing.B) {
	store := NewMapStore(map[string]*m2mauth.Claims{
		"sk_live_key_001": {Subject: "svc-orders", Scopes: []string{"read:data"}},
		"sk_live_key_002": {Subject: "svc-analytics", Scopes: []string{"read:data"}},
		"sk_live_key_003": {Subject: "svc-admin", Scopes: []string{"admin"}},
	})
	v, _ := New(WithStore(store))
	ctx := context.Background()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
			req.Header.Set("X-API-Key", "sk_live_key_002")
			_, err := v.Validate(ctx, req)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}
