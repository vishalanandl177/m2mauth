package apikey

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/vishalanandl177/m2mauth"
)

func TestValidator_Valid(t *testing.T) {
	store := NewMapStore(map[string]*m2mauth.Claims{
		"sk_test_valid": {Subject: "svc-orders", Scopes: []string{"read:data"}},
	})

	v, err := New(WithStore(store))
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	req.Header.Set("X-API-Key", "sk_test_valid")

	claims, err := v.Validate(context.Background(), req)
	if err != nil {
		t.Fatalf("Validate error: %v", err)
	}
	if claims.Subject != "svc-orders" {
		t.Errorf("expected subject svc-orders, got %q", claims.Subject)
	}
}

func TestValidator_InvalidKey(t *testing.T) {
	store := NewMapStore(map[string]*m2mauth.Claims{
		"sk_test_valid": {Subject: "svc-orders"},
	})
	v, _ := New(WithStore(store))

	req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	req.Header.Set("X-API-Key", "sk_test_invalid")

	_, err := v.Validate(context.Background(), req)
	if !errors.Is(err, m2mauth.ErrInvalidAPIKey) {
		t.Errorf("expected ErrInvalidAPIKey, got %v", err)
	}
}

func TestValidator_MissingKey(t *testing.T) {
	store := NewMapStore(map[string]*m2mauth.Claims{})
	v, _ := New(WithStore(store))

	req := httptest.NewRequest(http.MethodGet, "/api/data", nil)

	_, err := v.Validate(context.Background(), req)
	if !errors.Is(err, m2mauth.ErrMissingAPIKey) {
		t.Errorf("expected ErrMissingAPIKey, got %v", err)
	}
}

func TestValidator_CustomHeader(t *testing.T) {
	store := NewMapStore(map[string]*m2mauth.Claims{
		"mykey": {Subject: "svc-test"},
	})
	v, _ := New(WithStore(store), WithHeaderName("Authorization"))

	req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	req.Header.Set("Authorization", "mykey")

	claims, err := v.Validate(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if claims.Subject != "svc-test" {
		t.Errorf("expected svc-test, got %q", claims.Subject)
	}
}

func TestNew_RequiresStore(t *testing.T) {
	_, err := New()
	if err == nil {
		t.Fatal("expected error when no store is set")
	}
}
