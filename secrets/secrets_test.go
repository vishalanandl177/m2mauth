package secrets

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/vishalanandl177/m2mauth"
)

func TestEnvProvider(t *testing.T) {
	t.Setenv("M2M_CLIENT_SECRET", "super-secret")

	p := NewEnvProvider("M2M_")
	val, err := p.GetSecret(context.Background(), "CLIENT_SECRET")
	if err != nil {
		t.Fatal(err)
	}
	if val != "super-secret" {
		t.Errorf("expected super-secret, got %q", val)
	}
}

func TestEnvProvider_NotFound(t *testing.T) {
	p := NewEnvProvider("")
	_, err := p.GetSecret(context.Background(), "NONEXISTENT_KEY_12345")
	if !errors.Is(err, m2mauth.ErrSecretNotFound) {
		t.Errorf("expected ErrSecretNotFound, got %v", err)
	}
}

func TestFileProvider(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "client-secret"), []byte("file-secret\n"), 0o600)

	p := NewFileProvider(dir)
	val, err := p.GetSecret(context.Background(), "client-secret")
	if err != nil {
		t.Fatal(err)
	}
	if val != "file-secret" {
		t.Errorf("expected file-secret, got %q", val)
	}
}

func TestFileProvider_NotFound(t *testing.T) {
	p := NewFileProvider("/nonexistent")
	_, err := p.GetSecret(context.Background(), "missing")
	if !errors.Is(err, m2mauth.ErrSecretNotFound) {
		t.Errorf("expected ErrSecretNotFound, got %v", err)
	}
}

func TestStaticProvider(t *testing.T) {
	p := NewStaticProvider(map[string]string{"key": "value"})
	val, err := p.GetSecret(context.Background(), "key")
	if err != nil {
		t.Fatal(err)
	}
	if val != "value" {
		t.Errorf("expected value, got %q", val)
	}
}

func TestChain(t *testing.T) {
	p1 := NewStaticProvider(map[string]string{"a": "from-p1"})
	p2 := NewStaticProvider(map[string]string{"b": "from-p2"})
	chain := NewChain(p1, p2)

	val, err := chain.GetSecret(context.Background(), "b")
	if err != nil {
		t.Fatal(err)
	}
	if val != "from-p2" {
		t.Errorf("expected from-p2, got %q", val)
	}
}

func TestChain_AllFail(t *testing.T) {
	p1 := NewStaticProvider(map[string]string{})
	chain := NewChain(p1)
	_, err := chain.GetSecret(context.Background(), "missing")
	if !errors.Is(err, m2mauth.ErrSecretNotFound) {
		t.Errorf("expected ErrSecretNotFound, got %v", err)
	}
}
