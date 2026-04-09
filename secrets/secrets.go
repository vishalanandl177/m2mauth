// Package secrets provides SecretProvider implementations for retrieving
// secrets from environment variables, files, and HashiCorp Vault.
package secrets

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/vishalanandl177/m2mauth"
)

// EnvProvider reads secrets from environment variables.
type EnvProvider struct {
	prefix string
}

// NewEnvProvider creates a provider that reads from environment variables.
// If prefix is non-empty, it's prepended to the key (e.g., prefix "M2M_"
// and key "CLIENT_SECRET" reads "M2M_CLIENT_SECRET").
func NewEnvProvider(prefix string) *EnvProvider {
	return &EnvProvider{prefix: prefix}
}

func (p *EnvProvider) GetSecret(_ context.Context, key string) (string, error) {
	envKey := p.prefix + key
	val := os.Getenv(envKey)
	if val == "" {
		return "", fmt.Errorf("%w: env var %q not set", m2mauth.ErrSecretNotFound, envKey)
	}
	return strings.TrimSpace(val), nil
}

// FileProvider reads secrets from files, one secret per file.
// This is common with Kubernetes-mounted secrets.
type FileProvider struct {
	basePath string
}

// NewFileProvider creates a provider that reads secrets from files under basePath.
// The key is used as the filename: basePath/key.
func NewFileProvider(basePath string) *FileProvider {
	return &FileProvider{basePath: basePath}
}

func (p *FileProvider) GetSecret(_ context.Context, key string) (string, error) {
	path := filepath.Join(p.basePath, key)
	// Prevent path traversal: ensure resolved path stays within basePath.
	absPath, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("m2mauth/secrets: resolve path: %w", err)
	}
	absBase, err := filepath.Abs(p.basePath)
	if err != nil {
		return "", fmt.Errorf("m2mauth/secrets: resolve base: %w", err)
	}
	if !strings.HasPrefix(absPath, absBase+string(filepath.Separator)) && absPath != absBase {
		return "", fmt.Errorf("m2mauth/secrets: path traversal detected in key %q", key)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf("%w: file %q", m2mauth.ErrSecretNotFound, path)
		}
		return "", fmt.Errorf("m2mauth/secrets: read file %q: %w", path, err)
	}
	return strings.TrimSpace(string(data)), nil
}

// StaticProvider returns a fixed set of secrets. Useful for testing.
type StaticProvider struct {
	secrets map[string]string
}

// NewStaticProvider creates a provider with pre-configured key-value pairs.
func NewStaticProvider(secrets map[string]string) *StaticProvider {
	return &StaticProvider{secrets: secrets}
}

func (p *StaticProvider) GetSecret(_ context.Context, key string) (string, error) {
	val, ok := p.secrets[key]
	if !ok {
		return "", fmt.Errorf("%w: key %q", m2mauth.ErrSecretNotFound, key)
	}
	return val, nil
}

// Chain tries multiple providers in order, returning the first successful result.
type Chain struct {
	providers []m2mauth.SecretProvider
}

// NewChain creates a provider that tries each provider in order.
func NewChain(providers ...m2mauth.SecretProvider) *Chain {
	return &Chain{providers: providers}
}

func (c *Chain) GetSecret(ctx context.Context, key string) (string, error) {
	for _, p := range c.providers {
		val, err := p.GetSecret(ctx, key)
		if err == nil {
			return val, nil
		}
	}
	return "", fmt.Errorf("%w: key %q not found in any provider", m2mauth.ErrSecretNotFound, key)
}
