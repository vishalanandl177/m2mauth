package ginauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/vishalanandl177/m2mauth"
)

func init() {
	gin.SetMode(gin.TestMode)
}

// mockValidator is a simple Validator for testing.
type mockValidator struct {
	claims *m2mauth.Claims
	err    error
}

func (m *mockValidator) Validate(_ context.Context, _ *http.Request) (*m2mauth.Claims, error) {
	return m.claims, m.err
}

func TestRequireAuth_Success(t *testing.T) {
	claims := &m2mauth.Claims{Subject: "svc-test", Scopes: []string{"read:data"}}
	v := &mockValidator{claims: claims}

	r := gin.New()
	r.Use(RequireAuth(v))
	r.GET("/api/data", func(c *gin.Context) {
		got := ClaimsFromContext(c)
		if got == nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "no claims"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"subject": got.Subject})
	})

	req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var body map[string]string
	json.Unmarshal(rec.Body.Bytes(), &body)
	if body["subject"] != "svc-test" {
		t.Errorf("expected subject svc-test, got %q", body["subject"])
	}
}

func TestRequireAuth_Failure(t *testing.T) {
	v := &mockValidator{err: m2mauth.ErrMissingToken}

	r := gin.New()
	r.Use(RequireAuth(v))
	r.GET("/api/data", func(c *gin.Context) {
		t.Error("handler should not be called on auth failure")
	})

	req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}

	var body map[string]string
	json.Unmarshal(rec.Body.Bytes(), &body)
	if body["error"] != "unauthorized" {
		t.Errorf("expected error unauthorized, got %q", body["error"])
	}
}

func TestRequireAuth_CustomErrorHandler(t *testing.T) {
	v := &mockValidator{err: m2mauth.ErrInvalidToken}

	customHandler := func(c *gin.Context, err error) {
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "custom_denied"})
	}

	r := gin.New()
	r.Use(RequireAuth(v, WithErrorHandler(customHandler)))
	r.GET("/api/data", func(c *gin.Context) {
		t.Error("handler should not be called on auth failure")
	})

	req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rec.Code)
	}
}

func TestClaimsFromContext_Missing(t *testing.T) {
	r := gin.New()
	r.GET("/test", func(c *gin.Context) {
		claims := ClaimsFromContext(c)
		if claims != nil {
			t.Error("expected nil claims when middleware not used")
		}
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
}

func TestRequireAuth_ClaimsInRequestContext(t *testing.T) {
	claims := &m2mauth.Claims{Subject: "svc-ctx-test"}
	v := &mockValidator{claims: claims}

	r := gin.New()
	r.Use(RequireAuth(v))
	r.GET("/api/data", func(c *gin.Context) {
		// Verify claims are also available via standard m2mauth.ClaimsFromContext
		got, ok := m2mauth.ClaimsFromContext(c.Request.Context())
		if !ok || got.Subject != "svc-ctx-test" {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "missing from request context"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"subject": got.Subject})
	})

	req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
}
