package authzworkspace_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yudaprama/authzworkspace"
)

func do(h http.HandlerFunc, body string) int {
	r := httptest.NewRequest(http.MethodPost, "/authz/workspace", strings.NewReader(body))
	w := httptest.NewRecorder()
	h(w, r)
	return w.Code
}

func TestHTTPHandler_BadBodyAndEmptyUser(t *testing.T) {
	h := authzworkspace.HTTPHandler(nil, nil)
	if got := do(h, `not json`); got != http.StatusForbidden {
		t.Errorf("bad json: got %d, want 403", got)
	}
	if got := do(h, `{"workspace":"w1","permission":"view"}`); got != http.StatusForbidden {
		t.Errorf("empty user: got %d, want 403", got)
	}
}

func TestHTTPHandler_PersonalScopeAllowed(t *testing.T) {
	// Empty workspace = personal scope → 200 even with no client/fallback.
	h := authzworkspace.HTTPHandler(nil, nil)
	if got := do(h, `{"user":"u1","workspace":"","permission":"view"}`); got != http.StatusOK {
		t.Errorf("personal scope: got %d, want 200", got)
	}
}

func TestHTTPHandler_NoKetoNoFallbackFailsClosed(t *testing.T) {
	h := authzworkspace.HTTPHandler(nil, nil)
	if got := do(h, `{"user":"u1","workspace":"w1","permission":"view"}`); got != http.StatusForbidden {
		t.Errorf("fail-closed: got %d, want 403", got)
	}
}

func TestHTTPHandler_FallbackPaths(t *testing.T) {
	allow := func(context.Context, string, string, string) (bool, error) { return true, nil }
	deny := func(context.Context, string, string, string) (bool, error) { return false, nil }
	boom := func(context.Context, string, string, string) (bool, error) { return false, context.DeadlineExceeded }

	if got := do(authzworkspace.HTTPHandler(nil, allow), `{"user":"u1","workspace":"w1","permission":"write"}`); got != http.StatusOK {
		t.Errorf("fallback allow: got %d, want 200", got)
	}
	if got := do(authzworkspace.HTTPHandler(nil, deny), `{"user":"u1","workspace":"w1","permission":"write"}`); got != http.StatusForbidden {
		t.Errorf("fallback deny: got %d, want 403", got)
	}
	if got := do(authzworkspace.HTTPHandler(nil, boom), `{"user":"u1","workspace":"w1","permission":"write"}`); got != http.StatusForbidden {
		t.Errorf("fallback error: got %d, want 403 (fail closed)", got)
	}
}

func TestHTTPHandler_KetoEnabledTakesPrecedence(t *testing.T) {
	// A Keto stub that allows; the fallback would DENY — verifies Keto wins when enabled.
	keto := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"allowed":true}`))
	}))
	defer keto.Close()

	client := authzworkspace.New(keto.URL, keto.URL)
	deny := func(context.Context, string, string, string) (bool, error) { return false, nil }
	if got := do(authzworkspace.HTTPHandler(client, deny), `{"user":"u1","workspace":"w1","permission":"view"}`); got != http.StatusOK {
		t.Errorf("keto-allow precedence: got %d, want 200", got)
	}
}
