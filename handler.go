package authzworkspace

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
)

// MembershipChecker authorizes a workspace permission against an out-of-band
// source (e.g. the `workspace_members` table — the Keto dual-write mirror) when
// Keto is not configured. It keeps this package free of any database dependency:
// the host supplies the closure. Returns (false, nil) for "not a member" (deny,
// not an error). permission is one of "view", "write", "manage".
type MembershipChecker func(ctx context.Context, workspace, user, permission string) (bool, error)

// HTTPHandler returns the Ory Oathkeeper remote_json adapter for the workspace
// authorization gate (mounted at /authz/workspace by whichever service hosts
// it). It reads the rule payload {user, workspace, permission}, authorizes via
// Keto (preferred) or the optional fallback, and answers with a STATUS CODE
// (200 allow / 403 deny) — Oathkeeper's remote_json authorizer keys on the
// status, not the body (Keto's own /check returns 200+{allowed} which
// remote_json cannot read).
//
// Semantics (preserved from the original egent-lobehub adapter):
//   - empty workspace → personal scope → 200 (pREST scopes to user_id, ws NULL);
//   - Keto enabled → CheckWorkspace;
//   - Keto disabled + fallback set → fallback;
//   - Keto disabled + no fallback → 403 (fail closed);
//   - any error → 403 (fail closed).
func HTTPHandler(client *Client, fallback MembershipChecker) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			User       string `json:"user"`
			Workspace  string `json:"workspace"`
			Permission string `json:"permission"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.User == "" {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		if body.Workspace == "" {
			w.WriteHeader(http.StatusOK) // personal scope
			return
		}

		perm := body.Permission
		if perm != "view" && perm != "write" && perm != "manage" {
			perm = "view"
		}

		var (
			allowed bool
			err     error
		)
		switch {
		case client != nil && client.Enabled():
			allowed, err = client.CheckWorkspace(r.Context(), body.Workspace, body.User, perm)
		case fallback != nil:
			allowed, err = fallback(r.Context(), body.Workspace, body.User, perm)
		default:
			http.Error(w, "forbidden", http.StatusForbidden) // fail closed
			return
		}
		if err != nil {
			slog.Error("authzworkspace: check failed", "err", err)
			http.Error(w, "authz error", http.StatusForbidden) // fail closed
			return
		}
		if !allowed {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusOK)
	}
}
