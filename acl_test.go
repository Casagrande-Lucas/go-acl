package acl

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMemoryStore_AddRole_GetRole(t *testing.T) {
	store := NewMemoryStore()
	role := &Role{Name: "admin", Permissions: map[string]struct{}{"user:create": {}, "user:delete": {}}}
	err := store.AddRole(role)
	assert.NoError(t, err)

	got, err := store.GetRole("admin")
	assert.NoError(t, err)
	assert.Equal(t, "admin", got.Name)
	assert.Contains(t, got.Permissions, "user:create")
	assert.Contains(t, got.Permissions, "user:delete")
}

func TestMemoryStore_GetRole_NotFound(t *testing.T) {
	store := NewMemoryStore()
	_, err := store.GetRole("missing")
	assert.ErrorIs(t, err, ErrRoleNotFound)
}

func TestMemoryStore_GetUser_AddRole_AssignRoleToUser(t *testing.T) {
	store := NewMemoryStore()
	role := &Role{Name: "dev", Permissions: map[string]struct{}{"api:use": {}}}
	store.AddRole(role)
	store.users["john"] = &User{ID: "john"}

	err := store.AssignRoleToUser("john", "dev")
	assert.NoError(t, err)

	user, err := store.GetUser("john")
	assert.NoError(t, err)
	assert.Len(t, user.Roles, 1)
	assert.Equal(t, "dev", user.Roles[0].Name)
}

func TestMemoryStore_AssignRoleToUser_NotFound(t *testing.T) {
	store := NewMemoryStore()
	err := store.AssignRoleToUser("nouser", "norole")
	assert.ErrorIs(t, err, ErrUserOrRoleNotFound)
}

func TestMemoryStore_AddPermissionToRole(t *testing.T) {
	store := NewMemoryStore()
	role := &Role{Name: "qa"}
	store.AddRole(role)

	err := store.AddPermissionToRole("qa", "test:run")
	assert.NoError(t, err)

	r, _ := store.GetRole("qa")
	_, ok := r.Permissions["test:run"]
	assert.True(t, ok)
}

func TestMemoryStore_AddPermissionToRole_RoleNotFound(t *testing.T) {
	store := NewMemoryStore()
	err := store.AddPermissionToRole("missing", "some:perm")
	assert.ErrorIs(t, err, ErrRoleNotFound)
}

func TestMemoryStore_GetUser_NotFound(t *testing.T) {
	store := NewMemoryStore()
	_, err := store.GetUser("missing")
	assert.ErrorIs(t, err, ErrUserNotFound)
}

func TestAuthorizer_HasPermission(t *testing.T) {
	store := NewMemoryStore()
	role := &Role{Name: "ops", Permissions: map[string]struct{}{"api:read": {}}}
	store.AddRole(role)
	store.users["ops"] = &User{ID: "ops", Roles: []*Role{role}}
	authz := NewAuthorizer(store)

	user, _ := store.GetUser("ops")
	assert.True(t, authz.HasPermission(user, "api:read"))
	assert.False(t, authz.HasPermission(user, "api:write"))
}

func TestAuthorizer_RegisterPolicy_Allow(t *testing.T) {
	store := NewMemoryStore()
	user := &User{ID: "42"}
	store.users["42"] = user
	authz := NewAuthorizer(store)

	authz.RegisterPolicy("can_edit", func(u *User, resource any) bool {
		obj, ok := resource.(map[string]any)
		return ok && obj["owner_id"] == u.ID
	})
	resource := map[string]any{"owner_id": "42"}

	assert.True(t, authz.Can(user, "can_edit", resource))
}

func TestAuthorizer_RegisterPolicy_Deny(t *testing.T) {
	store := NewMemoryStore()
	user := &User{ID: "99"}
	store.users["99"] = user
	authz := NewAuthorizer(store)

	authz.RegisterPolicy("can_edit", func(u *User, resource any) bool {
		obj, ok := resource.(map[string]any)
		return ok && obj["owner_id"] == u.ID
	})
	resource := map[string]any{"owner_id": "42"}

	assert.False(t, authz.Can(user, "can_edit", resource))
}

func TestAuthorizer_Can_FallbackToPermission(t *testing.T) {
	store := NewMemoryStore()
	role := &Role{Name: "auditor", Permissions: map[string]struct{}{"log:read": {}}}
	store.AddRole(role)
	store.users["a"] = &User{ID: "a", Roles: []*Role{role}}
	authz := NewAuthorizer(store)

	user, _ := store.GetUser("a")
	assert.True(t, authz.Can(user, "log:read", nil))
	assert.False(t, authz.Can(user, "log:delete", nil))
}

func TestRBACMiddleware_AllowAndDeny(t *testing.T) {
	store := NewMemoryStore()
	role := &Role{Name: "api", Permissions: map[string]struct{}{"endpoint:access": {}}}
	store.AddRole(role)
	store.users["u1"] = &User{ID: "u1", Roles: []*Role{role}}
	authz := NewAuthorizer(store)

	// User extraction function for testing
	userFromRequest := func(r *http.Request) *User {
		id := r.Header.Get("X-User-ID")
		u, _ := store.GetUser(id)
		return u
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	mw := RBACMiddleware(authz, "endpoint:access", userFromRequest)(handler)

	// Test: Allow
	req1 := httptest.NewRequest("GET", "/", nil)
	req1.Header.Set("X-User-ID", "u1")
	w1 := httptest.NewRecorder()
	mw.ServeHTTP(w1, req1)
	assert.Equal(t, http.StatusOK, w1.Code)

	// Test: Deny
	req2 := httptest.NewRequest("GET", "/", nil)
	req2.Header.Set("X-User-ID", "nobody")
	w2 := httptest.NewRecorder()
	mw.ServeHTTP(w2, req2)
	assert.Equal(t, http.StatusForbidden, w2.Code)

	var resp map[string]string
	json.NewDecoder(bytes.NewReader(w2.Body.Bytes())).Decode(&resp)
	assert.Equal(t, "forbidden", resp["error"])
}

func TestPolicyMiddleware_AllowAndDeny(t *testing.T) {
	store := NewMemoryStore()
	user := &User{ID: "12"}
	store.users["12"] = user
	authz := NewAuthorizer(store)
	authz.RegisterPolicy("custom", func(u *User, resource any) bool {
		obj, ok := resource.(map[string]any)
		return ok && obj["allowed"] == true
	})

	userFromRequest := func(r *http.Request) *User {
		id := r.Header.Get("X-User-ID")
		u, _ := store.GetUser(id)
		return u
	}
	resourceFromRequest := func(r *http.Request) any {
		if r.URL.Query().Get("allow") == "true" {
			return map[string]any{"allowed": true}
		}
		return map[string]any{"allowed": false}
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	mw := PolicyMiddleware(authz, "custom", userFromRequest, resourceFromRequest)(handler)

	// Allow
	req := httptest.NewRequest("GET", "/?allow=true", nil)
	req.Header.Set("X-User-ID", "12")
	w := httptest.NewRecorder()
	mw.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	// Deny
	req2 := httptest.NewRequest("GET", "/?allow=false", nil)
	req2.Header.Set("X-User-ID", "12")
	w2 := httptest.NewRecorder()
	mw.ServeHTTP(w2, req2)
	assert.Equal(t, http.StatusForbidden, w2.Code)
}
