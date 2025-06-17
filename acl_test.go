package acl

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMemoryStore_CreateUser(t *testing.T) {
	store := NewMemoryStore()
	user := &User{ID: "alice"}
	err := store.CreateUser(user)
	require.NoError(t, err)

	got, err := store.GetUser("alice")
	require.NoError(t, err)
	assert.Equal(t, "alice", got.ID)
}

func TestMemoryStore_AddRole_GetRole(t *testing.T) {
	store := NewMemoryStore()
	role := &Role{Name: "admin", Permissions: map[string]struct{}{"user:create": {}, "user:delete": {}}}
	require.NoError(t, store.AddRole(role))

	got, err := store.GetRole("admin")
	require.NoError(t, err)
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
	require.NoError(t, store.AddRole(role))

	user := &User{ID: "john"}
	require.NoError(t, store.CreateUser(user))

	err := store.AssignRoleToUser("john", "dev")
	require.NoError(t, err)

	user, err = store.GetUser("john")
	require.NoError(t, err)
	assert.Len(t, user.Roles, 1)

	found := false
	for _, r := range user.Roles {
		if r.Name == "dev" {
			found = true
			break
		}
	}
	assert.True(t, found, "role 'dev' should be assigned to user")
}

func TestMemoryStore_AssignRoleToUser_NotFound(t *testing.T) {
	store := NewMemoryStore()
	err := store.AssignRoleToUser("nouser", "norole")
	assert.ErrorIs(t, err, ErrUserOrRoleNotFound)
}

func TestMemoryStore_AddPermissionToRole(t *testing.T) {
	store := NewMemoryStore()
	role := &Role{Name: "qa"}
	require.NoError(t, store.AddRole(role))

	err := store.AddPermissionToRole("qa", "test:run")
	require.NoError(t, err)

	r, err := store.GetRole("qa")
	require.NoError(t, err)
	assert.Contains(t, r.Permissions, "test:run")
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
	require.NoError(t, store.AddRole(role))

	user := &User{ID: "ops", Roles: []*Role{role}}
	require.NoError(t, store.CreateUser(user))

	authz := NewAuthorizer(store)

	user, err := store.GetUser("ops")
	require.NoError(t, err)
	assert.True(t, authz.HasPermission(user, "api:read"))
	assert.False(t, authz.HasPermission(user, "api:write"))
}

func TestAuthorizer_RegisterPolicy_Allow(t *testing.T) {
	store := NewMemoryStore()
	user := &User{ID: "42"}
	require.NoError(t, store.CreateUser(user))

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
	require.NoError(t, store.CreateUser(user))

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
	require.NoError(t, store.AddRole(role))

	user := &User{ID: "a", Roles: []*Role{role}}
	require.NoError(t, store.CreateUser(user))

	authz := NewAuthorizer(store)

	user, err := store.GetUser("a")
	require.NoError(t, err)
	assert.True(t, authz.Can(user, "log:read", nil))
	assert.False(t, authz.Can(user, "log:delete", nil))
}

func TestRBACMiddleware_Allow(t *testing.T) {
	store := NewMemoryStore()
	role := &Role{Name: "api", Permissions: map[string]struct{}{"endpoint:access": {}}}
	require.NoError(t, store.AddRole(role))

	user := &User{ID: "u1", Roles: []*Role{role}}
	require.NoError(t, store.CreateUser(user))

	authz := NewAuthorizer(store)

	userFromRequest := func(r *http.Request) *User {
		id := r.Header.Get("X-User-ID")
		u, _ := store.GetUser(id)
		return u
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	mw := RBACMiddleware(authz, "endpoint:access", userFromRequest)(handler)

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-User-ID", "u1")
	w := httptest.NewRecorder()

	mw.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestRBACMiddleware_Deny(t *testing.T) {
	store := NewMemoryStore()
	authz := NewAuthorizer(store)

	userFromRequest := func(r *http.Request) *User {
		id := r.Header.Get("X-User-ID")
		u, _ := store.GetUser(id)
		return u
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	mw := RBACMiddleware(authz, "endpoint:access", userFromRequest)(handler)

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-User-ID", "nobody")
	w := httptest.NewRecorder()

	mw.ServeHTTP(w, req)
	assert.Equal(t, http.StatusForbidden, w.Code)

	var resp map[string]string
	err := json.NewDecoder(bytes.NewReader(w.Body.Bytes())).Decode(&resp)
	require.NoError(t, err)
	assert.Equal(t, "forbidden", resp["error"])
}

func TestPolicyMiddleware_Allow(t *testing.T) {
	store := NewMemoryStore()
	user := &User{ID: "12"}
	require.NoError(t, store.CreateUser(user))

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

	req := httptest.NewRequest("GET", "/?allow=true", nil)
	req.Header.Set("X-User-ID", "12")
	w := httptest.NewRecorder()

	mw.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestPolicyMiddleware_Deny(t *testing.T) {
	store := NewMemoryStore()
	user := &User{ID: "12"}
	require.NoError(t, store.CreateUser(user))

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

	req := httptest.NewRequest("GET", "/?allow=false", nil)
	req.Header.Set("X-User-ID", "12")
	w := httptest.NewRecorder()

	mw.ServeHTTP(w, req)
	assert.Equal(t, http.StatusForbidden, w.Code)

	var resp map[string]string
	err := json.NewDecoder(bytes.NewReader(w.Body.Bytes())).Decode(&resp)
	require.NoError(t, err)
	assert.Equal(t, "forbidden", resp["error"])
}
