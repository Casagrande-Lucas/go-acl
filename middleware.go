package acl

import (
	"encoding/json"
	"net/http"
)

func RBACMiddleware(authz *Authorizer, perm string, userFromRequest func(r *http.Request) *User) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user := userFromRequest(r)
			if user == nil || !authz.HasPermission(user, perm) {
				w.WriteHeader(http.StatusForbidden)
				json.NewEncoder(w).Encode(map[string]string{"error": "forbidden"})
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func PolicyMiddleware(authz *Authorizer, action string, userFromRequest func(r *http.Request) *User, resourceFromRequest func(r *http.Request) any) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user := userFromRequest(r)
			resource := resourceFromRequest(r)
			if user == nil || !authz.Can(user, action, resource) {
				w.WriteHeader(http.StatusForbidden)
				json.NewEncoder(w).Encode(map[string]string{"error": "forbidden"})
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
