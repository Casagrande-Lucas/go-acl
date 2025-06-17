# go-acl

<img src="https://github.com/user-attachments/assets/1b863dd5-5243-41b6-ad28-f3bb7f78f817" width="640" height="320" alt="Descrição da imagem">

**Access control, roles, and permissions (RBAC + Policy/Ability) for Go APIs — maximum performance, flexibility, and decoupling.**

[![Go Reference](https://pkg.go.dev/badge/github.com/Casagrande-Lucas/go-acl.svg)](https://pkg.go.dev/github.com/Casagrande-Lucas/go-acl)

---

## Features

- **RBAC (Role-Based Access Control):** Define roles, permissions, and users dynamically.
- **Policy/Ability Pattern:** Advanced authorization logic for complex business requirements.
- **Fully Decoupled:** Pure Go, zero framework dependencies. Compatible with any HTTP stack (Gin, Gorilla, Fiber, Echo, Chi, etc.).
- **Native Middlewares:** Ready-to-use with `net/http`, easily adaptable for any framework.
- **Extensible:** Implement your own Store (in-memory, SQL, Redis, etc) and plug it in easily.

---

## Installation

```bash
go get github.com/Casagrande-Lucas/go-acl
```

---

## Overview

`go-acl` provides everything you need for robust, scalable, and reusable access control in any Go API—from monoliths to microservices.

---

## Quick Start — Pure Go (`net/http`)

```go
package main

import (
    "net/http"
    "github.com/Casagrande-Lucas/go-acl"
)

func main() {
    store := acl.NewMemoryStore()

    // Create roles and users
    adminRole := &acl.Role{Name: "admin", Permissions: map[string]struct{}{"user:create": {}, "user:delete": {}}}
    store.AddRole(adminRole)
    user := &acl.User{ID: "1", Roles: []*acl.Role{adminRole}}
    // Directly populate the user map
    store.Users()["1"] = user

    authz := acl.NewAuthorizer(store)

    // RBAC-protected route
    http.Handle("/admin", acl.RBACMiddleware(authz, "user:create", func(r *http.Request) *acl.User {
        id := r.Header.Get("X-User-ID")
        u, _ := store.GetUser(id)
        return u
    })(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.Write([]byte("admin area"))
    })))
    http.ListenAndServe(":8080", nil)
}
```

---

## Advanced Example — Policy/Ability

```go
authz.RegisterPolicy("edit_post", func(user *acl.User, resource any) bool {
    post, ok := resource.(map[string]any)
    if !ok { return false }
    return post["owner_id"] == user.ID
})

http.Handle("/post/edit", acl.PolicyMiddleware(authz, "edit_post",
    func(r *http.Request) *acl.User {
        id := r.Header.Get("X-User-ID")
        u, _ := store.GetUser(id)
        return u
    },
    func(r *http.Request) any {
        // Simulated resource fetch
        return map[string]any{"owner_id": r.Header.Get("X-User-ID")}
    },
)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    w.Write([]byte("edit permitted"))
})))
```

---

## Using with Frameworks (Gin, Gorilla, etc)

`go-acl` is pure Go and has **no direct dependencies on any web framework**.  
To integrate with frameworks like Gin or Gorilla, simply create adapters in your application.

### Example: RBAC Middleware for Gin

```go
import (
    "github.com/gin-gonic/gin"
    "github.com/Casagrande-Lucas/go-acl"
)

func RBACGinMiddleware(authz *acl.Authorizer, perm string, userFromContext func(*gin.Context) *acl.User) gin.HandlerFunc {
    return func(c *gin.Context) {
        user := userFromContext(c)
        if user == nil || !authz.HasPermission(user, perm) {
            c.AbortWithStatusJSON(403, gin.H{"error": "forbidden"})
            return
        }
        c.Next()
    }
}

// Usage
r := gin.Default()
r.GET("/admin", RBACGinMiddleware(authz, "user:create", func(c *gin.Context) *acl.User {
    id := c.GetHeader("X-User-ID")
    u, _ := store.GetUser(id)
    return u
}), func(c *gin.Context) {
    c.JSON(200, gin.H{"status": "admin ok"})
})
```

---

### Example: Policy Middleware for Gin

```go
func PolicyGinMiddleware(authz *acl.Authorizer, action string, userFromContext func(*gin.Context) *acl.User, resourceFromContext func(*gin.Context) any) gin.HandlerFunc {
    return func(c *gin.Context) {
        user := userFromContext(c)
        resource := resourceFromContext(c)
        if user == nil || !authz.Can(user, action, resource) {
            c.AbortWithStatusJSON(403, gin.H{"error": "forbidden"})
            return
        }
        c.Next()
    }
}

// Usage for editing a post (only owner can edit)
r.PUT("/post/:id/edit", PolicyGinMiddleware(
    authz,
    "edit_post",
    func(c *gin.Context) *acl.User {
        id := c.GetHeader("X-User-ID")
        u, _ := store.GetUser(id)
        return u
    },
    func(c *gin.Context) any {
        // Simulate resource load
        return map[string]any{"owner_id": c.GetHeader("X-User-ID")}
    },
), func(c *gin.Context) {
    c.JSON(200, gin.H{"status": "edit permitted"})
})
```

---

### Example: Using with Gorilla Mux

With Gorilla Mux, you can use the middleware as-is, since it follows the standard `http.Handler` interface:

```go
import (
    "github.com/gorilla/mux"
    "github.com/Casagrande-Lucas/go-acl"
    "net/http"
)

r := mux.NewRouter()
r.Handle("/admin", acl.RBACMiddleware(authz, "user:create", userFromRequest)(
    http.HandlerFunc(adminHandler),
)).Methods("GET")
```

---

> **Note:**  
> Middleware adapters for Gin, Echo, Fiber, etc. **are not provided in the core library** — this keeps the core decoupled, lightweight, and framework-agnostic.  
> Implement adapters in your application as needed.

---

## Extending: Using Custom Stores (e.g., GORM/SQL)

You can implement your own Store (SQL, Redis, etc.) by following the `Store` interface:

```go
type Store interface {
    GetUser(userID string) (*User, error)
    GetRole(roleName string) (*Role, error)
    AddRole(role *Role) error
    AssignRoleToUser(userID, roleName string) error
    AddPermissionToRole(roleName, permName string) error
}
```

---

### Quick Example: Store with GORM

```go
import (
    "gorm.io/gorm"
    "github.com/Casagrande-Lucas/go-acl"
)

// GORM Models
type User struct {
    ID    string  `gorm:"primaryKey"`
    Roles []Role  `gorm:"many2many:user_roles;"`
}
type Role struct {
    ID          string       `gorm:"primaryKey"`
    Name        string
    Permissions []Permission `gorm:"many2many:role_permissions;"`
}
type Permission struct {
    ID   string `gorm:"primaryKey"`
    Name string
}

// Implementation (minimal)
type GormStore struct { db *gorm.DB }

func (s *GormStore) GetUser(userID string) (*acl.User, error) {
    var dbUser User
    if err := s.db.Preload("Roles.Permissions").First(&dbUser, "id = ?", userID).Error; err != nil {
        return nil, err
    }
    roles := make([]*acl.Role, 0)
    for _, r := range dbUser.Roles {
        perms := map[string]struct{}{}
        for _, p := range r.Permissions {
            perms[p.Name] = struct{}{}
        }
        roles = append(roles, &acl.Role{Name: r.Name, Permissions: perms})
    }
    return &acl.User{ID: dbUser.ID, Roles: roles}, nil
}
```

**Usage with GORM (but works with PostgreSQL, MySQL, etc):**

```go
import "gorm.io/driver/sqlite"

func main() {
    db, _ := gorm.Open(sqlite.Open("acl.db"), &gorm.Config{})
    db.AutoMigrate(&User{}, &Role{}, &Permission{})

    store := &GormStore{db: db}
    authz := acl.NewAuthorizer(store)

    // Use authz as in the other examples
}
```

---

## Testing

To run unit tests (with coverage):

```bash
go test -cover ./...
```

To generate a coverage HTML report:

```bash
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

---

## Roadmap

- Native support for SQL/NoSQL stores
- Official adapters for Gin, Echo, Fiber, and other frameworks
- Auditing/logging hooks
- Advanced documentation for policies and abilities
- Multi-tenant support

---

## Contributions

Contributions are welcome!  
Please open an issue, submit a pull request, or share your feedback.

---

## Contact

Questions, suggestions, or corporate proposals?  
Contact LinkedIn [Lucas Casagrande](https://www.linkedin.com/in/lucas-casagrande-923103211/).
