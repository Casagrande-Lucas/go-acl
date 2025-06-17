package acl

import "errors"

type Store interface {
	CreateUser(user *User) error
	GetUser(userID string) (*User, error)
	GetRole(roleName string) (*Role, error)
	AddRole(role *Role) error
	AssignRoleToUser(userID, roleName string) error
	AddPermissionToRole(roleName, permName string) error
}

type MemoryStore struct {
	users map[string]*User
	roles map[string]*Role
}

var (
	ErrUserNotFound       = errors.New("user not found")
	ErrRoleNotFound       = errors.New("role not found")
	ErrUserOrRoleNotFound = errors.New("user or role not found")
)

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		users: make(map[string]*User),
		roles: make(map[string]*Role),
	}
}

func (s *MemoryStore) CreateUser(user *User) error {
	s.users[user.ID] = user
	return nil
}

func (s *MemoryStore) GetUser(userID string) (*User, error) {
	user, ok := s.users[userID]
	if !ok {
		return nil, ErrUserNotFound
	}
	return user, nil
}

func (s *MemoryStore) GetRole(roleName string) (*Role, error) {
	role, ok := s.roles[roleName]
	if !ok {
		return nil, ErrRoleNotFound
	}
	return role, nil
}

func (s *MemoryStore) AddRole(role *Role) error {
	s.roles[role.Name] = role
	return nil
}

func (s *MemoryStore) AssignRoleToUser(userID, roleName string) error {
	user, uok := s.users[userID]
	role, rok := s.roles[roleName]
	if !uok || !rok {
		return ErrUserOrRoleNotFound
	}
	user.Roles = append(user.Roles, role)
	return nil
}

func (s *MemoryStore) AddPermissionToRole(roleName, permName string) error {
	role, ok := s.roles[roleName]
	if !ok {
		return ErrRoleNotFound
	}
	if role.Permissions == nil {
		role.Permissions = make(map[string]struct{})
	}
	role.Permissions[permName] = struct{}{}
	return nil
}
