package acl

type Role struct {
	ID          string
	Name        string
	Permissions map[string]struct{}
}

type Permission struct {
	Name string
}

type User struct {
	ID    string
	Roles []*Role
}
