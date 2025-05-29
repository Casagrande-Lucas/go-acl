package acl

type PolicyFunc func(user *User, resource any) bool
