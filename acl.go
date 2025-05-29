package acl

type Authorizer struct {
	store    Store
	policies map[string]PolicyFunc
}

func NewAuthorizer(store Store) *Authorizer {
	return &Authorizer{
		store:    store,
		policies: make(map[string]PolicyFunc),
	}
}

func (a *Authorizer) HasPermission(user *User, permission string) bool {
	for _, role := range user.Roles {
		if _, ok := role.Permissions[permission]; ok {
			return true
		}
	}
	return false
}

func (a *Authorizer) RegisterPolicy(action string, fn PolicyFunc) {
	a.policies[action] = fn
}

func (a *Authorizer) Can(user *User, action string, resource any) bool {
	if fn, ok := a.policies[action]; ok {
		return fn(user, resource)
	}
	return a.HasPermission(user, action)
}
