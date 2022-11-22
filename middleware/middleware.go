package middleware

import (
	"context"
)

var UserClaimsCtxKey = &contextKey{"user"}

type contextKey struct {
	name string
}

func init() {

}

func RoleAllowed(ctx context.Context, allowedServiceRoles []string, allowedUserRoles []string) (bool, string) {
	//read environment for roles in cookie or header and compare to allowed roles
	//if allowed, return true
	return true, ""
}
