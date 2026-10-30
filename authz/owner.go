package authz

import (
	"context"
	"errors"
	"strings"
)

// ErrNotFound is what [Owner.OwnerOf] returns when the named resource does not
// exist.
var ErrNotFound = errors.New("authz: resource not found")

// Owner is an [Authorizer] that allows a request when the caller owns the
// resource it names, so a service whose resources each belong to one caller
// needs nothing but the owner column it already has: there is no second copy
// of who owns what to keep in sync. Swap it for a relationship store when
// resources are shared.
//
// A resource that does not exist and one that is someone else's both are
// refused, so a caller cannot find out which IDs exist. A request that names
// no resource is allowed: a top-level List or Create, which the handler scopes
// to the caller.
type Owner struct {
	// OwnerOf returns the subject that owns the named resource, or
	// [ErrNotFound]. It is asked about the root of the name, so a child such as
	// "shelves/s1/books/b1" is owned by whoever owns "shelves/s1".
	OwnerOf func(ctx context.Context, name string) (string, error)
}

// Authorize implements [Authorizer].
func (o Owner) Authorize(ctx context.Context, req Request) (bool, error) {
	if req.Resource == "" {
		return true, nil
	}
	owner, err := o.OwnerOf(ctx, root(req.Resource))
	if errors.Is(err, ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return owner == req.Subject, nil
}

// root is the first collection and ID of name: "shelves/s1/books/b1" is
// "shelves/s1".
func root(name string) string {
	parts := strings.SplitN(name, "/", 3)
	if len(parts) < 2 {
		return name
	}
	return parts[0] + "/" + parts[1]
}
