package authz

import "context"

// Request is what an RPC asks to do, as the interceptor reads it.
type Request struct {
	// Subject is the caller's stable ID, from authn.
	Subject string
	// Procedure is the leading-slash RPC path, such as
	// "/acme.v1.LibraryService/GetBook".
	Procedure string
	// Resource is the full AIP name the request holds in its name field, in its
	// nested resource's name, or in its parent field, such as
	// "users/u1/shelves/s1". It is empty when the request names none: a List
	// or a Create at the top level, which the handler scopes to the caller.
	Resource string
}

// Authorizer reports whether a request may proceed. It returns an error only
// when it cannot decide, such as a store that is down, which the interceptor
// answers as an internal error and never as an allow.
type Authorizer interface {
	Authorize(ctx context.Context, req Request) (bool, error)
}
