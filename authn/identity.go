package authn

import "context"

// Identity is who a request's credential proves the caller to be.
type Identity struct {
	// Subject is the caller's stable ID, the token's sub claim. Key what a
	// caller owns on it: an email can change, a subject does not.
	Subject string
	// Email is the caller's email, when the credential carries one.
	Email string
}

type identityKey struct{}

// NewContext returns a context that carries id.
func NewContext(ctx context.Context, id Identity) context.Context {
	return context.WithValue(ctx, identityKey{}, id)
}

// FromContext returns the caller that [NewInterceptor] authenticated, and
// false for a context it did not.
func FromContext(ctx context.Context) (Identity, bool) {
	id, ok := ctx.Value(identityKey{}).(Identity)
	return id, ok
}
