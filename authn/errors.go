package authn

import (
	"errors"

	"connectrpc.com/connect/v2"
)

// Why a request is refused, which [NewInterceptor] hands to the mapper of
// [WithErrorMapper] and, without one, carries as the cause of the refusal. Test
// for them with [errors.Is].
var (
	// ErrCredentialsMissing is why a request that carries no credential is refused.
	ErrCredentialsMissing = errors.New("authn: the request carries no credential")
	// ErrCredentialsInvalid is why a request whose credential the verifier did
	// not accept is refused. The error wraps the verifier's own, which says
	// why: an expired token, a signature that does not match.
	ErrCredentialsInvalid = errors.New("authn: the credential was not accepted")
)

// Unauthenticated returns the answer to a refused request when there is no
// mapper: [connect.CodeUnauthenticated] with a fixed message, and why as the
// cause, for the error interceptor to log; it never reaches the client. The
// authz interceptor answers a call without a caller in the same way.
func Unauthenticated(why error) *connect.Error {
	return connect.NewError(connect.CodeUnauthenticated, "The request is not authenticated").WithCause(why)
}
