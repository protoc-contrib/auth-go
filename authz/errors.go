package authz

import (
	"errors"
	"fmt"
)

// ErrAuthorizationFailed is why a request is refused when the [Authorizer]
// could not decide. The error wraps the Authorizer's own.
var ErrAuthorizationFailed = errors.New("authz: the authorizer could not decide")

// DeniedError is why a request is refused when the [Authorizer] did not allow
// it. It holds the request, so a mapper can name the resource it was about.
// Its text names the caller and the resource, for the log; it never reaches the
// client.
type DeniedError struct {
	Request Request
}

func (e *DeniedError) Error() string {
	return fmt.Sprintf("authz: %q may not call %s on %q", e.Request.Subject, e.Request.Procedure, e.Request.Resource)
}
