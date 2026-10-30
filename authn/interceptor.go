package authn

import (
	"context"
	"fmt"
	"strings"

	"connectrpc.com/connect/v2"
)

const (
	defaultHeader = "Authorization"
	bearer        = "Bearer "
)

type options struct {
	header string
	mapper func(err error) error
}

// Option configures [NewInterceptor].
type Option func(*options)

// WithHeader reads the credential from the named request header, in place of
// Authorization. Cloudflare Access, for one, sends its token in
// Cf-Access-Jwt-Assertion.
func WithHeader(name string) Option {
	return func(o *options) {
		o.header = name
	}
}

// WithErrorMapper answers a refused request with the error mapper returns for
// why, in place of [Unauthenticated]: [ErrCredentialsMissing] for a request
// without a credential, and an error that wraps [ErrCredentialsInvalid] and the
// verifier's own for one whose credential was not accepted. A service gives the
// refusal its own shape this way, with the details and the domain of its
// errors, and keeps the library out of them. A mapper that returns nil falls
// back to [Unauthenticated].
func WithErrorMapper(mapper func(err error) error) Option {
	return func(o *options) {
		o.mapper = mapper
	}
}

// NewInterceptor returns a [connect.ServerInterceptor] that refuses an RPC
// whose credential is missing or is not proved by verifier, with
// [Unauthenticated] unless [WithErrorMapper] says otherwise. An RPC it lets
// through carries the caller's [Identity], which [FromContext] returns.
//
// The credential is the value of the Authorization header, less a leading
// "Bearer " in any case, unless [WithHeader] names another header. Install it
// before every interceptor that reads or validates a message, so that a caller
// that is not authenticated learns nothing about them.
func NewInterceptor(verifier Verifier, opts ...Option) connect.ServerInterceptor {
	cfg := options{header: defaultHeader}
	for _, opt := range opts {
		opt(&cfg)
	}
	return func(next connect.ServerFunc) connect.ServerFunc {
		return func(ctx context.Context, spec connect.Spec, stream connect.ServerStream) error {
			info, ok := connect.CallInfoForServerContext(ctx)
			if !ok {
				return cfg.refuse(ErrCredentialsMissing)
			}
			credential := credentialOf(info.RequestHeader().Get(cfg.header))
			if credential == "" {
				return cfg.refuse(ErrCredentialsMissing)
			}
			id, err := verifier.Verify(ctx, credential)
			if err != nil {
				return cfg.refuse(fmt.Errorf("%w: %w", ErrCredentialsInvalid, err))
			}
			return next(NewContext(ctx, id), spec, stream)
		}
	}
}

// refuse answers a request that is refused for why.
func (o options) refuse(why error) error {
	if o.mapper != nil {
		if err := o.mapper(why); err != nil {
			return err
		}
	}
	return Unauthenticated(why)
}

// credentialOf is value less a leading "Bearer ", whose case is not significant.
func credentialOf(value string) string {
	if len(value) > len(bearer) && strings.EqualFold(value[:len(bearer)], bearer) {
		return value[len(bearer):]
	}
	return value
}
