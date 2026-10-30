package authz

import (
	"context"
	"errors"
	"fmt"

	"connectrpc.com/connect/v2"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/protoc-contrib/auth-go/authn"
)

type options struct {
	mapper func(err error) error
}

// Option configures [NewInterceptor].
type Option func(*options)

// WithErrorMapper answers a refused request with the error mapper returns for
// why, in place of the default: a *[DeniedError] for a request the Authorizer
// did not allow, an error that wraps [ErrAuthorizationFailed] and the
// Authorizer's own for one it could not decide, and [authn.ErrCredentialsMissing]
// for a call without a caller. A service gives the refusal its own shape this
// way, with the details and the domain of its errors, and names the resource
// from the request a *DeniedError holds. A mapper that returns nil falls back
// to the default.
func WithErrorMapper(mapper func(err error) error) Option {
	return func(o *options) {
		o.mapper = mapper
	}
}

// NewInterceptor returns a [connect.ServerInterceptor] that asks authorizer
// about every message an RPC receives, and refuses the RPC it does not allow
// with [connect.CodePermissionDenied] and a fixed message, unless
// [WithErrorMapper] says otherwise. An Authorizer that cannot decide is an
// internal error, never an allow; and a message that is not a protobuf message
// has no resource to name, so it is not allowed. Each carries why as its cause,
// for the error interceptor to log, and never reaches the client.
//
// The resource is in the message, which exists only once it is received, so the
// check runs in the handler's Receive and a message that is refused never
// reaches it. Install the interceptor after authn's, which puts the caller in
// the context — a call without one is [connect.CodeUnauthenticated] — and
// before every interceptor that validates or fills in a message, so a caller
// that is not allowed learns nothing about them, and the Authorizer sees the
// request as the client sent it.
func NewInterceptor(authorizer Authorizer, opts ...Option) connect.ServerInterceptor {
	var cfg options
	for _, opt := range opts {
		opt(&cfg)
	}
	return func(next connect.ServerFunc) connect.ServerFunc {
		return func(ctx context.Context, spec connect.Spec, stream connect.ServerStream) error {
			caller, ok := authn.FromContext(ctx)
			if !ok {
				return cfg.refuse(authn.ErrCredentialsMissing)
			}
			return next(ctx, spec, &authorizedStream{ServerStream: stream, ctx: ctx, cfg: cfg, authorizer: authorizer, subject: caller.Subject, procedure: spec.Procedure})
		}
	}
}

// authorizedStream authorizes each message of one RPC, as [NewInterceptor]
// describes.
type authorizedStream struct {
	connect.ServerStream
	ctx        context.Context
	cfg        options
	authorizer Authorizer
	subject    string
	procedure  string
}

func (s *authorizedStream) Receive(message any) error {
	if err := s.ServerStream.Receive(message); err != nil {
		return err
	}
	req := Request{Subject: s.subject, Procedure: s.procedure}
	request, ok := message.(proto.Message)
	if !ok {
		return s.cfg.refuse(&DeniedError{Request: req})
	}
	req.Resource = resourceName(request)
	allowed, err := s.authorizer.Authorize(s.ctx, req)
	if err != nil {
		return s.cfg.refuse(fmt.Errorf("%w: %w", ErrAuthorizationFailed, err))
	}
	if !allowed {
		return s.cfg.refuse(&DeniedError{Request: req})
	}
	return nil
}

// refuse answers a request that is refused for why.
func (o options) refuse(why error) error {
	if o.mapper != nil {
		if err := o.mapper(why); err != nil {
			return err
		}
	}
	switch {
	case errors.Is(why, authn.ErrCredentialsMissing):
		return authn.Unauthenticated(why)
	case errors.Is(why, ErrAuthorizationFailed):
		return connect.NewError(connect.CodeInternal, "authorization failed").WithCause(why)
	default:
		return connect.NewError(connect.CodePermissionDenied, "The caller is not allowed to perform this operation").WithCause(why)
	}
}

// resourceName is the name of the resource a request names: its own name field,
// else its parent field, else — for an update, which carries the resource —
// that of the first message field that is set. A repeated or map field is not
// searched, so a batch request names none. It is "" when there is none.
func resourceName(message proto.Message) string {
	reflected := message.ProtoReflect()
	fields := reflected.Descriptor().Fields()
	for _, name := range []protoreflect.Name{"name", "parent"} {
		if field := fields.ByName(name); field != nil && field.Kind() == protoreflect.StringKind && !field.IsList() {
			return reflected.Get(field).String()
		}
	}
	for i := range fields.Len() {
		field := fields.Get(i)
		if field.Message() != nil && !field.IsList() && !field.IsMap() && reflected.Has(field) {
			if name := resourceName(reflected.Get(field).Message().Interface()); name != "" {
				return name
			}
		}
	}
	return ""
}
