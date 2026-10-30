package authz_test

import (
	"context"
	"errors"

	"connectrpc.com/connect/v2"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/protoc-contrib/auth-go/authn"
	"github.com/protoc-contrib/auth-go/authz"
)

var _ = Describe("Refusals", func() {
	var (
		ctx    context.Context
		auth   *authorizer
		seen   []error
		mapped = connect.NewError(connect.CodePermissionDenied, "mapped")
		mapper = func(why error) error {
			seen = append(seen, why)
			return mapped
		}
		nothing = func(error) error { return nil }
		get     = func() *stream { return &stream{request: message("GetBookRequest", `name: "books/1"`)} }
	)

	BeforeEach(func() {
		ctx = authn.NewContext(context.Background(), authn.Identity{Subject: "alice"})
		auth = &authorizer{}
		seen = nil
	})

	Describe("PermissionDeniedError", func() {
		It("names the caller, the procedure and the resource, for the log", func() {
			err := &authz.PermissionDeniedError{Request: authz.Request{Subject: "alice", Procedure: procedure, Resource: "books/1"}}

			Expect(err.Error()).To(Equal(`authz: "alice" may not call /test.v1.LibraryService/GetBook on "books/1"`))
		})
	})

	When("there is no mapper", func() {
		It("carries a *PermissionDeniedError, holding the request, as the cause of a request that is not allowed", func() {
			err := call(ctx, auth, get(), empty("GetBookRequest"))

			var denied *authz.PermissionDeniedError
			Expect(errors.As(err, &denied)).To(BeTrue())
			Expect(denied.Request).To(Equal(authz.Request{Subject: "alice", Procedure: procedure, Resource: "books/1"}))
		})

		It("carries ErrAuthorizationFailed, and the authorizer's error, as the cause of one it could not decide", func() {
			reason := errors.New("store is down")
			auth.err = reason

			err := call(ctx, auth, get(), empty("GetBookRequest"))

			Expect(errors.Is(err, authz.ErrAuthorizationFailed)).To(BeTrue())
			Expect(errors.Is(err, reason)).To(BeTrue())
		})

		It("carries ErrCredentialsMissing as the cause of a call without a caller", func() {
			err := call(context.Background(), auth, get(), empty("GetBookRequest"))

			Expect(errors.Is(err, authn.ErrCredentialsMissing)).To(BeTrue())
		})
	})

	When("there is a mapper", func() {
		opt := authz.WithErrorMapper(mapper)

		It("is given a *PermissionDeniedError holding the request, and its error is the answer", func() {
			err := call(ctx, auth, get(), empty("GetBookRequest"), opt)

			Expect(errors.Is(err, mapped)).To(BeTrue())
			Expect(seen).To(HaveLen(1))
			var denied *authz.PermissionDeniedError
			Expect(errors.As(seen[0], &denied)).To(BeTrue())
			Expect(denied.Request).To(Equal(authz.Request{Subject: "alice", Procedure: procedure, Resource: "books/1"}))
		})

		It("is given a *PermissionDeniedError that names no resource for a message that is not a protobuf message", func() {
			var text string

			err := call(ctx, auth, &stream{}, &text, opt)

			Expect(errors.Is(err, mapped)).To(BeTrue())
			var denied *authz.PermissionDeniedError
			Expect(errors.As(seen[0], &denied)).To(BeTrue())
			Expect(denied.Request).To(Equal(authz.Request{Subject: "alice", Procedure: procedure}))
		})

		It("is given an error that wraps ErrAuthorizationFailed and the authorizer's", func() {
			reason := errors.New("store is down")
			auth.err = reason

			err := call(ctx, auth, get(), empty("GetBookRequest"), opt)

			Expect(errors.Is(err, mapped)).To(BeTrue())
			Expect(errors.Is(seen[0], authz.ErrAuthorizationFailed)).To(BeTrue())
			Expect(errors.Is(seen[0], reason)).To(BeTrue())
		})

		It("is given ErrCredentialsMissing for a call without a caller", func() {
			err := call(context.Background(), auth, get(), empty("GetBookRequest"), opt)

			Expect(errors.Is(err, mapped)).To(BeTrue())
			Expect(errors.Is(seen[0], authn.ErrCredentialsMissing)).To(BeTrue())
		})

		It("falls back to the default when it returns nil", func() {
			err := call(ctx, auth, get(), empty("GetBookRequest"), authz.WithErrorMapper(nothing))

			Expect(connect.CodeOf(err)).To(Equal(connect.CodePermissionDenied))
			var denied *authz.PermissionDeniedError
			Expect(errors.As(err, &denied)).To(BeTrue())
		})
	})
})
