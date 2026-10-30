package authn_test

import (
	"context"
	"errors"

	"connectrpc.com/connect/v2"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/protoc-contrib/auth-go/authn"
)

var _ = Describe("Refusals", func() {
	var (
		verify *verifier
		seen   []error
		mapped = connect.NewError(connect.CodeUnauthenticated, "mapped")
		mapper = func(why error) error {
			seen = append(seen, why)
			return mapped
		}
	)

	BeforeEach(func() {
		verify = &verifier{}
		seen = nil
	})

	Describe("Unauthenticated", func() {
		It("is Unauthenticated with a fixed message, and why as the cause", func() {
			why := errors.New("why")

			err := authn.Unauthenticated(why)

			Expect(err.Code()).To(Equal(connect.CodeUnauthenticated))
			Expect(err.Message()).To(Equal("The request is not authenticated"))
			Expect(errors.Is(err, why)).To(BeTrue())
		})
	})

	When("there is no mapper", func() {
		It("carries ErrCredentialsMissing as the cause of a request without a credential", func() {
			_, _, err := call(authn.NewInterceptor(verify), nil)

			Expect(errors.Is(err, authn.ErrCredentialsMissing)).To(BeTrue())
		})

		It("carries ErrCredentialsInvalid, and the verifier's error, as the cause of a credential it refused", func() {
			reason := errors.New("token is expired")
			verify.err = reason

			_, _, err := call(authn.NewInterceptor(verify), map[string]string{"Authorization": "Bearer token"})

			Expect(errors.Is(err, authn.ErrCredentialsInvalid)).To(BeTrue())
			Expect(errors.Is(err, reason)).To(BeTrue())
		})
	})

	When("there is a mapper", func() {
		It("is given ErrCredentialsMissing for a request without a credential, and its error is the answer", func() {
			_, reached, err := call(authn.NewInterceptor(verify, authn.WithErrorMapper(mapper)), nil)

			Expect(errors.Is(err, mapped)).To(BeTrue())
			Expect(reached).To(BeFalse())
			Expect(seen).To(HaveLen(1))
			Expect(errors.Is(seen[0], authn.ErrCredentialsMissing)).To(BeTrue())
		})

		It("is given an error that wraps ErrCredentialsInvalid and the verifier's for a credential it refused", func() {
			reason := errors.New("token is expired")
			verify.err = reason

			_, _, err := call(authn.NewInterceptor(verify, authn.WithErrorMapper(mapper)), map[string]string{"Authorization": "Bearer token"})

			Expect(errors.Is(err, mapped)).To(BeTrue())
			Expect(seen).To(HaveLen(1))
			Expect(errors.Is(seen[0], authn.ErrCredentialsInvalid)).To(BeTrue())
			Expect(errors.Is(seen[0], reason)).To(BeTrue())
		})

		It("is given ErrCredentialsMissing for a call without call info", func() {
			next := func(context.Context, connect.Spec, connect.ServerStream) error { return nil }

			err := authn.NewInterceptor(verify, authn.WithErrorMapper(mapper))(next)(context.Background(), connect.Spec{}, nil)

			Expect(errors.Is(err, mapped)).To(BeTrue())
			Expect(errors.Is(seen[0], authn.ErrCredentialsMissing)).To(BeTrue())
		})

		It("falls back to Unauthenticated when it returns nil", func() {
			nothing := authn.WithErrorMapper(func(error) error { return nil })

			_, _, err := call(authn.NewInterceptor(verify, nothing), nil)

			Expect(connect.CodeOf(err)).To(Equal(connect.CodeUnauthenticated))
			Expect(errors.Is(err, authn.ErrCredentialsMissing)).To(BeTrue())
		})
	})
})
