package authn_test

import (
	"context"
	"errors"

	"connectrpc.com/connect/v2"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/protoc-contrib/auth-go/authn"
)

const procedure = "/acme.v1.LibraryService/GetBook"

// verifier records the credentials it is asked about, and answers with what it
// was given.
type verifier struct {
	identity    authn.Identity
	err         error
	credentials []string
}

func (v *verifier) Verify(_ context.Context, credential string) (authn.Identity, error) {
	v.credentials = append(v.credentials, credential)
	return v.identity, v.err
}

// call serves one RPC with the request headers through a server that has only
// interceptor, and reports what its handler saw: the caller it read from the
// context, and whether it ran at all.
func call(interceptor connect.ServerInterceptor, headers map[string]string) (caller authn.Identity, reached bool, err error) {
	server := connect.NewServer(interceptor)
	server.Register(connect.Method{
		Spec: connect.Spec{Procedure: procedure, StreamType: connect.StreamTypeUnary},
		Handler: func(ctx context.Context, _ connect.Spec, _ connect.ServerStream) error {
			caller, _ = authn.FromContext(ctx)
			reached = true
			return nil
		},
	})
	info := &connect.CallInfo{}
	for key, value := range headers {
		info.RequestHeader().Set(key, value)
	}
	err = server.Call(context.Background(), procedure, info, nil)
	return caller, reached, err
}

var _ = Describe("Interceptor", func() {
	var (
		verify *verifier
		alice  = authn.Identity{Subject: "alice", Email: "alice@example.com"}
	)

	BeforeEach(func() {
		verify = &verifier{identity: alice}
	})

	DescribeTable("reads the credential of the Authorization header",
		func(value, credential string) {
			caller, reached, err := call(authn.NewInterceptor(verify), map[string]string{"Authorization": value})
			Expect(err).NotTo(HaveOccurred())
			Expect(reached).To(BeTrue())
			Expect(caller).To(Equal(alice))
			Expect(verify.credentials).To(Equal([]string{credential}))
		},
		Entry("after Bearer", "Bearer token", "token"),
		Entry("after bearer, in any case", "bearer token", "token"),
		Entry("as it is, without a scheme", "token", "token"),
		Entry("with nothing after Bearer, as it is", "Bearer ", "Bearer "),
	)

	It("reads the credential from the header it is given, and from no other", func() {
		interceptor := authn.NewInterceptor(verify, authn.WithHeader("Cf-Access-Jwt-Assertion"))

		caller, reached, err := call(interceptor, map[string]string{"Cf-Access-Jwt-Assertion": "token"})
		Expect(err).NotTo(HaveOccurred())
		Expect(reached).To(BeTrue())
		Expect(caller).To(Equal(alice))
		Expect(verify.credentials).To(Equal([]string{"token"}))

		_, reached, err = call(interceptor, map[string]string{"Authorization": "Bearer token"})
		Expect(connect.CodeOf(err)).To(Equal(connect.CodeUnauthenticated))
		Expect(reached).To(BeFalse())
	})

	When("the request carries no credential", func() {
		It("is unauthenticated, and neither the verifier nor the handler is reached", func() {
			_, reached, err := call(authn.NewInterceptor(verify), nil)

			Expect(connect.CodeOf(err)).To(Equal(connect.CodeUnauthenticated))
			Expect(reached).To(BeFalse())
			Expect(verify.credentials).To(BeEmpty())
		})
	})

	When("the verifier does not accept the credential", func() {
		It("is unauthenticated with a fixed message, and the reason as the cause", func() {
			reason := errors.New("token is expired")
			verify.err = reason

			_, reached, err := call(authn.NewInterceptor(verify), map[string]string{"Authorization": "Bearer token"})

			var cerr *connect.Error
			Expect(errors.As(err, &cerr)).To(BeTrue())
			Expect(cerr.Code()).To(Equal(connect.CodeUnauthenticated))
			Expect(cerr.Message()).To(Equal("The request is not authenticated"))
			Expect(errors.Is(err, reason)).To(BeTrue())
			Expect(reached).To(BeFalse())
		})
	})

	When("the call carries no call info", func() {
		It("is unauthenticated", func() {
			reached := false
			next := func(context.Context, connect.Spec, connect.ServerStream) error {
				reached = true
				return nil
			}

			err := authn.NewInterceptor(verify)(next)(context.Background(), connect.Spec{}, nil)

			Expect(connect.CodeOf(err)).To(Equal(connect.CodeUnauthenticated))
			Expect(reached).To(BeFalse())
			Expect(verify.credentials).To(BeEmpty())
		})
	})
})
