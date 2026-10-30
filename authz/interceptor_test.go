package authz_test

import (
	"context"
	"errors"
	"io"

	"connectrpc.com/connect/v2"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"google.golang.org/protobuf/proto"

	"github.com/protoc-contrib/auth-go/authn"
	"github.com/protoc-contrib/auth-go/authz"
)

const procedure = "/test.v1.LibraryService/GetBook"

// authorizer records what it is asked, and answers with what it was given.
type authorizer struct {
	allow    bool
	err      error
	requests []authz.Request
}

func (a *authorizer) Authorize(_ context.Context, req authz.Request) (bool, error) {
	a.requests = append(a.requests, req)
	return a.allow, a.err
}

// verifierOf is an authn.Verifier that proves every credential to be its identity.
type verifierOf authn.Identity

func (v verifierOf) Verify(context.Context, string) (authn.Identity, error) {
	return authn.Identity(v), nil
}

// stream delivers one request to the handler, or the error it was given.
type stream struct {
	request proto.Message
	err     error
}

func (s *stream) Receive(message any) error {
	if s.err != nil {
		return s.err
	}
	if dst, ok := message.(proto.Message); ok {
		proto.Merge(dst, s.request)
	}
	return nil
}

func (s *stream) SendHeaders() error { return nil }

func (s *stream) Send(any) error { return nil }

// call serves one RPC through a server that has only the interceptor. The
// handler receives one message into received, and reports what Receive said.
func call(ctx context.Context, authorizer authz.Authorizer, in *stream, received any, opts ...authz.Option) error {
	server := connect.NewServer(authz.NewInterceptor(authorizer, opts...))
	server.Register(connect.Method{
		Spec: connect.Spec{Procedure: procedure, StreamType: connect.StreamTypeUnary},
		Handler: func(_ context.Context, _ connect.Spec, stream connect.ServerStream) error {
			return stream.Receive(received)
		},
	})
	return server.Call(ctx, procedure, &connect.CallInfo{}, in)
}

var _ = Describe("Interceptor", func() {
	var (
		ctx  context.Context
		auth *authorizer
	)

	BeforeEach(func() {
		ctx = authn.NewContext(context.Background(), authn.Identity{Subject: "alice"})
		auth = &authorizer{allow: true}
	})

	When("the authorizer allows the request", func() {
		It("asks it about the caller, the procedure and the resource, and delivers the message", func() {
			request := message("GetBookRequest", `name: "books/1"`)
			received := empty("GetBookRequest")

			err := call(ctx, auth, &stream{request: request}, received)

			Expect(err).NotTo(HaveOccurred())
			Expect(auth.requests).To(Equal([]authz.Request{{Subject: "alice", Procedure: procedure, Resource: "books/1"}}))
			Expect(proto.Equal(received, request)).To(BeTrue())
		})
	})

	When("the authorizer refuses the request", func() {
		It("is permission denied with a fixed message", func() {
			auth.allow = false

			err := call(ctx, auth, &stream{request: message("GetBookRequest", `name: "books/1"`)}, empty("GetBookRequest"))

			var cerr *connect.Error
			Expect(errors.As(err, &cerr)).To(BeTrue())
			Expect(cerr.Code()).To(Equal(connect.CodePermissionDenied))
			Expect(cerr.Message()).To(Equal("The caller is not allowed to perform this operation"))
		})
	})

	When("the authorizer cannot decide", func() {
		It("is internal, never an allow, with the reason as the cause", func() {
			reason := errors.New("store is down")
			auth.err = reason

			err := call(ctx, auth, &stream{request: message("GetBookRequest", `name: "books/1"`)}, empty("GetBookRequest"))

			var cerr *connect.Error
			Expect(errors.As(err, &cerr)).To(BeTrue())
			Expect(cerr.Code()).To(Equal(connect.CodeInternal))
			Expect(cerr.Message()).To(Equal("authorization failed"))
			Expect(errors.Is(err, reason)).To(BeTrue())
		})
	})

	When("no caller was authenticated", func() {
		It("is unauthenticated, and neither the authorizer nor the handler is reached", func() {
			reached := false
			server := connect.NewServer(authz.NewInterceptor(auth))
			server.Register(connect.Method{
				Spec: connect.Spec{Procedure: procedure, StreamType: connect.StreamTypeUnary},
				Handler: func(context.Context, connect.Spec, connect.ServerStream) error {
					reached = true
					return nil
				},
			})

			err := server.Call(context.Background(), procedure, &connect.CallInfo{}, &stream{})

			Expect(connect.CodeOf(err)).To(Equal(connect.CodeUnauthenticated))
			Expect(auth.requests).To(BeEmpty())
			Expect(reached).To(BeFalse())
		})
	})

	When("it follows authn's interceptor", func() {
		It("asks the authorizer about the caller that interceptor authenticated", func() {
			verify := verifierOf(authn.Identity{Subject: "carol"})
			server := connect.NewServer(authn.NewInterceptor(verify), authz.NewInterceptor(auth))
			server.Register(connect.Method{
				Spec: connect.Spec{Procedure: procedure, StreamType: connect.StreamTypeUnary},
				Handler: func(_ context.Context, _ connect.Spec, stream connect.ServerStream) error {
					return stream.Receive(empty("GetBookRequest"))
				},
			})
			info := &connect.CallInfo{}
			info.RequestHeader().Set("Authorization", "Bearer token")

			err := server.Call(context.Background(), procedure, info, &stream{request: message("GetBookRequest", `name: "books/1"`)})

			Expect(err).NotTo(HaveOccurred())
			Expect(auth.requests).To(Equal([]authz.Request{{Subject: "carol", Procedure: procedure, Resource: "books/1"}}))
		})
	})

	When("the stream has no message to give", func() {
		It("returns what the stream returned, without asking the authorizer", func() {
			err := call(ctx, auth, &stream{err: io.EOF}, empty("GetBookRequest"))

			Expect(err).To(MatchError(io.EOF))
			Expect(auth.requests).To(BeEmpty())
		})
	})

	When("the message is not a protobuf message", func() {
		It("is permission denied, without asking the authorizer", func() {
			var text string

			err := call(ctx, auth, &stream{}, &text)

			Expect(connect.CodeOf(err)).To(Equal(connect.CodePermissionDenied))
			Expect(auth.requests).To(BeEmpty())
		})
	})

	DescribeTable("names the resource of a request by",
		func(name, text, resource string) {
			err := call(ctx, auth, &stream{request: message(name, text)}, empty(name))

			Expect(err).NotTo(HaveOccurred())
			Expect(auth.requests).To(HaveLen(1))
			Expect(auth.requests[0].Resource).To(Equal(resource))
		},
		Entry("its name, as a get does", "GetBookRequest", `name: "books/1"`, "books/1"),
		Entry("its parent, as a list does", "ListBooksRequest", `parent: "shelves/s1" page_size: 10`, "shelves/s1"),
		Entry("the name of the resource it carries, as an update does", "UpdateBookRequest", `book { name: "books/1" title: "Dune" }`, "books/1"),
		Entry("nothing, when it names none", "ListBooksRequest", `page_size: 10`, ""),
		Entry("nothing, when the resource it carries is unset", "UpdateBookRequest", ``, ""),
		Entry("nothing, when the resource it carries is unnamed", "UpdateBookRequest", `book { title: "Dune" }`, ""),
		Entry("nothing, when it has no name field", "CountRequest", `count: 3`, ""),
		Entry("nothing, when its name is not a string", "NumberedRequest", `name: 3`, ""),
		Entry("nothing, for the books of a batch", "BatchGetBooksRequest", `books { name: "books/1" } books { name: "books/2" }`, ""),
		Entry("nothing, for a map of books", "BatchGetBooksRequest", `by_name { key: "a" value { name: "books/1" } }`, ""),
	)
})
