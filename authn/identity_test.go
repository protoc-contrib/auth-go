package authn_test

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/protoc-contrib/auth-go/authn"
)

var _ = Describe("Identity", func() {
	It("is not in a context that was not authenticated", func() {
		_, ok := authn.FromContext(context.Background())
		Expect(ok).To(BeFalse())
	})

	It("is returned from the context that carries it", func() {
		id := authn.Identity{Subject: "u1", Email: "u1@example.com"}
		got, ok := authn.FromContext(authn.NewContext(context.Background(), id))
		Expect(ok).To(BeTrue())
		Expect(got).To(Equal(id))
	})
})
