package authz_test

import (
	"context"
	"errors"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/protoc-contrib/auth-go/authz"
)

var _ = Describe("Owner", func() {
	var (
		owners map[string]string
		asked  []string
		err    error
		owner  authz.Owner
	)

	BeforeEach(func() {
		owners = map[string]string{"shelves/s1": "alice"}
		asked = nil
		err = nil
		owner = authz.Owner{OwnerOf: func(_ context.Context, name string) (string, error) {
			asked = append(asked, name)
			if err != nil {
				return "", err
			}
			subject, ok := owners[name]
			if !ok {
				return "", authz.ErrNotFound
			}
			return subject, nil
		}}
	})

	authorize := func(subject, resource string) (bool, error) {
		return owner.Authorize(context.Background(), authz.Request{Subject: subject, Resource: resource})
	}

	It("allows the owner", func() {
		allowed, err := authorize("alice", "shelves/s1")
		Expect(err).NotTo(HaveOccurred())
		Expect(allowed).To(BeTrue())
	})

	It("refuses anyone else", func() {
		allowed, err := authorize("bob", "shelves/s1")
		Expect(err).NotTo(HaveOccurred())
		Expect(allowed).To(BeFalse())
	})

	It("refuses a resource that does not exist, as it does one that is not the caller's", func() {
		allowed, err := authorize("alice", "shelves/s2")
		Expect(err).NotTo(HaveOccurred())
		Expect(allowed).To(BeFalse())
	})

	It("allows a request that names no resource, without asking who owns it", func() {
		allowed, err := authorize("alice", "")
		Expect(err).NotTo(HaveOccurred())
		Expect(allowed).To(BeTrue())
		Expect(asked).To(BeEmpty())
	})

	It("cannot decide when the owner cannot be read", func() {
		reason := errors.New("database is down")
		err = reason

		allowed, got := authorize("alice", "shelves/s1")

		Expect(got).To(MatchError(reason))
		Expect(allowed).To(BeFalse())
	})

	DescribeTable("asks about the root of the name",
		func(resource, root string) {
			_, _ = authorize("alice", resource)
			Expect(asked).To(Equal([]string{root}))
		},
		Entry("as it is, for a resource", "shelves/s1", "shelves/s1"),
		Entry("of a child", "shelves/s1/books/b1", "shelves/s1"),
		Entry("of a parent that is a collection of children", "shelves/s1/books", "shelves/s1"),
		Entry("as it is, when there is no ID", "shelves", "shelves"),
	)
})
