package authn_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/protoc-contrib/auth-go/authn"
)

const keyID = "key-1"

// issuer is an OpenID Connect provider that serves its metadata and its signing
// key, and signs tokens with that key.
type issuer struct {
	server *httptest.Server
	key    *rsa.PrivateKey
}

func newIssuer() *issuer {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	Expect(err).NotTo(HaveOccurred())
	i := &issuer{key: key}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"issuer": i.server.URL, "jwks_uri": i.server.URL + "/keys"})
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, _ *http.Request) {
		keys := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: keyID, Algorithm: string(jose.RS256), Use: "sig"}}}
		_ = json.NewEncoder(w).Encode(keys)
	})
	i.server = httptest.NewServer(mux)
	return i
}

func (i *issuer) url() string { return i.server.URL }

// token signs claims with key, over the defaults of a token this issuer
// issues for the "api" audience, which claims override.
func (i *issuer) token(key *rsa.PrivateKey, claims map[string]any) string {
	all := map[string]any{
		"iss":   i.url(),
		"aud":   "api",
		"sub":   "u1",
		"email": "u1@example.com",
		"iat":   jwt.NewNumericDate(time.Now()),
		"exp":   jwt.NewNumericDate(time.Now().Add(time.Hour)),
	}
	for name, value := range claims {
		all[name] = value
	}
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: key, KeyID: keyID}},
		(&jose.SignerOptions{}).WithType("JWT"),
	)
	Expect(err).NotTo(HaveOccurred())
	raw, err := jwt.Signed(signer).Claims(all).Serialize()
	Expect(err).NotTo(HaveOccurred())
	return raw
}

var _ = Describe("OIDC verifier", func() {
	var (
		provider *issuer
		stranger *rsa.PrivateKey
	)

	BeforeEach(func() {
		provider = newIssuer()
		DeferCleanup(provider.server.Close)
		var err error
		stranger, err = rsa.GenerateKey(rand.Reader, 2048)
		Expect(err).NotTo(HaveOccurred())
	})

	constructors := map[string]func(ctx context.Context, provider *issuer) (authn.Verifier, error){
		"with the keys discovered from the issuer": func(ctx context.Context, provider *issuer) (authn.Verifier, error) {
			return authn.NewOIDC(ctx, authn.Config{Issuer: provider.url(), Audience: "api"})
		},
		"with the keys at a URL": func(ctx context.Context, provider *issuer) (authn.Verifier, error) {
			return authn.NewOIDC(ctx, authn.Config{Issuer: provider.url(), Audience: "api", KeysURL: provider.url() + "/keys"})
		},
	}

	for name, construct := range constructors {
		Context(name, func() {
			var verify authn.Verifier

			BeforeEach(func() {
				ctx, cancel := context.WithCancel(context.Background())
				DeferCleanup(cancel)
				var err error
				verify, err = construct(ctx, provider)
				Expect(err).NotTo(HaveOccurred())
			})

			It("returns the subject and the email of a valid token", func() {
				id, err := verify.Verify(context.Background(), provider.token(provider.key, nil))
				Expect(err).NotTo(HaveOccurred())
				Expect(id).To(Equal(authn.Identity{Subject: "u1", Email: "u1@example.com"}))
			})

			It("returns no email for a token that carries none", func() {
				id, err := verify.Verify(context.Background(), provider.token(provider.key, map[string]any{"email": nil}))
				Expect(err).NotTo(HaveOccurred())
				Expect(id).To(Equal(authn.Identity{Subject: "u1"}))
			})

			DescribeTable("refuses a token",
				func(key func() *rsa.PrivateKey, claims map[string]any) {
					_, err := verify.Verify(context.Background(), provider.token(key(), claims))
					Expect(err).To(HaveOccurred())
				},
				Entry("that has expired", func() *rsa.PrivateKey { return provider.key }, map[string]any{"exp": jwt.NewNumericDate(time.Now().Add(-time.Hour))}),
				Entry("for another audience", func() *rsa.PrivateKey { return provider.key }, map[string]any{"aud": "other"}),
				Entry("from another issuer", func() *rsa.PrivateKey { return provider.key }, map[string]any{"iss": "https://other.example.com"}),
				Entry("signed with a key the issuer does not publish", func() *rsa.PrivateKey { return stranger }, nil),
				Entry("whose email is not a string", func() *rsa.PrivateKey { return provider.key }, map[string]any{"email": 7}),
			)

			It("refuses a credential that is not a token", func() {
				_, err := verify.Verify(context.Background(), "not-a-token")
				Expect(err).To(HaveOccurred())
			})
		})
	}

	DescribeTable("is not built without",
		func(cfg authn.Config) {
			_, err := authn.NewOIDC(context.Background(), cfg)
			Expect(err).To(HaveOccurred())
		},
		Entry("an issuer", authn.Config{Audience: "api"}),
		Entry("an audience", authn.Config{Issuer: "https://issuer.example.com"}),
	)

	It("is not built when the issuer's metadata cannot be discovered", func() {
		provider.server.Close()
		_, err := authn.NewOIDC(context.Background(), authn.Config{Issuer: provider.url(), Audience: "api"})
		Expect(err).To(HaveOccurred())
	})
})
