package authn

import (
	"context"
	"errors"

	"github.com/coreos/go-oidc/v3/oidc"
)

// Verifier checks a credential, and returns the identity it proves or the
// reason it proves none.
type Verifier interface {
	Verify(ctx context.Context, credential string) (Identity, error)
}

// Config tells [NewOIDC] which tokens to accept.
type Config struct {
	// Issuer is the iss claim a token must carry. Unless KeysURL is set, it is
	// also where the signing keys are discovered, from the provider's
	// .well-known/openid-configuration.
	Issuer string
	// Audience is the aud claim a token must carry: the client ID of the API
	// at the identity provider, or the AUD tag of a Cloudflare Access
	// application.
	Audience string
	// KeysURL is where the issuer publishes its signing keys. Leave it empty
	// to discover it from Issuer; set it for an issuer that has no metadata
	// to discover, such as Cloudflare Access, whose keys are at
	// https://<team>.cloudflareaccess.com/cdn-cgi/access/certs.
	KeysURL string
}

// NewOIDC returns a [Verifier] of the ID tokens an OpenID Connect issuer
// signs: it checks the signature against the issuer's keys, the issuer, the
// audience and the expiry, and reads the subject and the email off the claims.
//
// The keys are fetched and cached for as long as ctx lives, so pass the
// server's context and not a request's. It fails when Issuer or Audience is
// empty, which would accept no token at all, and when the issuer's metadata
// cannot be discovered.
func NewOIDC(ctx context.Context, cfg Config) (Verifier, error) {
	if cfg.Issuer == "" || cfg.Audience == "" {
		return nil, errors.New("authn: an issuer and an audience are required")
	}
	oidcConfig := &oidc.Config{ClientID: cfg.Audience}
	if cfg.KeysURL != "" {
		keys := oidc.NewRemoteKeySet(ctx, cfg.KeysURL)
		return &oidcVerifier{verifier: oidc.NewVerifier(cfg.Issuer, keys, oidcConfig)}, nil
	}
	provider, err := oidc.NewProvider(ctx, cfg.Issuer)
	if err != nil {
		return nil, err
	}
	return &oidcVerifier{verifier: provider.Verifier(oidcConfig)}, nil
}

type oidcVerifier struct {
	verifier *oidc.IDTokenVerifier
}

func (v *oidcVerifier) Verify(ctx context.Context, credential string) (Identity, error) {
	token, err := v.verifier.Verify(ctx, credential)
	if err != nil {
		return Identity{}, err
	}
	var claims struct {
		Email string `json:"email"`
	}
	if err := token.Claims(&claims); err != nil {
		return Identity{}, err
	}
	return Identity{Subject: token.Subject, Email: claims.Email}, nil
}
