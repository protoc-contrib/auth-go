# auth-go

[![CI](https://github.com/protoc-contrib/auth-go/actions/workflows/ci.yml/badge.svg)](https://github.com/protoc-contrib/auth-go/actions/workflows/ci.yml)
[![Go](https://img.shields.io/badge/Go-1.27-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Connect interceptors that authenticate and authorize the RPCs of a Go server.

Two packages, which a service uses together or apart:

| Package | Answers | Refuses with |
| --- | --- | --- |
| `authn` | who is calling | `Unauthenticated` |
| `authz` | whether they may do this to that resource | `PermissionDenied` |

Both are `connect.ServerInterceptor`s of connect v2, so one of each serves every
protocol the server speaks: Connect, gRPC, gRPC-Web, and the REST routes that
Vanguard dispatches through the same `connect.Server`. The messages of a
refusal are fixed sentences; the reason is the error's cause, for the error
interceptor to log, and never reaches the client.

## authn

`authn.NewInterceptor` reads a credential from the request, has a `Verifier`
check it, and puts the `Identity` it proves in the context.

```go
verifier, err := authn.NewOIDC(ctx, authn.Config{
	Issuer:   "https://auth.example.com/",
	Audience: "library-api",
})

guard := authn.NewInterceptor(verifier)

// in a handler
id, ok := authn.FromContext(ctx) // id.Subject, id.Email
```

`NewOIDC` verifies the ID tokens of an OpenID Connect issuer: the signature
against the issuer's keys, the issuer, the audience and the expiry. The keys are
discovered from the issuer's metadata, or taken from `Config.KeysURL` for an
issuer that publishes none. Cloudflare Access is one, and sends its token in
its own header:

```go
verifier, err := authn.NewOIDC(ctx, authn.Config{
	Issuer:   "https://acme.cloudflareaccess.com",
	Audience: "<the application's AUD tag>",
	KeysURL:  "https://acme.cloudflareaccess.com/cdn-cgi/access/certs",
})

guard := authn.NewInterceptor(verifier, authn.WithHeader("Cf-Access-Jwt-Assertion"))
```

Moving to another identity provider is a change of `Config`, and of the header
when it is not `Authorization`. Anything that is not an OIDC token implements
`Verifier`, which is one method.

Key what a caller owns on `Identity.Subject`, not on the email.

## authz

`authz.NewInterceptor` hands an `Authorizer` what a request asks to do, and
refuses the RPC it does not allow:

```go
type Request struct {
	Subject   string // the caller, from authn
	Procedure string // "/acme.v1.LibraryService/GetBook"
	Resource  string // "users/u1/shelves/s1": the name the request holds
}

type Authorizer interface {
	Authorize(ctx context.Context, req Request) (bool, error)
}
```

An AIP request names its resource in its `name` field, in the `name` of the
resource an update carries, or in its `parent` field. The interceptor reads it
off the message, so it needs no knowledge of the service. A request that names
none, such as a top-level List or Create, has an empty `Resource`, and the
Authorizer decides. A batch request holds its names in a repeated field, which
is not searched.

An Authorizer that returns an error is an internal error, never an allow.

`authz.OwnerAuthorizer` is the first Authorizer, for a service in which a
resource belongs to one caller. It asks the service for the owner of the root of
the name:

```go
authorizer := authz.OwnerAuthorizer{
	OwnerOf: func(ctx context.Context, name string) (string, error) {
		owner, err := queries.GetShelfOwner(ctx, name)
		if errors.Is(err, pgx.ErrNoRows) {
			return "", authz.ErrNotFound
		}
		return owner, err
	},
}

guard := authz.NewInterceptor(authorizer)
```

A resource that does not exist and one that is someone else's are refused alike,
so a caller cannot find out which IDs exist. When resources are shared, or roles
come, write an `Authorizer` over OpenFGA or Casbin and pass it in its place: the
interceptor and the handlers do not change.

## Errors

A refusal is a `connect.Error` with a fixed message, and why it happened as its
cause, for your error interceptor to log; the cause never reaches the client.

| Refusal | Code | Why (the cause) |
| --- | --- | --- |
| no credential | `Unauthenticated` | `authn.ErrCredentialsMissing` |
| a credential the verifier refused | `Unauthenticated` | `authn.ErrCredentialsInvalid`, wrapping the verifier's error |
| a request the `Authorizer` did not allow | `PermissionDenied` | `*authz.PermissionDeniedError`, holding the `Request` |
| an `Authorizer` that could not decide | `Internal` | `authz.ErrAuthorizationFailed`, wrapping its error |

The library does not decide what a client is told beyond that. A service gives
the refusal the shape of its own errors, with a domain, a reason and the
details, by passing a mapper, which receives why and returns the error to
answer with:

```go
guard := authn.NewInterceptor(verifier, authn.WithErrorMapper(func(why error) error {
	if errors.Is(why, authn.ErrCredentialsMissing) {
		return Unauthenticated(ReasonCredentialsMissing, why) // the service's own constructor
	}
	return Unauthenticated(ReasonCredentialsInvalid, why)
}))

check := authz.NewInterceptor(authorizer, authz.WithErrorMapper(func(why error) error {
	var denied *authz.PermissionDeniedError
	if errors.As(why, &denied) {
		return PermissionDenied(denied.Request.Resource, why) // names the resource, in its own details
	}
	return nil // anything else: the default
}))
```

A mapper that returns nil falls back to the default answer. `authz` hands its
mapper `authn.ErrCredentialsMissing` for a call that reached it without a
caller, which means authn is not installed in front of it.

## Order

Authorization needs the message, which exists only once the handler receives it,
so the check is in `Receive`: a message that is refused never reaches the
handler. Install the two before every interceptor that validates or fills in a
message, and `authn` first:

```
authn → authz → field behavior and validation → the rest
```

Placed after validation, a caller that is not allowed is answered with the
validation errors of a request it may not make, and the Authorizer sees the
request as the server completed it, with an ID minted, not as the client sent
it.

## Development

Dependencies are managed via [Nix](https://nixos.org/) flakes, or a
[Dev Container](https://containers.dev/) that installs Nix. Every `make` target
expects the shell.

```bash
nix develop
make test       # ginkgo, with coverage
make lint       # golangci-lint, with gofumpt
make fmt        # apply the formatter
make coverage   # coverage by file
```

The packages are covered at 100%, and CI holds them there. A change that adds a
branch adds the spec that reaches it.
