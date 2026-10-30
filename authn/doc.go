// Package authn authenticates the RPCs of a Connect server: it reads the
// credential a request carries, has a [Verifier] check it, and puts the
// [Identity] it proves in the context of the call, for the handlers and for
// the authz package to read with [FromContext].
//
// One interceptor serves every protocol the server speaks, since Connect, gRPC,
// gRPC-Web and the REST routes of Vanguard all reach a handler through the same
// connect.Server.
package authn
