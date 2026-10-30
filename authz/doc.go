// Package authz authorizes the RPCs of a Connect server before their handlers
// run: it hands an [Authorizer] the caller, the procedure and the resource the
// request names, and refuses the RPC the Authorizer does not allow.
//
// An AIP request names its resource in the `name` field of a Get, an Update's
// nested resource or a Delete, and in the `parent` field of a List or a Create,
// so the check needs no knowledge of the service: what a caller may do to which
// resource is the Authorizer's. [Owner] is the first, for a service in which a
// resource belongs to one caller; a relationship store such as OpenFGA, or a
// policy engine such as Casbin, is another, and replaces it without a change to
// the interceptor or the handlers.
package authz
