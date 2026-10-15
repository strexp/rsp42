// Package es2plus implements the SM-DP+ ES2+ server handlers: the
// operator-facing downloadOrder/confirmOrder/cancelOrder/releaseProfile
// functions, the progress and ACR callbacks, and the tenant/authorisation and
// response plumbing they share.
//
// The outbound ES2+ clients (the callback sender and the operator client
// library) live in internal/client/es2p.
package es2plus
