# ADR-0001: Bind access tokens to agent keys with DPoP (not mTLS)

- **Status:** accepted
- **Date:** 2026-11-10
- **Deciders:** team

## Context
A bearer token works for whoever holds it, so a leaked token equals a compromised agent. We need tokens that work only for the agent instance they were issued to. That turns the token into a real *possession* factor.

## Decision
Use **OAuth 2.0 DPoP (RFC 9449)**:
- The access token carries `cnf.jkt`, the thumbprint of the agent's public key.
- Every request includes a fresh proof JWT signed by the agent's private key. The proof covers the method, URL, time, a unique `jti`, and `ath` (a hash of the token).

## Alternatives considered
- **mTLS-bound tokens (RFC 8705).** These are equally strong, but need a local CA, certificates per agent, and TLS on every service. That's heavy for a 20-day project on Windows laptops, and harder to demo and explain.
- **Plain bearer tokens with short TTL.** Still stealable during the TTL, so A2 would succeed.
- **HMAC request signing with a shared secret.** The server would then hold the secret too, which weakens the possession property.

## Consequences
- **Gained:** application-layer binding that we can implement in about 100 lines, test thoroughly, and show in the demo (A2, A3).
- **Accepted risks:** the replay cache is in memory (bounded by the 60-second `iat` window). There's no TLS, so localhost traffic isn't encrypted.
