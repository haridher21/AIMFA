# Research: landscape, rationale, practicality

This document feeds the report's "related work" and "design rationale" sections. Snapshot as of Nov 2026. Vendor details come largely from secondary sources (see the list at the end), so re-check them against official pages before quoting.

## 1. What exists today

### 1a. Commercial agent-identity products
Six or more vendors shipped agent-identity products **before** the standards were finished.

| Product | Summary | Relevance |
|---|---|---|
| Microsoft Entra Agent ID (GA ~spring 2026) | First-class directory identities for agents; supports OAuth 2.0, MCP, A2A | Confirms that agents need their own identities, not borrowed human credentials or API keys |
| AWS Bedrock AgentCore Identity | Inbound authentication to agents, plus outbound credentials to AWS and third-party tools | Like our STS + gateway, but tied to AWS |
| Auth0 for AI Agents (GA late 2025) | Token Vault, plus asynchronous human approval for sensitive actions (CIBA) | Direct analogue of our human step-up |
| Okta Cross App Access, Ping Identity for AI, WorkOS, Skyfire | Delegated / on-behalf-of authorization | Market validation |

### 1b. Standards and frameworks
- **SPIFFE/SPIRE** (CNCF): attests workloads and issues short-lived identities (SVIDs). This is the production form of our attestation pillar.
- **IETF AIMS draft** (`draft-klrc-aiagent-auth`, -00 Mar 2026 → -03 Jul 2026; authors from AWS, Zscaler, Ping, Okta, OpenAI and others):
  - treats agents as workloads
  - builds on SPIFFE/WIMSE + OAuth 2.0
  - defines **no new protocol**
  - requires unique agent identifiers
  - favors cryptographically bound credentials over static API keys

  It is an individual draft, not a standard.
- **IETF `draft-liu-agent-operation-authorization`**: carries workload identity tokens for agent operations.
- **NIST NCCoE concept paper** (Feb 5, 2026), *"Accelerating the Adoption of Software and AI Agent Identity and Authorization"*:
  - proposes demonstrating **existing** standards (OAuth, OIDC, SPIFFE) applied to agents
  - asks how credentials are issued and revoked, whether authorization should adapt **in real time**, how to apply **zero trust**, and how to **log and audit** agent activity

  AIMFA is a student-scale answer to these questions.
- **MCP authorization spec:** MCP servers act as OAuth 2.1 resource servers (RFC 9728, RFC 8707). The spec leaves open how non-human workloads authenticate, and how humans approve actions.
- **OWASP Top 10 for Agentic Applications 2026** (Dec 2025):
  - **ASI02 Tool Misuse.** Its own example is an invoice agent tricked into emailing sensitive documents externally, which is our A4.
  - **ASI03** Identity & Privilege Abuse.
  - **ASI10** Rogue Agents. Monitoring and kill switches are recommended.
- **RFCs we implement (simplified):**
  - RFC 9449 DPoP
  - RFC 7638 JWK thumbprint
  - RFC 8037 EdDSA in JOSE
  - RFC 7519 JWT
  - RFC 6238 TOTP
  - We borrow ideas from RFC 8693 Token Exchange and OpenID CIBA.
- **Content guardrails** (e.g., Lakera Guard, NVIDIA NeMo Guardrails) filter prompts and outputs. They work at a different layer from AIMFA, which governs actions and credentials. The two approaches are complementary.

## 2. Where AIMFA fits
- **Identity products** answer *"who is this agent and what token does it get?"*
- **Runtime-security products** answer *"is it saying or doing something bad?"*

Both are mostly proprietary and cloud-bound, and the standards are drafts.

**AIMFA is a small, open, localhost reference implementation** that composes four layers at **one enforcement point**:
- attested identity
- proof-of-possession tokens
- continuous behavior scoring
- human step-up

It is then evaluated against concrete attacks. AIMFA is **an integration and evaluation, not new research**, which matches NIST's "demonstrate existing standards" framing.

**A less common angle:** the agent's **system prompt + tool manifest + model id** count as part of its measured identity. Change the prompt and it becomes a different agent.

## 3. Why it works: the security argument
**Thesis: for agents, the attacker usually operates inside an authenticated session.** Prompt injection hijacks a legitimate agent that already holds a valid identity, key and token. Login-time checks are therefore necessary but not sufficient. Authorization must be **continuous and per action**.

| Attacker capability | What still stops them |
|---|---|
| Steals a token | DPoP: no private key, so every request fails |
| Captures a full request | `jti` replay cache + `iat` window |
| Tampers with agent code or prompt at rest | Attestation mismatch |
| Hijacks the running agent (holds everything) | Scope, 15-min TTL, behavior → revoke, human step-up on high-risk actions |
| Tampers with logs | Hash chain verification |

**Bounded blast radius.** A hijacked agent's worst-case damage is limited by four things together:
- the scope it was granted
- the token's lifetime
- only actions below the human-approval tier
- only until the monitor trips

## 4. Practicality: production equivalents
| AIMFA | Production |
|---|---|
| Launcher + attestation | SPIRE workload attestors; TPM / TEE (Nitro Enclaves, confidential VMs) |
| STS | OAuth AS with Token Exchange + DPoP (Keycloak, Okta, Auth0, Entra) |
| Gateway | Envoy / API gateway + ext_authz + OPA; MCP gateways |
| Monitor | UEBA in a SIEM (Sentinel, Splunk) |
| Human step-up | OpenID CIBA, Duo / Okta Verify push |
| Audit chain | WORM storage, transparency logs |

**Deployment requirements:**
- **The gateway must be the only path.** Agents hold no raw credentials, and network egress is restricted.
- **Policies must be authored per role.**
- **Latency:** signature checks cost about 1 ms. Human approval takes minutes, so it suits only rare actions.

The hard parts in practice are policy authoring, behavior baselining and hardware-rooted attestation, not the cryptography.

## Sources
- Microsoft Entra Agent ID: https://learn.microsoft.com/en-us/entra/agent-id/whats-new-agent-id
- AWS AgentCore Identity: https://aws.amazon.com/blogs/machine-learning/introducing-amazon-bedrock-agentcore-identity-securing-agentic-ai-at-scale
- Vendors ahead of IETF: https://forkast.news/six-vendors-are-shipping-agent-identity-products-the-ietf-has-not-finished-the-standard/
- Auth0 for AI Agents GA: https://guptadeepak.com/ciam-compass/changelog/auth0-for-ai-agents-ga/
- IETF AIMS draft -03: https://www.ietf.org/archive/id/draft-klrc-aiagent-auth-03.html
- IETF Agent Operation Authorization: https://datatracker.ietf.org/doc/html/draft-liu-agent-operation-authorization-02
- CSA note on IETF agent identity: https://labs.cloudsecurityalliance.org/research/csa-research-note-ietf-agent-identity-standards-20260902-csa/
- NIST NCCoE concept paper: https://www.nccoe.nist.gov/sites/default/files/2026-02/accelerating-the-adoption-of-software-and-ai-agent-identity-and-authorization-concept-paper.pdf
- MCP authorization standards & gaps: https://www.cerbos.dev/blog/mcp-authorization-standards
- MCP step-up: https://workos.com/blog/mcp-scope-step-up-vs-authentication-step-up
- OWASP Agentic Top 10 summaries: https://cycode.com/blog/owasp-top-10-agentic-applications/ , https://graylog.org/post/what-is-the-owasp-top-10-agentic-ai
- TAMU AI Chat API: https://www.it.tamu.edu/services/services-by-category/communication-and-collaboration/tamu-ai-chat.html , https://docs.tamus.ai/
