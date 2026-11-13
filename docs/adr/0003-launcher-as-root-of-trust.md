# ADR-0003: Software launcher as the attestation root of trust (simulated attestation)

- **Status:** accepted
- **Date:** 2026-11-10
- **Deciders:** team

## Context
Real workload attestation roots trust in hardware (TPM, TEE) or in a platform agent (SPIRE agent + Kubernetes/Docker selectors). We have no hardware root on student laptops, and no time to deploy SPIRE.

## Decision
A trusted **launcher** process holds its own Ed25519 key, which is registered with the control plane. It:
1. measures the agent: SHA-256 over code files, system prompt, tool manifest and model id
2. generates a fresh in-memory key pair for this agent instance
3. signs the evidence together with a control-plane nonce
4. runs the agent **in-process**, handing it the private key object, which is never written to disk

## Alternatives considered
- **SPIRE.** The real thing, but too heavy for our timeline and Windows setup. Listed as stretch work.
- **Docker image digest as the measurement.** A good stretch goal, but it adds Docker as a hard dependency for the demo.
- **The agent measures itself.** Worthless: a tampered agent would just report the golden hash.

## Consequences
- **Gained:** factor 1 is demonstrable (A1), and the code maps 1:1 onto SPIRE concepts (attestor, SVID).
- **Accepted risk:** **a compromised launcher, or code that modifies the agent after measurement, defeats attestation.** This is documented in THREAT_MODEL §3 and §6.

## Implementation (T5.1)
`aimfa/agents/launcher.py`: the agent runs in the launcher's process. The per-instance key is an in-memory object handed straight to `AgentClient` and is never saved. The launcher's own long-term key is stored in `keys/launcher.pem` (git-ignored), like a host key, and its public half is registered with `scripts/register_agents.py`. The system prompt is read only from the manifest's prompt file, which is part of the measurement.
