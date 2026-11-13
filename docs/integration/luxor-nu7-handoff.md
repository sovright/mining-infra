# Luxor NU7 upgrade

**Draft for release preparation — no production installation requested yet.**
Sovright will supply the pinned release and installation command after qualification.

We are preparing an upgrade for your existing Sovright integration. Assuming you
run the current published client release, the intended change is a binary update
of the components you already use: the receive sidecar and, where installed,
the pool submission gateway. We will qualify that path before requesting rollout.

## Your steps when the release is ready

1. Install the supplied, checksummed release on one instance during the agreed
   window. Keep your existing configuration, authentication key, relay endpoints,
   and pool RPC integration unless our final release note identifies a required change.
2. Let Sovright verify reconnection, block delivery and submission health.
3. Roll the same package through the remaining instances after the canary passes.

There is no manual P2P version setting to change. The upgraded gateway selects
the mainnet version automatically. No new integration, key rotation, fixture
generation or test harness is requested for this handoff.

Sovright owns the compatibility tests, relay deployment, monitoring and release
instructions. We will include the supported NU7 full-node release and coordinate
any necessary node upgrade as part of the same window. Your existing node must
be NU7-compatible; updating the relay client alone does not upgrade consensus.

Keep direct submission to a synced NU7-compatible node available during the
transition. If the relay path is unhealthy, use that path while Sovright resolves
it. After activation, an older pre-NU7 node or client is not an approved fallback.

The final handoff will contain the release URL, checksums, exact installation and
restart command, supported node version, activation height, fallback command,
and Sovright's named contact. Those values are withheld until verified; this
draft is not an instruction to install the qualification candidate.
