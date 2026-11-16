# Read the in-force network policy from the runtime, not the sandbox record

A policy replacement lives only in the running runtime, so the sandbox record and `msb inspect` keep showing the launch policy after one. We decided that reading back a sandbox's policy asks the running runtime over the control endpoint for the in-force policy and its revision, and that a stopped sandbox reports its launch policy, labelled as such, because that is exactly what its next start enforces. We did not persist replacements to make the record authoritative: a replacement is a grant the launcher owns and must re-send after restart, restore, or fork, and persisting it would change that security model and the catalog's compatibility surface.

## Considered Options

- **Persist each replacement** so `inspect` and the stored config are authoritative. Rejected: restart, restore, and fork would silently keep grants the launcher meant to be temporary, and it adds a catalog write on the live-control path.
- **Report the launch policy only.** Rejected: it is wrong after any replacement, which is the only case where a read-back adds information.

## Consequences

- `msb inspect` stays a catalog read and does not show the in-force policy; `msb network-policy get` is the place to look.
- A runtime that can replace but not read its policy cannot answer truthfully, so the read is refused there rather than inferred from the record.
- The platform floor is not part of the reading.
