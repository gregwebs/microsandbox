# Context

Domain language for microsandbox. These are shared definitions, not a roadmap or
an algorithm; implementation and rationale live in the code and in
[`docs/adr/`](docs/adr).

## Language

**File-mount stage**:
The host-side directory microsandbox shares over virtio-fs so one host *file* can
be bind-mounted into the guest without exposing the files next to it.
_Avoid_: "staging dir" when a specific kind is meant.

**Stage root**:
The directory holding one or more file-mount stages (`<root>/<fm_tag>/<file>`).

**Sandbox-dir stage**:
On Unix, the stage root inside the sandbox's own directory
(`<sandbox_dir>/file-mounts`). Owned by microsandbox and cleared on spawn and on
`rm`.

**Source-parent stage**:
A stage root created beside a writable mount's source. A hard link must stay on
one filesystem, so on Unix this is used only when the source filesystem differs
from the sandbox-dir stage's. It lives in the user's tree, which is why it needs
recorded cleanup. See [`docs/adr/0001-runtime-owned-file-mount-stages.md`](docs/adr/0001-runtime-owned-file-mount-stages.md).
