# 1. Runtime-owned file-mount stages

Status: accepted (Unix scope; one decision's cleanup is implemented in #25)

## Context

Virtio-fs exports directories, but a file bind mount must expose only the
selected host file, not the files next to it. For each file mount the runtime
creates a file-mount stage: a directory holding just that file, which the guest
bind-mounts at the requested path. A hard link preserves the host inode, so guest
writes reach the source; a copy does not.

Before this decision the runtime created a system-temp-root stage root up front
for every spawn that had file mounts, then created a `<fm_tag>` directory per
mount there. Hard links rarely succeed when the system temp dir is on a different
filesystem (on Linux, `/tmp` is often tmpfs), so writable mounts frequently
staged inside the user's own tree instead, and a system-temp stage root has no
owner tied to the sandbox. See [issue #23](https://github.com/gregwebs/microsandbox/issues/23).

## Decision

On Unix (Linux and macOS) the local backend now:

1. **Stages in the sandbox directory, not the system temp dir.** The stage root
   is `<sandbox_dir>/file-mounts`, created with mode `0700` because it holds hard
   links to possibly private files. It is cleared at spawn, before staging, while
   the sandbox lifecycle guard is held; `rm` removes it with the rest of the
   sandbox directory.
2. **Chooses the stage root per mount by filesystem identity, before doing any
   work.** The source's `st_dev` is compared with the sandbox-dir stage's. The
   device is read from a held-parent no-follow `fstatat`, and a writable mount
   that still gets `EXDEV` from the sandbox-dir link retries exactly once in a
   source-parent stage, so device equality is treated as a preflight check
   rather than mount-instance identity:
   - same device: hard link into `<sandbox_dir>/file-mounts/<fm_tag>/<file>`;
   - different device, readonly: copy into the same sandbox-dir stage, since a
     link cannot cross filesystems and a readonly mount needs no writeback;
   - different device, writable: hard link in a source-parent stage beside the
     source, so guest writes still reach it. The parent must be writable; there
     is no copy fallback.
3. **Attributes source-parent cleanup to the runtime process.** A sweep guarded
   by the lifecycle lock covers crashes. *Accepted direction; the sweep itself is
   implemented in [#25](https://github.com/gregwebs/microsandbox/issues/25).* In
   #23 source-parent stages remain owned by `TempDir`: dropped on ordinary handle
   drop and kept on detach. Sandbox-dir stages are *not* removed on runtime exit;
   they persist until the next spawn of the same name or `rm`.

Routing and lifetime (Unix):

```text
Stopped generation / leftover sandbox-dir stage
  -- acquire lifecycle guard + prove previous owner dead -->
clear exact <sandbox_dir>/file-mounts
  -- no file mounts --> no root recreated
  -- file mounts --> private root (0700) --> stage by device --> launch
       | staging/launch error: sandbox-dir residue retained; source-parent RAII applies
       | attached handle dropped: sandbox-dir retained; source-parent roots dropped
       | detached handle disarmed: sandbox-dir retained; source-parent roots kept
Stopped/crashed again
  -- next spawn, under guard --> clear/rebuild
  -- rm, under guard --> remove whole sandbox directory
```

Consequences:

- On the common layout (sources under `$HOME`, a private `MSB_HOME` under
  `$HOME`), every mount stages in the sandbox directory.
- Readonly cross-device copies consume storage under `MSB_HOME`
  (`sandboxes/<name>/file-mounts`) rather than in the system temp dir, and can
  persist until the next spawn or `rm`. The sandbox directory already held logs,
  scripts, and disks, but copies can add materially to its size.
- Same-device readonly mounts are hard links, not snapshots: they reflect later
  host edits and do not isolate the file.
- The stage root is private (`0700`); it is never more permissive than the
  process umask would allow.
- Windows is **unchanged** (see below).

## Windows and other non-Unix targets

This decision is scoped to Unix. The runtime has no real Windows lifecycle guard
on this checkout: the guard is empty on non-Unix and only retained on Unix, and
the Windows live-pipe probe does not serialize starts before a pipe is published.
Clearing a deterministic same-name root without that serialization could delete a
winning runtime's backing files, and Windows directory symlinks and readonly hard
links need a distinct safe cleanup design. Windows therefore keeps the previous
behavior: an eager system-temp stage root, hard link, then `EXDEV` routing where
readonly cross-volume mounts copy in place and writable cross-volume mounts stage
beside the source. Temporary roots are removed on ordinary handle drop or kept on
detach; the sandbox-dir persistence/reset guarantee does not apply.

Windows lifecycle locking and safe persistent-stage cleanup are separately scoped
future work, **not part of #25's source-parent runtime cleanup** and not delivered
by #23. This is not a commitment to Windows parity for this design.

## Alternatives considered

- **Keep the system temp dir and create it lazily.** Still depends on temp
  availability, still places readonly copies on tmpfs, and a temp-dir stage still
  has no owner tied to the sandbox.
- **Leave detach-time residue and document it.** Source-parent stages are
  user-visible and unbounded; documenting the leak does not bound it. Recorded,
  guarded cleanup (decision 3, #25) is preferred.
- **Give source-parent stages deterministic names instead of recording them.**
  A deterministic name can collide with a concurrent runtime and cannot be safely
  removed without a manifest of what this runtime created. TempDir plus a recorded
  sweep is safer.

## Links

- Issue: https://github.com/gregwebs/microsandbox/issues/23
- File sources honor `follow_root_symlinks` and stage from no-follow descriptors: https://github.com/gregwebs/microsandbox/issues/24
- Follow-up (source-parent cleanup): https://github.com/gregwebs/microsandbox/issues/25
