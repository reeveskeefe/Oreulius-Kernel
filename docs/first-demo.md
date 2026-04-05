# First Demo

This is the shortest end-to-end path that shows what makes Oreulius different.

## Goal

In one session, show:

- a capability boundary
- a temporal history boundary
- a verification surface

## Demo Path

Boot the recommended `i686` target:

```bash
cd kernel
./build.sh
./run.sh
```

Then run:

```text
cap-test-atten
temporal-write /tmp/demo alpha
temporal-snapshot /tmp/demo
temporal-write /tmp/demo beta
temporal-history /tmp/demo
formal-verify
```

The runtime bootstraps `/tmp` in the in-memory VFS, so you do not need to create it before running this sequence.
Keep the temporal path exact across the sequence: write, snapshot, and history should all use `/tmp/demo`.

## What You Should See

- `cap-test-atten`
  - demonstrates that capability rights cannot be delegated upward arbitrarily
- `temporal-write` + `temporal-snapshot` + `temporal-history`
  - demonstrates that object state becomes history rather than silent mutation
- `formal-verify`
  - demonstrates that verification is surfaced as a runnable kernel command rather than only a static claim

## Optional Network Extension

If you want one more concrete system behavior:

```text
netstack-info
dns-resolve example.com
http-get http://example.com/
```

That extension shows the real network stack and shell transport working end to end.

## Where To Go Next

- [Architecture Overview](architecture-overview.md)
- [Verification Overview](verification-overview.md)
- [ABI Reference](abi-reference.md)
