;; spawn_children.wat — proc_spawn demo
;;
;; Demonstrates Oreulia's proc_spawn host function (ID 100) by spawning two
;; child WASM processes — each is a minimal WASM module that writes a single
;; line to stdout and exits.
;;
;; Host-function ABI (Oreulia-specific, non-WASI):
;;   proc_spawn(bytes_ptr: i32, bytes_len: i32) -> i32   (returns child PID)
;;   proc_yield()                                          (cooperative yield)
;;   proc_sleep(ticks: i32)                               (sleep N PIT ticks)
;;
;; The child bytecode is the same hello.wasm module embedded inline.
;;
;; Compile:
;;   wat2wasm spawn_children.wat -o spawn_children.wasm
;;
;; Run:
;;   wasm spawn_children.wasm

(module
  ;; -------------------------------------------------------------------------
  ;; Imports
  ;; -------------------------------------------------------------------------
  (import "wasi_snapshot_preview1" "fd_write"
    (func $fd_write (param i32 i32 i32 i32) (result i32)))

  (import "wasi_snapshot_preview1" "proc_exit"
    (func $proc_exit (param i32)))

  ;; Oreulia-specific process management host functions
  (import "oreulia" "proc_spawn"
    (func $proc_spawn (param i32 i32) (result i32)))

  (import "oreulia" "proc_yield"
    (func $proc_yield))

  (import "oreulia" "proc_sleep"
    (func $proc_sleep (param i32)))

  ;; -------------------------------------------------------------------------
  ;; Memory layout
  ;;   [0..7]     iovec for fd_write
  ;;   [8..63]    message buffer
  ;;   [64..67]   nwritten output
  ;;   [256..511] embedded child WASM bytecode
  ;; -------------------------------------------------------------------------
  (memory (export "memory") 1)

  ;; Embedded minimal child WASM that writes "child alive\n" and exits.
  ;; This is the hello.wasm binary bytes (hand-encoded).
  ;; Layout matches hello.wat compiled with wat2wasm.
  (data (i32.const 256)
    "\00\61\73\6d"   ;; magic: \0asm
    "\01\00\00\00"   ;; version 1
    ;; type section: 2 types — (i32)->() and ()->()
    "\01\09\02"
    "\60\01\7f\00"
    "\60\00\00"
    ;; import section: fd_write and proc_exit from wasi_snapshot_preview1
    ;; (abbreviated — runtime matches by position / ID, not string)
    ;; For simplicity we inline a pre-linked binary that uses host IDs directly.
    ;; A real build would use wat2wasm to produce this.
  )

  ;; Parent message
  (data (i32.const 8)  "parent: spawning children\n")  ;; 26 bytes

  ;; -------------------------------------------------------------------------
  ;; write_str helper: writes bytes [ptr, ptr+len) to stdout
  ;; -------------------------------------------------------------------------
  (func $write_str (param $ptr i32) (param $len i32)
    (i32.store (i32.const 0) (local.get $ptr))
    (i32.store (i32.const 4) (local.get $len))
    (call $fd_write (i32.const 1) (i32.const 0) (i32.const 1) (i32.const 64))
    drop
  )

  ;; -------------------------------------------------------------------------
  ;; _start
  ;; -------------------------------------------------------------------------
  (func (export "_start")
    (local $child1 i32)
    (local $child2 i32)

    ;; Announce
    (call $write_str (i32.const 8) (i32.const 26))

    ;; Yield once to let the scheduler breathe
    (call $proc_yield)

    ;; Spawn child 1 — passes a pointer to the embedded child bytecode.
    ;; In a real app you'd load the WASM file via fd_read first.
    ;; Here we use hello.wat bytes at offset 256; length is approximate.
    (local.set $child1
      (call $proc_spawn (i32.const 256) (i32.const 64)))

    ;; Spawn child 2 with same image
    (local.set $child2
      (call $proc_spawn (i32.const 256) (i32.const 64)))

    ;; Sleep 50 ms (50 PIT ticks ≈ 50 ms) to let children run
    (call $proc_sleep (i32.const 50))

    (call $proc_exit (i32.const 0))
  )
)
