;; poll_demo.wat — demonstrates poll_oneoff clock timeout
;;
;; Uses WASI poll_oneoff with a CLOCK_MONOTONIC subscription to sleep for
;; ~100 ms (100 000 000 ns), then writes a message confirming the wake-up.
;;
;; WASI subscription layout (48 bytes):
;;   [0..7]   userdata  : u64
;;   [8]      tag       : u8   (0 = clock)
;;   [9..15]  _pad      : 7 × u8
;;   [16..23] clock_id  : u32  (1 = monotonic)
;;   [24..31] timeout   : u64  (nanoseconds)
;;   [32..39] precision : u64  (0 = don't care)
;;   [40..41] flags     : u16  (0 = relative)
;;   [42..47] _pad
;;
;; WASI event layout (32 bytes) — written by poll_oneoff.
;;
;; Compile:
;;   wat2wasm poll_demo.wat -o poll_demo.wasm
;;
;; Run:
;;   wasm poll_demo.wasm

(module
  ;; -------------------------------------------------------------------------
  ;; Imports
  ;; -------------------------------------------------------------------------
  (import "wasi_snapshot_preview1" "fd_write"
    (func $fd_write (param i32 i32 i32 i32) (result i32)))

  (import "wasi_snapshot_preview1" "poll_oneoff"
    (func $poll_oneoff (param i32 i32 i32 i32) (result i32)))

  (import "wasi_snapshot_preview1" "proc_exit"
    (func $proc_exit (param i32)))

  ;; -------------------------------------------------------------------------
  ;; Memory layout
  ;;   [0..47]   subscription struct
  ;;   [48..79]  event output (32 bytes)
  ;;   [80..83]  nevents output
  ;;   [128..7]  iovec for fd_write
  ;;   [136..167] message "woke up!\n" (9 bytes)
  ;;   [176]     nwritten
  ;; -------------------------------------------------------------------------
  (memory (export "memory") 1)

  (data (i32.const 136) "poll_demo: woke up after ~100ms\n")  ;; 32 bytes

  ;; -------------------------------------------------------------------------
  ;; _start
  ;; -------------------------------------------------------------------------
  (func (export "_start")
    ;; ----- Build subscription at address 0 -----
    ;; userdata = 0x42 (arbitrary)
    (i64.store (i32.const 0) (i64.const 0x42))
    ;; tag = 0 (EVENTTYPE_CLOCK)
    (i32.store8 (i32.const 8) (i32.const 0))
    ;; _pad bytes 9-15 = 0 (already zeroed by default)
    ;; clock_id = 1 (CLOCKID_MONOTONIC)
    (i32.store (i32.const 16) (i32.const 1))
    ;; timeout = 100_000_000 ns = 0x5F5E100
    (i64.store (i32.const 24) (i64.const 100000000))
    ;; precision = 0
    (i64.store (i32.const 32) (i64.const 0))
    ;; flags = 0 (relative)
    (i32.store16 (i32.const 40) (i32.const 0))

    ;; ----- Call poll_oneoff -----
    ;;   in_ptr=0, out_ptr=48, nsubscriptions=1, nevents_ptr=80
    (call $poll_oneoff
      (i32.const 0)   ;; in_ptr
      (i32.const 48)  ;; out_ptr
      (i32.const 1)   ;; nsubscriptions
      (i32.const 80)  ;; nevents_ptr
    )
    drop

    ;; ----- Write confirmation message -----
    (i32.store (i32.const 128) (i32.const 136))  ;; buf_ptr
    (i32.store (i32.const 132) (i32.const 32))   ;; buf_len
    (call $fd_write
      (i32.const 1)    ;; stdout
      (i32.const 128)  ;; iovec
      (i32.const 1)
      (i32.const 176)
    )
    drop

    (call $proc_exit (i32.const 0))
  )
)
