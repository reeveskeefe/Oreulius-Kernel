;; thread_demo.wat — cooperative WASM thread demo
;;
;; Demonstrates Oreulia's cooperative thread host ABI by spawning one worker
;; thread, yielding until it completes, then checking the joined exit code.
;;
;; Host-function ABI (Oreulia-specific, non-WASI):
;;   thread_spawn(func_idx: i32, arg: i32) -> i32
;;   thread_join(tid: i32) -> i32
;;   thread_id() -> i32
;;   thread_yield()
;;   thread_exit(code: i32)
;;   proc_yield()
;;
;; Compile:
;;   wat2wasm thread_demo.wat -o thread_demo.wasm
;;
;; Run:
;;   wasm thread_demo.wasm

(module
  ;; -------------------------------------------------------------------------
  ;; Imports
  ;; -------------------------------------------------------------------------
  (import "wasi_snapshot_preview1" "fd_write"
    (func $fd_write (param i32 i32 i32 i32) (result i32)))

  (import "wasi_snapshot_preview1" "proc_exit"
    (func $proc_exit (param i32)))

  (import "oreulia" "thread_spawn"
    (func $thread_spawn (param i32 i32) (result i32)))

  (import "oreulia" "thread_join"
    (func $thread_join (param i32) (result i32)))

  (import "oreulia" "thread_id"
    (func $thread_id (result i32)))

  (import "oreulia" "thread_yield"
    (func $thread_yield))

  (import "oreulia" "thread_exit"
    (func $thread_exit (param i32)))

  (import "oreulia" "proc_yield"
    (func $proc_yield))

  ;; -------------------------------------------------------------------------
  ;; Memory layout
  ;;   [0..7]     iovec for fd_write
  ;;   [8..11]    fd_write nwritten
  ;;   [64..87]   "thread_demo: main start\n"      (24 bytes)
  ;;   [96..122]  "thread_demo: child running\n"   (27 bytes)
  ;;   [128..148] "thread_demo: join ok\n"         (21 bytes)
  ;;   [160..184] "thread_demo: join failed\n"     (25 bytes)
  ;;   [192..217] "thread_demo: spawn failed\n"    (26 bytes)
  ;; -------------------------------------------------------------------------
  (memory (export "memory") 1)

  (data (i32.const 64)  "thread_demo: main start\n")
  (data (i32.const 96)  "thread_demo: child running\n")
  (data (i32.const 128) "thread_demo: join ok\n")
  (data (i32.const 160) "thread_demo: join failed\n")
  (data (i32.const 192) "thread_demo: spawn failed\n")

  ;; -------------------------------------------------------------------------
  ;; Worker thread entry — defined function index 0
  ;; -------------------------------------------------------------------------
  (func $worker (param $arg i32)
    (local $tid i32)

    (local.set $tid (call $thread_id))
    (call $write_str (i32.const 96) (i32.const 27))
    (call $thread_yield)

    ;; A spawned worker should never observe thread ID 0.
    (local.get $tid)
    (i32.eqz)
    (if
      (then
        (call $thread_exit (i32.const 99))
      )
    )

    (call $thread_exit (local.get $arg))
  )

  ;; -------------------------------------------------------------------------
  ;; write_str helper
  ;; -------------------------------------------------------------------------
  (func $write_str (param $ptr i32) (param $len i32)
    (i32.store (i32.const 0) (local.get $ptr))
    (i32.store (i32.const 4) (local.get $len))
    (call $fd_write (i32.const 1) (i32.const 0) (i32.const 1) (i32.const 8))
    drop
  )

  ;; -------------------------------------------------------------------------
  ;; _start
  ;; -------------------------------------------------------------------------
  (func (export "_start")
    (local $tid i32)
    (local $rc i32)

    (call $write_str (i32.const 64) (i32.const 24))

    ;; Spawn the first defined function: $worker => func_idx 0.
    (local.set $tid
      (call $thread_spawn (i32.const 0) (i32.const 42)))

    (local.get $tid)
    (i32.const 0)
    (i32.lt_s)
    (if
      (then
        (call $write_str (i32.const 192) (i32.const 26))
        (call $proc_exit (i32.const 1))
      )
    )

    (block $done
      (loop $join
        (local.set $rc (call $thread_join (local.get $tid)))
        (local.get $rc)
        (i32.const -1)
        (i32.eq)
        (if
          (then
            (call $proc_yield)
            (br $join)
          )
        )
        (br $done)
      )
    )

    (local.get $rc)
    (i32.const 42)
    (i32.eq)
    (if
      (then
        (call $write_str (i32.const 128) (i32.const 21))
        (call $proc_exit (i32.const 0))
      )
      (else
        (call $write_str (i32.const 160) (i32.const 25))
        (call $proc_exit (i32.const 2))
      )
    )
  )
)
