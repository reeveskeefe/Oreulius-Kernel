;; hello.wat — "Hello from Oreulia!" demo
;;
;; Writes a greeting to stdout (fd 1) using the WASI fd_write syscall.
;; Compile:
;;   wat2wasm hello.wat -o hello.wasm
;;
;; Run inside Oreulia shell:
;;   wasm hello.wasm
;;
;; WASI syscalls used:
;;   fd_write  (WASI Preview 1, host function ID 71)

(module
  ;; -------------------------------------------------------------------------
  ;; Imports
  ;; -------------------------------------------------------------------------
  (import "wasi_snapshot_preview1" "fd_write"
    (func $fd_write (param i32 i32 i32 i32) (result i32)))

  (import "wasi_snapshot_preview1" "proc_exit"
    (func $proc_exit (param i32)))

  ;; -------------------------------------------------------------------------
  ;; Memory layout (1 page = 64 KiB)
  ;;   [0..7]   iovec: { buf_ptr: i32, buf_len: i32 }
  ;;   [8..28]  message bytes
  ;;   [28..32] nwritten (output)
  ;; -------------------------------------------------------------------------
  (memory (export "memory") 1)

  (data (i32.const 8)  "Hello from Oreulia!\n")  ;; 20 bytes

  ;; -------------------------------------------------------------------------
  ;; _start — entry point called by the Oreulia WASM runtime
  ;; -------------------------------------------------------------------------
  (func (export "_start")
    ;; Build iovec at address 0:
    ;;   buf_ptr = 8
    ;;   buf_len = 20
    (i32.store (i32.const 0) (i32.const 8))
    (i32.store (i32.const 4) (i32.const 20))

    ;; Call fd_write(fd=1, iovs=0, iovs_len=1, nwritten=28)
    (call $fd_write
      (i32.const 1)   ;; stdout
      (i32.const 0)   ;; iovec array pointer
      (i32.const 1)   ;; number of iovecs
      (i32.const 28)  ;; where to store nwritten
    )
    drop              ;; ignore return value (errno)

    ;; Exit cleanly
    (call $proc_exit (i32.const 0))
  )
)
