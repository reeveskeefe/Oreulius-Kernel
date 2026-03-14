;; echo.wat — stdin → stdout line echo loop
;;
;; Reads up to 256 bytes from stdin (fd 0) and writes them back to
;; stdout (fd 1).  Loops until fd_read returns 0 bytes (EOF / no input).
;;
;; Compile:
;;   wat2wasm echo.wat -o echo.wasm
;;
;; Run inside Oreulia shell:
;;   wasm echo.wasm
;;
;; WASI syscalls used:
;;   fd_read   (host ID 65)
;;   fd_write  (host ID 71)
;;   proc_exit (host ID 83)

(module
  ;; -------------------------------------------------------------------------
  ;; Imports
  ;; -------------------------------------------------------------------------
  (import "wasi_snapshot_preview1" "fd_read"
    (func $fd_read  (param i32 i32 i32 i32) (result i32)))

  (import "wasi_snapshot_preview1" "fd_write"
    (func $fd_write (param i32 i32 i32 i32) (result i32)))

  (import "wasi_snapshot_preview1" "proc_exit"
    (func $proc_exit (param i32)))

  ;; -------------------------------------------------------------------------
  ;; Memory layout
  ;;   [0..7]    read  iovec  { buf_ptr=16, buf_len=256 }
  ;;   [8..15]   write iovec  { buf_ptr=16, buf_len=<nread> }
  ;;   [16..272] I/O buffer (256 bytes)
  ;;   [272..276] nread  (output from fd_read)
  ;;   [276..280] nwritten (output from fd_write)
  ;; -------------------------------------------------------------------------
  (memory (export "memory") 1)

  ;; -------------------------------------------------------------------------
  ;; Helpers: store read-iovec and write-iovec
  ;; -------------------------------------------------------------------------
  (func $init_iovecs
    ;; read iovec: buf at 16, len 256
    (i32.store (i32.const 0)  (i32.const 16))
    (i32.store (i32.const 4)  (i32.const 256))
  )

  ;; -------------------------------------------------------------------------
  ;; _start
  ;; -------------------------------------------------------------------------
  (func (export "_start")
    (local $nread i32)

    (call $init_iovecs)

    (block $break
      (loop $loop
        ;; fd_read(fd=0, iovs=0, iovs_len=1, nread=272)
        (call $fd_read
          (i32.const 0)    ;; stdin
          (i32.const 0)    ;; iovec array
          (i32.const 1)    ;; 1 iovec
          (i32.const 272)  ;; &nread
        )
        drop

        ;; nread = memory[272]
        (local.set $nread (i32.load (i32.const 272)))

        ;; if nread == 0 break (EOF or no input available)
        (br_if $break (i32.eqz (local.get $nread)))

        ;; build write iovec: buf at 16, len = nread
        (i32.store (i32.const 8)  (i32.const 16))
        (i32.store (i32.const 12) (local.get $nread))

        ;; fd_write(fd=1, iovs=8, iovs_len=1, nwritten=276)
        (call $fd_write
          (i32.const 1)    ;; stdout
          (i32.const 8)    ;; iovec array
          (i32.const 1)    ;; 1 iovec
          (i32.const 276)  ;; &nwritten
        )
        drop

        (br $loop)
      )
    )

    (call $proc_exit (i32.const 0))
  )
)
