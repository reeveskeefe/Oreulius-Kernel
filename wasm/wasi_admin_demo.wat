(module
  (import "oreulius" "path_open"
    (func $path_open (param i32 i32 i32 i32 i32 i64 i64 i32 i32) (result i32)))
  (import "oreulius" "fd_allocate"
    (func $fd_allocate (param i32 i64 i64) (result i32)))
  (import "oreulius" "fd_write"
    (func $fd_write (param i32 i32 i32 i32) (result i32)))
  (import "oreulius" "fd_tell"
    (func $fd_tell (param i32 i32) (result i32)))
  (import "oreulius" "fd_filestat_set_size"
    (func $fd_filestat_set_size (param i32 i64) (result i32)))
  (import "oreulius" "fd_filestat_set_times"
    (func $fd_filestat_set_times (param i32 i64 i64 i32) (result i32)))
  (import "oreulius" "fd_renumber"
    (func $fd_renumber (param i32 i32) (result i32)))
  (import "oreulius" "fd_sync"
    (func $fd_sync (param i32) (result i32)))
  (import "oreulius" "fd_close"
    (func $fd_close (param i32) (result i32)))
  (import "oreulius" "proc_exit"
    (func $proc_exit (param i32)))

  (memory (export "memory") 1)

  ;; "/tmp/wasi-admin-demo"
  (data (i32.const 32) "/tmp/wasi-admin-demo")
  ;; payload
  (data (i32.const 128) "hello")
  ;; iovec { ptr=128, len=5 }
  (data (i32.const 160) "\80\00\00\00\05\00\00\00")

  (func (export "_start")
    ;; path_open(root=3, dirflags=0, path, oflags=CREAT|TRUNC, rights=READ|WRITE|SEEK|TELL, fdflags=0, &fd)
    (drop
      (call $path_open
        (i32.const 3)
        (i32.const 0)
        (i32.const 32)
        (i32.const 20)
        (i32.const 9)
        (i64.const 15)
        (i64.const 15)
        (i32.const 0)
        (i32.const 96)))

    ;; fd_allocate(fd, 0, 64)
    (drop
      (call $fd_allocate
        (i32.load (i32.const 96))
        (i64.const 0)
        (i64.const 64)))

    ;; fd_write(fd, &iov, 1, &nwritten)
    (drop
      (call $fd_write
        (i32.load (i32.const 96))
        (i32.const 160)
        (i32.const 1)
        (i32.const 104)))

    ;; fd_tell(fd, &offset)
    (drop
      (call $fd_tell
        (i32.load (i32.const 96))
        (i32.const 112)))

    ;; fd_filestat_set_size(fd, 2)
    (drop
      (call $fd_filestat_set_size
        (i32.load (i32.const 96))
        (i64.const 2)))

    ;; fd_filestat_set_times(fd, atim=0, mtim=0, ATIM_NOW|MTIM_NOW)
    (drop
      (call $fd_filestat_set_times
        (i32.load (i32.const 96))
        (i64.const 0)
        (i64.const 0)
        (i32.const 10)))

    ;; fd_renumber(fd, 9)
    (drop
      (call $fd_renumber
        (i32.load (i32.const 96))
        (i32.const 9)))

    ;; fd_sync(9) and close(9)
    (drop (call $fd_sync (i32.const 9)))
    (drop (call $fd_close (i32.const 9)))

    (call $proc_exit (i32.const 0)))
)
