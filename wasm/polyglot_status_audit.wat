(module
  (import "oreulius" "polyglot_link" (func $polyglot_link (param i32 i32 i32 i32) (result i32)))
  (import "oreulius" "polyglot_lineage_status" (func $polyglot_lineage_status (param i32 i32 i32) (result i32)))
  (import "oreulius" "polyglot_lineage_revoke" (func $polyglot_lineage_revoke (param i32) (result i32)))
  (import "oreulius" "proc_exit" (func $proc_exit (param i32)))

  (memory 1)
  (data (i32.const 0) "svc")
  (data (i32.const 16) "add")

  (func (export "_start")
    (local $cap i32)

    i32.const 0
    i32.const 3
    i32.const 16
    i32.const 3
    call $polyglot_link
    local.set $cap

    local.get $cap
    i32.const 256
    i32.const 40
    call $polyglot_lineage_status
    i32.const 1
    i32.ne
    if
      i32.const 1
      call $proc_exit
    end

    i32.const 257
    i32.load8_u
    i32.const 2
    i32.ne
    if
      i32.const 2
      call $proc_exit
    end

    local.get $cap
    call $polyglot_lineage_revoke
    drop

    i32.const 0
    call $proc_exit))
