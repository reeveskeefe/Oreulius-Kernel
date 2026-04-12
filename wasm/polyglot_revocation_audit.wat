(module
  (import "oreulius" "polyglot_link" (func $polyglot_link (param i32 i32 i32 i32) (result i32)))
  (import "oreulius" "polyglot_lineage_lookup" (func $polyglot_lineage_lookup (param i32 i32 i32) (result i32)))
  (import "oreulius" "polyglot_lineage_lookup_object" (func $polyglot_lineage_lookup_object (param i32 i32 i32 i32) (result i32)))
  (import "oreulius" "polyglot_lineage_revoke" (func $polyglot_lineage_revoke (param i32) (result i32)))
  (import "oreulius" "proc_exit" (func $proc_exit (param i32)))

  (memory 1)
  (data (i32.const 0) "svc")
  (data (i32.const 16) "add")

  (func (export "_start")
    (local $cap i32)
    (local $obj i64)
    (local $obj_lo i32)
    (local $obj_hi i32)

    i32.const 0
    i32.const 3
    i32.const 16
    i32.const 3
    call $polyglot_link
    local.set $cap

    local.get $cap
    i32.const 256
    i32.const 104
    call $polyglot_lineage_lookup
    i32.const 1
    i32.ne
    if
      i32.const 1
      call $proc_exit
    end

    i32.const 256
    i32.load8_u
    i32.const 1
    i32.ne
    if
      i32.const 2
      call $proc_exit
    end

    i32.const 265
    i32.load8_u
    i32.const 2
    i32.ne
    if
      i32.const 3
      call $proc_exit
    end

    i32.const 256
    i64.load offset=32
    local.set $obj

    local.get $cap
    call $polyglot_lineage_revoke
    i32.const 0
    i32.ne
    if
      i32.const 4
      call $proc_exit
    end

    local.get $obj
    i32.wrap_i64
    local.set $obj_lo
    local.get $obj
    i64.const 32
    i64.shr_u
    i32.wrap_i64
    local.set $obj_hi

    local.get $obj_lo
    local.get $obj_hi
    i32.const 384
    i32.const 104
    call $polyglot_lineage_lookup_object
    i32.const 1
    i32.ne
    if
      i32.const 5
      call $proc_exit
    end

    i32.const 393
    i32.load8_u
    i32.const 3
    i32.ne
    if
      i32.const 6
      call $proc_exit
    end

    i32.const 0
    call $proc_exit))
