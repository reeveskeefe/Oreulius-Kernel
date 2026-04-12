(module
  (import "oreulius" "polyglot_link" (func $polyglot_link (param i32 i32 i32 i32) (result i32)))
  (import "oreulius" "polyglot_lineage_query_page" (func $polyglot_lineage_query_page (param i32 i32 i32 i32) (result i32)))
  (import "oreulius" "proc_exit" (func $proc_exit (param i32)))

  (memory 1)
  (data (i32.const 0) "svc")
  (data (i32.const 16) "add")

  (func (export "_start")
    (local $cap i32)
    (local $first_count i32)

    i32.const 0
    i32.const 3
    i32.const 16
    i32.const 3
    call $polyglot_link
    drop

    i32.const 0
    i32.const 8
    i32.const 256
    i32.const 4096
    call $polyglot_lineage_query_page
    local.set $first_count

    local.get $first_count
    i32.const 0
    i32.eq
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

    i32.const 0
    call $proc_exit))
